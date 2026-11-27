package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

const (
	stateVersion      = 1
	identityFile      = "identity.json"
	bootStateFile     = "boot_state.json"
	configFile        = "config.json"
	rotationFile      = "rotation.json"
	controlFile       = "pending_control.json"
	cleanShutdownFile = "clean_shutdown"
	failClosedFile    = "fail_closed"
	lockFile          = ".lock"
	spoolDir          = "spool"
	quarantineDir     = "quarantine"
)

var (
	nodeIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	keyIDRe  = regexp.MustCompile(`^key-[0-9a-f]{8}$`)
	bootIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Identity is the durable node identity. PrivateKey is stored in the state
// directory with owner-only permissions; platform secret wrapping is an ADR
// boundary (OD-P7) and must not be confused with production approval.
type Identity struct {
	Version             int    `json:"version"`
	CenterURL           string `json:"center_url"`
	NodeID              string `json:"node_id"`
	EventID             string `json:"event_id"`
	NodeClass           string `json:"node_class"`
	KeyID               string `json:"key_id"`
	PublicKey           string `json:"public_key"`
	PrivateKey          string `json:"private_key,omitempty"`
	PrivateKeyProtected string `json:"private_key_dpapi,omitempty"`
}

// BootState is the atomic generation/sequence high-water basis. NextSeq is the
// next usable sequence; Exhausted is set only after an ACK carries next_seq=null.
type BootState struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"`
	BootID     string `json:"boot_id"`
	NextSeq    uint64 `json:"next_seq"`
	Exhausted  bool   `json:"exhausted"`
}

// RotationState is a persisted pending rotation intent. It survives restart and
// never contains a plaintext token.
type RotationState struct {
	Version                int    `json:"version"`
	Nonce                  string `json:"nonce"`
	NewKeyID               string `json:"new_key_id,omitempty"`
	NewPublicKey           string `json:"new_public_key"`
	NewPrivateKey          string `json:"new_private_key,omitempty"`
	NewPrivateKeyProtected string `json:"new_private_key_dpapi,omitempty"`
	Response               []byte `json:"response,omitempty"`
	State                  string `json:"state"` // awaiting_proof
}

// ControlState is a persisted config/rotate/pre-proof control attempt. It is
// replayed with refreshed transport fields under rev-5 full validation.
type ControlState struct {
	Version      int     `json:"version"`
	Kind         string  `json:"kind"` // config|rotate
	Attempt      Attempt `json:"attempt"`
	Body         []byte  `json:"body"`
	NewKeyID     string  `json:"new_key_id,omitempty"`
	NewPublicKey string  `json:"new_public_key,omitempty"`
}

// AgentConfig is the validated center config plus its raw bytes.
type AgentConfig struct {
	Version       int
	ConfigVersion int
	Cadence       int
	Collect       map[string]bool
	DeviceSalt    string
	ServerTime    int64
	Tags          []InboundTag
	Raw           []byte
}

// State owns the state directory lock and durable files.
type State struct {
	dir       string
	lockPath  string
	lockFile  *os.File
	lockToken string
	identity  *Identity
	boot      *BootState
	config    *AgentConfig
	rotation  *RotationState
	control   *ControlState
	spool     *Spool
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func newNonce() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newBootID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newUUIDv4() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := rejectLinksInPath(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp-" + fmt.Sprintf("%d", os.Getpid()) + "-" + fmt.Sprintf("%d", len(data))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		tmp = path + ".tmp-" + strings.ReplaceAll(fmt.Sprintf("%v", randString()), "/", "_")
		f, err = os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	ok = true
	return nil
}

func randString() string {
	b, err := randomBytes(8)
	if err != nil {
		return fmt.Sprint(os.Getpid())
	}
	return hex.EncodeToString(b)
}

func readJSON(path string, out any) (bool, error) {
	if err := rejectLink(path); err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return true, err
	}
	return true, nil
}

// rejectLink refuses a symlink or Windows reparse point at path. A missing path
// is allowed (the caller may be about to create it).
func rejectLink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return errors.New("agent: state path must not be a symlink or reparse point")
	}
	return nil
}

// rejectLinksInPath walks every existing component of path and refuses
// symlinks/reparse points. It is deliberately conservative: a state directory
// or any parent that redirects storage is a fail-closed configuration error.
func rejectLinksInPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs, volume)
	current := volume + string(os.PathSeparator)
	for _, part := range strings.Split(rest, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := rejectLink(current); err != nil {
			return err
		}
	}
	return nil
}

// OpenState acquires the single-instance lock and loads durable state. A missing
// boot_state with an existing identity is corruption and must not auto-recover.
func OpenState(dir string) (*State, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("agent: state directory is required")
	}
	if err := rejectLinksInPath(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := rejectLinksInPath(dir); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	s := &State{dir: dir, lockPath: filepath.Join(dir, lockFile)}
	if err := s.acquireLock(); err != nil {
		return nil, err
	}
	cleanup := func() { _ = s.release() }
	var ident Identity
	hasIdent, err := readJSON(filepath.Join(dir, identityFile), &ident)
	if err != nil {
		cleanup()
		return nil, errors.Join(ErrIdentityCorrupt, err)
	}
	if hasIdent {
		wasProtected := ident.PrivateKeyProtected != ""
		if ident.PrivateKeyProtected != "" {
			if ident.PrivateKey != "" {
				cleanup()
				return nil, errors.Join(ErrIdentityCorrupt, errors.New("identity has both plaintext and protected key"))
			}
			plaintext, err := unsealPrivateKey(ident.PrivateKeyProtected)
			if err != nil {
				cleanup()
				return nil, errors.Join(ErrIdentityCorrupt, err)
			}
			ident.PrivateKey = plaintext
			ident.PrivateKeyProtected = ""
		}
		if err := validateIdentity(&ident); err != nil {
			cleanup()
			return nil, errors.Join(ErrIdentityCorrupt, err)
		}
		s.identity = &ident
		// Migrate a legacy plaintext identity to DPAPI at first open on Windows.
		if !wasProtected && privateKeyProtectionAvailable() {
			if err := s.saveIdentity(ident); err != nil {
				cleanup()
				return nil, err
			}
		}
	}
	var boot BootState
	hasBoot, err := readJSON(filepath.Join(dir, bootStateFile), &boot)
	if err != nil {
		cleanup()
		return nil, errors.Join(ErrBootStateCorrupt, err)
	}
	if hasIdent && !hasBoot {
		cleanup()
		return nil, ErrBootStateCorrupt
	}
	if !hasIdent && hasBoot {
		cleanup()
		return nil, errors.Join(ErrIdentityCorrupt, errors.New("boot state without identity"))
	}
	if hasBoot {
		if err := validateBoot(&boot); err != nil {
			cleanup()
			return nil, errors.Join(ErrBootStateCorrupt, err)
		}
		s.boot = &boot
	}
	var cfg AgentConfig
	if ok, err := readJSON(filepath.Join(dir, configFile), &cfg); err != nil {
		cleanup()
		return nil, err
	} else if ok {
		if cfg.ConfigVersion < 1 || cfg.Cadence < 30 || cfg.Cadence > 300 {
			cleanup()
			return nil, errors.New("agent: stored config corrupt")
		}
		s.config = &cfg
	}
	var rot RotationState
	if ok, err := readJSON(filepath.Join(dir, rotationFile), &rot); err != nil {
		cleanup()
		return nil, errors.Join(ErrRotationMismatch, err)
	} else if ok {
		wasProtected := rot.NewPrivateKeyProtected != ""
		if wasProtected {
			if rot.NewPrivateKey != "" {
				cleanup()
				return nil, errors.Join(ErrRotationMismatch, errors.New("rotation has both plaintext and protected key"))
			}
			plaintext, err := unsealPrivateKey(rot.NewPrivateKeyProtected)
			if err != nil {
				cleanup()
				return nil, errors.Join(ErrRotationMismatch, err)
			}
			rot.NewPrivateKey = plaintext
			rot.NewPrivateKeyProtected = ""
		}
		if rot.Version != stateVersion || rot.Nonce == "" || rot.NewPrivateKey == "" {
			cleanup()
			return nil, ErrRotationMismatch
		}
		s.rotation = &rot
		if !wasProtected && privateKeyProtectionAvailable() {
			if err := s.saveRotation(rot); err != nil {
				cleanup()
				return nil, err
			}
		}
	}
	var ctl ControlState
	if ok, err := readJSON(filepath.Join(dir, controlFile), &ctl); err != nil {
		cleanup()
		return nil, err
	} else if ok {
		if ctl.Version != stateVersion || (ctl.Kind != "config" && ctl.Kind != "rotate") ||
			ctl.Attempt.Generation == 0 || ctl.Attempt.Seq == 0 || ctl.Attempt.BootID == "" {
			cleanup()
			return nil, ErrRotationMismatch
		}
		s.control = &ctl
	}
	s.spool, err = openSpool(filepath.Join(dir, spoolDir), filepath.Join(dir, quarantineDir))
	if err != nil {
		cleanup()
		return nil, err
	}
	return s, nil
}

func (s *State) acquireLock() error {
	if err := rejectLink(s.lockPath); err != nil {
		return err
	}
	f, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := lockFileExclusive(f); err != nil {
		_ = f.Close()
		return err
	}
	b, err := randomBytes(16)
	if err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return err
	}
	token := hex.EncodeToString(b)
	content := token + " " + fmt.Sprint(os.Getpid()) + "\n"
	if err := f.Truncate(0); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = unlockFile(f)
		_ = f.Close()
		return err
	}
	s.lockFile = f
	s.lockToken = token
	return nil
}

// Close writes the clean-shutdown marker (only for a fully opened state) and
// releases the single-writer resources. It never deletes identity/boot/spool
// data. The lock file may remain on disk; the OS lock, not file existence, is
// the single-writer authority.
func (s *State) Close() error {
	var first error
	if s.identity != nil {
		first = writeAtomic(filepath.Join(s.dir, cleanShutdownFile), []byte("clean\n"))
	}
	if err := s.release(); err != nil && first == nil {
		first = err
	}
	return first
}

// release closes the lock/spool without claiming a clean shutdown. It is used
// for failed OpenState cleanup so a corrupt state is not mislabeled clean.
func (s *State) release() error {
	var first error
	if s.spool != nil {
		if err := s.spool.Close(); err != nil && first == nil {
			first = err
		}
	}
	if s.lockFile != nil {
		if err := unlockFile(s.lockFile); err != nil && first == nil {
			first = err
		}
		if err := s.lockFile.Close(); err != nil && first == nil {
			first = err
		}
		s.lockFile = nil
	}
	return first
}

func (s *State) cleanShutdownRequested() (bool, error) {
	_, err := os.Stat(filepath.Join(s.dir, cleanShutdownFile))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *State) clearCleanShutdown() error {
	err := os.Remove(filepath.Join(s.dir, cleanShutdownFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *State) failClosedReason() (string, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, failClosedFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *State) markFailClosed(reason string) error {
	if len(reason) > 256 {
		reason = reason[:256]
	}
	return writeAtomic(filepath.Join(s.dir, failClosedFile), []byte(reason))
}

// ClearFailClosed is the explicit operator recovery step after an admin revoke
// and a fresh enrollment decision. It must never be called automatically.
func (s *State) ClearFailClosed() error {
	err := os.Remove(filepath.Join(s.dir, failClosedFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateIdentity(id *Identity) error {
	if id.Version != stateVersion || id.CenterURL == "" || id.NodeClass == "" || id.KeyID == "" ||
		!nodeIDRe.MatchString(id.NodeID) || !nodeIDRe.MatchString(id.EventID) ||
		!keyIDRe.MatchString(id.KeyID) {
		return errors.New("invalid identity fields")
	}
	privRaw, err := base64.RawURLEncoding.DecodeString(id.PrivateKey)
	if err != nil || len(privRaw) != ed25519.PrivateKeySize {
		return errors.New("invalid private key")
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(id.PublicKey)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	if !ed25519.PublicKey(pubRaw).Equal(ed25519.PrivateKey(privRaw).Public()) {
		return errors.New("public/private key mismatch")
	}
	return nil
}

func validateBoot(b *BootState) error {
	if b.Version != stateVersion || b.Generation < 1 || b.Generation > wire.MaxNumeric ||
		!bootIDRe.MatchString(b.BootID) || b.NextSeq < 1 || b.NextSeq > wire.MaxNumeric {
		return errors.New("invalid boot state")
	}
	return nil
}

func (s *State) Identity() (Identity, bool) {
	if s.identity == nil {
		return Identity{}, false
	}
	return *s.identity, true
}

func (s *State) Boot() (BootState, bool) {
	if s.boot == nil {
		return BootState{}, false
	}
	return *s.boot, true
}

func (s *State) Config() (AgentConfig, bool) {
	if s.config == nil {
		return AgentConfig{}, false
	}
	return *s.config, true
}

func (s *State) Rotation() (RotationState, bool) {
	if s.rotation == nil {
		return RotationState{}, false
	}
	return *s.rotation, true
}

func (s *State) saveIdentity(id Identity) error {
	if err := validateIdentity(&id); err != nil {
		return err
	}
	toWrite := id
	if privateKeyProtectionAvailable() {
		protected, err := sealPrivateKey(id.PrivateKey)
		if err != nil {
			return err
		}
		toWrite.PrivateKey = ""
		toWrite.PrivateKeyProtected = protected
	}
	data, err := json.Marshal(toWrite)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, identityFile), data); err != nil {
		return err
	}
	s.identity = &id
	return nil
}

func (s *State) saveBoot(b BootState) error {
	if err := validateBoot(&b); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, bootStateFile), data); err != nil {
		return err
	}
	s.boot = &b
	return nil
}

func (s *State) saveConfig(c AgentConfig) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, configFile), data); err != nil {
		return err
	}
	s.config = &c
	return nil
}

func (s *State) saveRotation(r RotationState) error {
	toWrite := r
	if r.NewPrivateKey != "" && privateKeyProtectionAvailable() {
		protected, err := sealPrivateKey(r.NewPrivateKey)
		if err != nil {
			return err
		}
		toWrite.NewPrivateKey = ""
		toWrite.NewPrivateKeyProtected = protected
	}
	data, err := json.Marshal(toWrite)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, rotationFile), data); err != nil {
		return err
	}
	s.rotation = &r
	return nil
}

func (s *State) Control() (ControlState, bool) {
	if s.control == nil {
		return ControlState{}, false
	}
	return *s.control, true
}

func (s *State) saveControl(c ControlState) error {
	if c.Version == 0 {
		c.Version = stateVersion
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, controlFile), data); err != nil {
		return err
	}
	s.control = &c
	return nil
}

func (s *State) clearControl() error {
	if err := os.Remove(filepath.Join(s.dir, controlFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.control = nil
	return nil
}

func (s *State) clearRotation() error {
	err := os.Remove(filepath.Join(s.dir, rotationFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.rotation = nil
	return nil
}

// Spool exposes the durable spool for runtime and recovery tests.
func (s *State) Spool() *Spool { return s.spool }

// StateDir returns the owner-only state directory (diagnostics only; callers
// must not log secrets from it).
func (s *State) StateDir() string { return s.dir }

// StateInspection is a secret-free read-only status view that does not acquire
// the writer lock (so it can inspect a running service's state directory).
type StateInspection struct {
	Enrolled      bool   `json:"enrolled"`
	Locked        bool   `json:"locked"`
	Generation    uint64 `json:"generation,omitempty"`
	NextSeq       uint64 `json:"next_seq,omitempty"`
	Exhausted     bool   `json:"exhausted,omitempty"`
	ConfigVersion int    `json:"config_version,omitempty"`
	Pending       int    `json:"pending"`
	Quarantined   int    `json:"quarantined"`
	FailClosed    string `json:"fail_closed,omitempty"`
}

// InspectState reads only durable metadata; it never loads or prints secrets.
func InspectState(dir string) (StateInspection, error) {
	var out StateInspection
	if _, err := os.Stat(filepath.Join(dir, lockFile)); err == nil {
		out.Locked = true
	}
	if data, err := os.ReadFile(filepath.Join(dir, failClosedFile)); err == nil {
		out.FailClosed = strings.TrimSpace(string(data))
	}
	var ident Identity
	if ok, err := readJSON(filepath.Join(dir, identityFile), &ident); err != nil {
		return out, errors.Join(ErrIdentityCorrupt, err)
	} else {
		out.Enrolled = ok
	}
	var boot BootState
	if ok, err := readJSON(filepath.Join(dir, bootStateFile), &boot); err != nil {
		return out, errors.Join(ErrBootStateCorrupt, err)
	} else if ok && out.Enrolled {
		out.Generation = boot.Generation
		out.NextSeq = boot.NextSeq
		out.Exhausted = boot.Exhausted
	}
	var cfg AgentConfig
	if ok, err := readJSON(filepath.Join(dir, configFile), &cfg); err == nil && ok {
		out.ConfigVersion = cfg.ConfigVersion
	}
	// Inspection must be read-only: do not MkdirAll/Chmod or let List move a
	// corrupt record to quarantine. The service account must not create a
	// root-owned state tree merely by running `status`.
	pending, err := countRegularFiles(filepath.Join(dir, spoolDir))
	if err != nil {
		return out, err
	}
	out.Pending = pending
	quarantined, err := countRegularFiles(filepath.Join(dir, quarantineDir))
	if err != nil {
		return out, err
	}
	out.Quarantined = quarantined
	return out, nil
}

// countRegularFiles counts non-directory entries in dir without following
// symlinks. A missing directory is observed as zero and is not created.
func countRegularFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		count++
	}
	return count, nil
}
