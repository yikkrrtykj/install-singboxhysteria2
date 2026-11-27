//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/secretstore"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsagent"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

var windowsAgentStartedAt = time.Now()

func platformCollector(c commonFlags) (agent.Collector, error) {
	opts := windowsagent.Options{
		AgentVersion: version,
		Uptime: func() int64 {
			return int64(time.Since(windowsAgentStartedAt) / time.Second)
		},
	}
	// R1 is activated only by a protected, locally provisioned authorization
	// record plus profile/secret files under the state directory. No environment
	// variable or center field can enable it by itself.
	observer, enabled, err := loadWindowsR1Observer(c.stateDir)
	if err != nil {
		return nil, err
	}
	if enabled {
		opts.Observer = observer
	}
	// The default binary has no terminal route source configured. R2 has no
	// proven local read-only surface in the tested builds; R1 remains
	// isolated-lab-only until the Owner records production authorization.
	return windowsagent.New(opts)
}

const (
	r1AcceptanceVersion = 1
	r1Decision          = "OD-P3-R1"
	r1ScopeIsolatedLab  = "isolated_lab"
	r1ProfileFile       = "profile.json"
	r1SecretFile        = "controller.secret.dpapi"
	r1AcceptanceFile    = "acceptance.json"
)

type r1Acceptance struct {
	Version         int    `json:"version"`
	Decision        string `json:"decision"`
	Scope           string `json:"scope"`
	OwnerReference  string `json:"owner_reference"`
	ProfileSHA256   string `json:"profile_sha256"`
	ProtectedSHA256 string `json:"protected_secret_sha256"`
	CreatedAtUnix   int64  `json:"created_at_unix"`
}

func r1Dir(stateDir string) string { return filepath.Join(stateDir, "r1") }

// loadWindowsR1Observer reads the fixed protected provisioning bundle from the
// state directory. A missing bundle is disabled (nil, false, nil); a partial,
// malformed or out-of-scope bundle fails closed. There is deliberately no
// environment-variable path or secret value override.
func loadWindowsR1Observer(stateDir string) (windowsagent.RouteObserver, bool, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, false, nil
	}
	dir := r1Dir(stateDir)
	acceptPath := filepath.Join(dir, r1AcceptanceFile)
	if _, err := os.Lstat(acceptPath); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, errors.New("um-agent: cannot inspect R1 authorization record")
	}
	rawAccept, err := readRegularBounded(acceptPath, 8192)
	if err != nil {
		return nil, false, errors.New("um-agent: invalid R1 authorization record")
	}
	var acceptance r1Acceptance
	if err := json.Unmarshal(rawAccept, &acceptance); err != nil {
		return nil, false, errors.New("um-agent: malformed R1 authorization record")
	}
	if acceptance.Version != r1AcceptanceVersion || acceptance.Decision != r1Decision ||
		acceptance.Scope != r1ScopeIsolatedLab || strings.TrimSpace(acceptance.OwnerReference) == "" {
		return nil, false, errors.New("um-agent: R1 authorization is not valid for isolated-lab scope")
	}
	profileBytes, err := readRegularBounded(filepath.Join(dir, r1ProfileFile), 16384)
	if err != nil || sha256Hex(profileBytes) != acceptance.ProfileSHA256 {
		return nil, false, errors.New("um-agent: R1 profile hash mismatch")
	}
	protected, err := readRegularBounded(filepath.Join(dir, r1SecretFile), 8192)
	if err != nil || sha256Hex(protected) != acceptance.ProtectedSHA256 {
		return nil, false, errors.New("um-agent: R1 credential hash mismatch")
	}
	protector, err := secretstore.NewDPAPIProtector(secretstore.DPAPIUserScope, nil)
	if err != nil {
		return nil, false, errors.New("um-agent: R1 DPAPI unavailable")
	}
	plain, err := protector.Unprotect(protected)
	if err != nil {
		return nil, false, errors.New("um-agent: R1 credential cannot be unsealed for this account")
	}
	defer clearBytes(plain)
	secret := strings.TrimSpace(string(plain))
	if secret == "" || strings.ContainsAny(secret, "\r\n\x00") {
		return nil, false, errors.New("um-agent: invalid R1 credential")
	}
	var profile windowsobs.Profile
	decoder := json.NewDecoder(bytes.NewReader(profileBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return nil, false, errors.New("um-agent: invalid R1 profile")
	}
	observer, err := windowsobs.New(profile, secret)
	if err != nil {
		return nil, false, errors.New("um-agent: cannot construct R1 observer")
	}
	return observer, true, nil
}

// provisionWindowsR1 is the only local provisioning path. It must be run by
// the account that will host the service (or the operator-approved lab
// account), because the controller secret is sealed with DPAPI CurrentUser.
// It writes a versioned authorization record binding the exact profile and
// protected secret bytes, and applies a protected DACL to the r1 directory.
func provisionWindowsR1(stateDir, profilePath, secretPath, ownerReference string) error {
	if strings.TrimSpace(stateDir) == "" || strings.TrimSpace(ownerReference) == "" {
		return errors.New("state-dir and owner-reference are required")
	}
	profile, err := readWindowsProfile(profilePath)
	if err != nil {
		return errors.New("invalid R1 profile")
	}
	secret, err := readWindowsSecret(secretPath)
	if err != nil {
		return errors.New("invalid R1 controller secret")
	}
	if _, err := windowsobs.New(profile, secret); err != nil {
		return errors.New("R1 profile/secret rejected")
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		return errors.New("cannot encode R1 profile")
	}
	protector, err := secretstore.NewDPAPIProtector(secretstore.DPAPIUserScope, nil)
	if err != nil {
		return errors.New("R1 DPAPI unavailable")
	}
	protected, err := protector.Protect([]byte(secret))
	if err != nil {
		return errors.New("cannot seal R1 credential")
	}
	dir := r1Dir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("cannot create R1 directory")
	}
	if err := applyPrivateDACL(dir, true); err != nil {
		return errors.New("cannot protect R1 directory ACL")
	}
	acceptance := r1Acceptance{
		Version: r1AcceptanceVersion, Decision: r1Decision, Scope: r1ScopeIsolatedLab,
		OwnerReference: strings.TrimSpace(ownerReference), ProfileSHA256: sha256Hex(profileBytes),
		ProtectedSHA256: sha256Hex(protected), CreatedAtUnix: time.Now().UTC().Unix(),
	}
	acceptBytes, err := json.MarshalIndent(acceptance, "", "  ")
	if err != nil {
		return errors.New("cannot encode R1 authorization")
	}
	for name, data := range map[string][]byte{
		r1ProfileFile: profileBytes, r1SecretFile: protected, r1AcceptanceFile: acceptBytes,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("cannot write R1 bundle file %s", name)
		}
		if err := applyPrivateDACL(path, false); err != nil {
			return fmt.Errorf("cannot protect R1 bundle file %s", name)
		}
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// applyPrivateDACL replaces inherited ACEs with full access for the current
// user, SYSTEM and Administrators only. It never logs or returns the DACL.
func applyPrivateDACL(path string, directory bool) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	inherit := uint32(0)
	if directory {
		inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, sid := range []*windows.SID{user.User.Sid, system, admins} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
}

func readWindowsProfile(path string) (windowsobs.Profile, error) {
	raw, err := readRegularBounded(path, 16384)
	if err != nil {
		return windowsobs.Profile{}, err
	}
	var profile windowsobs.Profile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return windowsobs.Profile{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return windowsobs.Profile{}, errors.New("trailing profile data")
	}
	return profile, nil
}

func readWindowsSecret(path string) (string, error) {
	raw, err := readRegularBounded(path, 4096)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return "", errors.New("empty controller secret")
	}
	return secret, nil
}

// readRegularBounded refuses symlinks/reparse points, non-regular files and
// over-limit inputs. The secret is never logged or included in an error.
func readRegularBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("expected regular non-symlink file")
	}
	if info.Size() > limit {
		return nil, errors.New("file exceeds configured limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file exceeds configured limit")
	}
	return raw, nil
}

func runR1Provision(args []string) int {
	fs := flag.NewFlagSet("r1-provision", flag.ContinueOnError)
	var stateDir, profile, secretFile, ownerReference string
	fs.StringVar(&stateDir, "state-dir", envOr("UM_AGENT_STATE_DIR", ""), "agent state directory")
	fs.StringVar(&profile, "profile", "", "operator-local windowsobs profile JSON")
	fs.StringVar(&secretFile, "secret-file", "", "controller secret file (read once, then DPAPI-sealed)")
	fs.StringVar(&ownerReference, "owner-reference", "", "versioned OD-P3 R1 isolated-lab acceptance reference")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if profile == "" || secretFile == "" {
		fmt.Fprintln(os.Stderr, "um-agent: r1-provision requires --profile and --secret-file")
		return 1
	}
	if err := provisionWindowsR1(stateDir, profile, secretFile, ownerReference); err != nil {
		fmt.Fprintln(os.Stderr, "um-agent:", err)
		return 1
	}
	fmt.Println("r1-provision: sealed isolated-lab R1 bundle written")
	return 0
}

func platformService(args []string) error {
	// Only the SCM lifecycle wrapper lives here. The final service account, ACL,
	// DPAPI scope and credential rotation remain OD-P7-gated (see ADR); this
	// wrapper does not install, configure, or approve an account.
	err := svc.Run("um-agent", &agentService{args: args})
	if err != nil {
		logServiceEvent(1, "service failed: "+err.Error())
	}
	return err
}

// logServiceEvent writes a closed-code service failure to the Application log.
// Callers must pass errors that contain no token, key, payload or secret.
func logServiceEvent(id uint32, message string) {
	log, err := eventlog.Open("um-agent")
	if err != nil {
		return
	}
	defer log.Close()
	_ = log.Error(id, message)
}

// mergeServiceArgs combines the ImagePath flags captured from os.Args with any
// extra arguments the SCM passes. The svc package always includes the service
// name as args[0], and the ImagePath flags are not repeated there. Keeping this
// pure makes the argument contract testable without an SCM.
func mergeServiceArgs(scmArgs, configured []string) []string {
	out := append([]string{}, configured...)
	if len(scmArgs) > 1 {
		out = append(out, scmArgs[1:]...)
	}
	return out
}

type agentService struct{ args []string }

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	runArgs := mergeServiceArgs(args, s.args)
	if len(runArgs) > 0 && runArgs[0] == "service" {
		runArgs = runArgs[1:]
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runAgentContext(ctx, runArgs) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case cr := <-r:
			switch cr.Cmd {
			case svc.Interrogate:
				changes <- cr.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-errCh:
					if err != nil && !errors.Is(err, context.Canceled) &&
						!strings.Contains(strings.ToLower(err.Error()), "stopped") {
						logServiceEvent(2, "agent stopped with error: "+err.Error())
						return false, 1
					}
					return false, 0
				case <-time.After(10 * time.Second):
					logServiceEvent(3, "agent stop timed out")
					return false, 0
				}
			}
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				logServiceEvent(4, "agent exited with error: "+err.Error())
				return false, 1
			}
			return false, 0
		}
	}
}
