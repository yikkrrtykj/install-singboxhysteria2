package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// Options configures the shared runtime. Collector is platform-specific.
type Options struct {
	StateDir     string
	CenterURL    string
	NodeClass    string
	HostOS       string
	AgentVersion string
	Collector    Collector
	HTTPClient   *http.Client
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
	MaxBackoff   time.Duration
	// SpoolMaxBytes/SpoolMaxAge are test overrides; zero uses frozen defaults.
	SpoolMaxBytes int64
	SpoolMaxAge   time.Duration
}

// Status is safe diagnostic state (no secrets/payloads/paths).
type Status struct {
	Enrolled      bool
	Revoked       bool
	Terminal      string
	ConfigVersion int
	Generation    uint64
	NextSeq       uint64
	Pending       int
	Quarantined   int
	LastResult    string
}

// Runtime is the shared B3 agent runtime.
type Runtime struct {
	mu               sync.Mutex
	opts             Options
	state            *State
	client           *Client
	collector        Collector
	host             HostInfo
	terminal         error
	revoked          bool
	lastCollect      int64
	lastConfigCheck  int64
	clockOffset      int64
	sentStartupEvent bool
	lastResult       string
	backoff          time.Duration
	closed           bool
}

// NewRuntime opens the state directory and applies durable recovery
// reconciliation. It performs no network I/O.
func NewRuntime(opts Options) (*Runtime, error) {
	if !validClass(opts.NodeClass) {
		return nil, errors.New("agent: node class must be linux_vps or windows_terminal")
	}
	if opts.AgentVersion == "" {
		opts.AgentVersion = "1.0.0"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepContext
	}
	if opts.MaxBackoff <= 0 || opts.MaxBackoff > 60*time.Second {
		opts.MaxBackoff = 60 * time.Second
	}
	st, err := OpenState(opts.StateDir)
	if err != nil {
		return nil, err
	}
	if opts.SpoolMaxBytes > 0 || opts.SpoolMaxAge > 0 {
		st.spool.SetLimits(opts.SpoolMaxBytes, opts.SpoolMaxAge)
	}
	// Expired spool payloads are removed by the frozen 7-day retention policy
	// before any restart/replay work; a full live spool is fail-closed instead of
	// silently evicting fsynced data.
	if err := st.spool.Prune(opts.Now().Unix()); err != nil {
		_ = st.Close()
		return nil, err
	}
	if reason, err := st.failClosedReason(); err != nil {
		_ = st.Close()
		return nil, err
	} else if reason != "" {
		_ = st.Close()
		return nil, fmt.Errorf("%w: %s", ErrFailClosed, reason)
	}
	host := platformHost()
	if opts.HostOS != "" {
		host.OS = opts.HostOS
	}
	if host.OS == "" || host.Kernel == "" || (host.Arch != "amd64" && host.Arch != "arm64") {
		_ = st.Close()
		return nil, errors.New("agent: host os/kernel/arch is invalid")
	}
	client, err := NewClient(opts.CenterURL, opts.HTTPClient, opts.Now)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	r := &Runtime{opts: opts, state: st, client: client, collector: opts.Collector, host: host, backoff: time.Second}
	if ident, ok := st.Identity(); ok {
		if ident.NodeClass != opts.NodeClass || ident.CenterURL != opts.CenterURL {
			_ = st.Close()
			return nil, errors.New("agent: persisted identity center/class mismatch")
		}
		if err := r.advanceCleanRestart(); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	if err := r.reconcileBoot(); err != nil {
		_ = st.Close()
		return nil, err
	}
	return r, nil
}

func validClass(c string) bool { return c == "linux_vps" || c == "windows_terminal" }

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// advanceCleanRestart implements the rev-5 normal-restart rule: a clean
// shutdown increments generation by exactly 1, replaces the boot id and replays
// pending payload records under the new generation with fresh transport fields.
// An abrupt power loss leaves no marker and preserves the generation/boot/seq
// persisted attempt for exact duplicate recovery (REC-27).
func (r *Runtime) advanceCleanRestart() error {
	clean, err := r.state.cleanShutdownRequested()
	if err != nil || !clean {
		return err
	}
	ident, ok := r.state.Identity()
	if !ok {
		return nil
	}
	boot, ok := r.state.Boot()
	if !ok {
		return ErrBootStateCorrupt
	}
	if boot.Generation >= wire.MaxNumeric {
		return ErrGenerationExhausted
	}
	newID, err := newBootID()
	if err != nil {
		return err
	}
	boot = BootState{Version: stateVersion, Generation: boot.Generation + 1, BootID: newID, NextSeq: 1}
	if err := r.state.saveBoot(boot); err != nil {
		return err
	}
	now := r.nowUnix()
	next := func() (Attempt, error) {
		if boot.Exhausted || boot.NextSeq == 0 || boot.NextSeq > wire.MaxNumeric {
			return Attempt{}, ErrGenerationExhausted
		}
		nonce, err := newNonce()
		if err != nil {
			return Attempt{}, err
		}
		a := Attempt{Generation: boot.Generation, BootID: boot.BootID, Seq: boot.NextSeq, SentAt: now, Nonce: nonce}
		if boot.NextSeq == wire.MaxNumeric {
			boot.Exhausted = true
		} else {
			boot.NextSeq++
		}
		if err := r.state.saveBoot(boot); err != nil {
			return Attempt{}, err
		}
		return a, nil
	}
	recs, err := r.state.spool.List()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		a, err := next()
		if err != nil {
			return err
		}
		a.Fingerprint, err = wire.Fingerprint(ReportFields(ident, a), rec.Body)
		if err != nil {
			return err
		}
		if err := r.state.spool.UpdateAttempt(rec.ID, a); err != nil {
			return err
		}
	}
	if ctl, ok := r.state.Control(); ok {
		a, err := next()
		if err != nil {
			return err
		}
		if ctl.Kind == "rotate" {
			// Rev-5 A-5: preserve intent nonce across a generation refresh.
			a.Nonce = ctl.Attempt.Nonce
		}
		ctl.Attempt = a
		if err := r.state.saveControl(ctl); err != nil {
			return err
		}
	}
	if err := r.state.clearCleanShutdown(); err != nil {
		return err
	}
	r.lastCollect = 0
	return nil
}

// reconcileBoot recovers NextSeq after a crash between spool/control write and
// boot-state persistence. It never lowers a persisted high-water.
func (r *Runtime) reconcileBoot() error {
	boot, ok := r.state.Boot()
	if !ok {
		return nil
	}
	maxSeq := uint64(0)
	recs, err := r.state.spool.List()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.Attempt.Seq > maxSeq {
			maxSeq = rec.Attempt.Seq
		}
	}
	if ctl, ok := r.state.Control(); ok {
		if ctl.Attempt.Seq > maxSeq {
			maxSeq = ctl.Attempt.Seq
		}
	}
	if maxSeq > 0 && (boot.NextSeq <= maxSeq && !boot.Exhausted) {
		if maxSeq >= wire.MaxNumeric {
			boot.NextSeq = wire.MaxNumeric
			boot.Exhausted = true
		} else {
			boot.NextSeq = maxSeq + 1
		}
		return r.state.saveBoot(boot)
	}
	return nil
}

// Identity returns the persisted identity (private key omitted by String like
// callers should not log the struct).
func (r *Runtime) Identity() (Identity, bool) { return r.state.Identity() }

// Boot returns the atomic boot state.
func (r *Runtime) Boot() (BootState, bool) { return r.state.Boot() }

// Config returns the current validated config.
func (r *Runtime) Config() (AgentConfig, bool) { return r.state.Config() }

// Status returns diagnostic state without secrets or payloads.
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{Quarantined: r.state.spool.QuarantinedCount()}
	if _, ok := r.state.Identity(); ok {
		s.Enrolled = true
	}
	if boot, ok := r.state.Boot(); ok {
		s.Generation = boot.Generation
		s.NextSeq = boot.NextSeq
	}
	if cfg, ok := r.state.Config(); ok {
		s.ConfigVersion = cfg.ConfigVersion
	}
	if recs, err := r.state.spool.List(); err == nil {
		s.Pending = len(recs)
	}
	if r.terminal != nil {
		s.Terminal = r.terminal.Error()
	}
	s.Revoked = r.revoked
	return s
}

func (r *Runtime) fail(err error) error {
	r.terminal = err
	if r.state != nil {
		_ = r.state.markFailClosed(err.Error())
	}
	return err
}

func (r *Runtime) failRevoked() error {
	r.revoked = true
	if r.state != nil {
		_ = r.state.markFailClosed(ErrRevoked.Error())
	}
	return ErrRevoked
}

func (r *Runtime) isTerminal() error {
	if r.revoked {
		return ErrRevoked
	}
	return r.terminal
}

// Enroll performs one real enrollment and atomically persists identity+boot
// state (two fsynced files; a crash between them is fail-closed boot corruption).
func (r *Runtime) Enroll(ctx context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.state.Identity(); ok {
		return ErrAlreadyEnrolled
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	req := EnrollRequest{
		V: 1, NodeClass: r.opts.NodeClass, AgentVersion: r.opts.AgentVersion,
		Host:         hostJSON{OS: r.host.OS, Kernel: r.host.Kernel, Arch: r.host.Arch},
		Capabilities: []string{"metrics_v1", "events_v1", "rotate_v1", "config_v1"},
	}
	resp, err := r.client.Enroll(ctx, strings.TrimSpace(token), req, priv)
	if err != nil {
		return err
	}
	if resp.NodeClass != r.opts.NodeClass {
		return errors.New("agent: enrollment class mismatch")
	}
	id := Identity{
		Version: stateVersion, CenterURL: r.opts.CenterURL, NodeID: resp.NodeID,
		EventID: resp.EventID, NodeClass: resp.NodeClass, KeyID: resp.KeyID,
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
	}
	bootID, err := newBootID()
	if err != nil {
		return err
	}
	if err := r.state.saveIdentity(id); err != nil {
		return err
	}
	if err := r.state.saveBoot(BootState{Version: stateVersion, Generation: 1, BootID: bootID, NextSeq: 1}); err != nil {
		return ErrBootStateCorrupt
	}
	return nil
}

// nowUnix applies a learned center clock offset. The offset is set only from a
// frozen `stale_timestamp` error's server_time and is never trusted for signing
// identity or high-water decisions.
func (r *Runtime) nowUnix() int64 { return r.opts.Now().Unix() + r.clockOffset }

func (r *Runtime) learnClock(ce *CenterError) {
	if ce != nil && ce.Code == "stale_timestamp" && ce.ServerTime > 0 && r.opts.Now != nil {
		r.clockOffset = ce.ServerTime - r.opts.Now().Unix()
	}
}

// nextAttempt allocates and persists the next sequence before a request can be
// sent. Exhaustion uses the frozen MAX_NUMERIC boundary and never wraps.
func (r *Runtime) nextAttempt() (Attempt, error) {
	boot, ok := r.state.Boot()
	if !ok {
		return Attempt{}, ErrNotEnrolled
	}
	if boot.Exhausted || boot.NextSeq == 0 || boot.NextSeq > wire.MaxNumeric {
		return Attempt{}, ErrGenerationExhausted
	}
	nonce, err := newNonce()
	if err != nil {
		return Attempt{}, err
	}
	a := Attempt{Generation: boot.Generation, BootID: boot.BootID, Seq: boot.NextSeq,
		SentAt: r.nowUnix(), Nonce: nonce}
	if boot.NextSeq == wire.MaxNumeric {
		boot.Exhausted = true
	} else {
		boot.NextSeq++
	}
	if err := r.state.saveBoot(boot); err != nil {
		return Attempt{}, err
	}
	return a, nil
}

// ReportFields exposes the frozen signing fields for a persisted attempt so
// tests/recovery tooling can verify fingerprints.
func ReportFields(identity Identity, attempt Attempt) wire.Fields {
	return wire.Fields{
		Endpoint: wire.Report, Protocol: wire.ProtocolVersion, Encoding: "identity",
		NodeID: identity.NodeID, KeyID: identity.KeyID,
		BootGen: strconv.FormatUint(attempt.Generation, 10), BootID: attempt.BootID,
		Sequence: strconv.FormatUint(attempt.Seq, 10), SentAt: strconv.FormatInt(attempt.SentAt, 10),
		Nonce: attempt.Nonce,
	}
}

func (r *Runtime) configFromResponse(c Config) (AgentConfig, error) {
	if c.ConfigVersion < 1 || c.Cadence < 30 || c.Cadence > 300 || len(c.Collect) != 6 {
		return AgentConfig{}, errors.New("agent: invalid config")
	}
	return AgentConfig{Version: stateVersion, ConfigVersion: c.ConfigVersion, Cadence: c.Cadence,
		Collect: cloneBoolMap(c.Collect), DeviceSalt: c.DeviceSalt, ServerTime: c.ServerTime,
		Tags: append([]InboundTag(nil), c.Tags...), Raw: append([]byte(nil), c.Raw...)}, nil
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// PullConfig performs the authenticated config request, using a persisted
// control attempt on restart so a lost response is replayed exactly.
func (r *Runtime) PullConfig(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pullConfigLocked(ctx)
}

func (r *Runtime) pullConfigLocked(ctx context.Context) error {
	if err := r.isTerminal(); err != nil {
		return err
	}
	ident, ok := r.state.Identity()
	if !ok {
		return ErrNotEnrolled
	}
	ctl, has := r.state.Control()
	if has && ctl.Kind == "rotate" {
		return r.driveRotationLocked(ctx, ident, ctl)
	}
	if !has {
		a, err := r.nextAttempt()
		if err != nil {
			return err
		}
		ctl = ControlState{Version: stateVersion, Kind: "config", Attempt: a}
		if err := r.state.saveControl(ctl); err != nil {
			return err
		}
	}
	if ctl.Attempt.SentAt > 0 && r.nowUnix()-ctl.Attempt.SentAt > 240 {
		return r.refreshControlLocked(ctl)
	}
	cfg, err := r.client.Config(ctx, ident, ctl.Attempt)
	if err != nil {
		var ce *CenterError
		if errors.As(err, &ce) && ce.Code == "stale_timestamp" {
			r.learnClock(ce)
			if rerr := r.refreshControlLocked(ctl); rerr != nil {
				return rerr
			}
			if updated, ok := r.state.Control(); ok {
				ctl = updated
			}
			cfg, err = r.client.Config(ctx, ident, ctl.Attempt)
		}
		if err != nil {
			return r.handleControlError(err)
		}
	}
	ac, err := r.configFromResponse(cfg)
	if err != nil {
		return r.fail(err)
	}
	if err := r.state.saveConfig(ac); err != nil {
		return err
	}
	if err := r.state.clearControl(); err != nil {
		return err
	}
	r.lastCollect = 0
	return nil
}

func (r *Runtime) refreshControlLocked(ctl ControlState) error {
	a, err := r.nextAttempt()
	if err != nil {
		return err
	}
	if ctl.Kind == "rotate" {
		// Rev-5 A-5: refreshed transport fields must preserve the intent nonce.
		a.Nonce = ctl.Attempt.Nonce
	}
	ctl.Attempt = a
	return r.state.saveControl(ctl)
}

// QueueReport builds a contract body through the collector and fsyncs it before
// returning. It returns the report_id; sending is separate.
func (r *Runtime) QueueReport(ctx context.Context, kind string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.isTerminal(); err != nil {
		return "", err
	}
	if r.collector == nil {
		return "", errors.New("agent: no platform collector")
	}
	cfg, ok := r.state.Config()
	if !ok {
		return "", ErrNotEnrolled
	}
	id, err := newUUIDv4()
	if err != nil {
		return "", err
	}
	now := r.nowUnix()
	rc := ReportContext{ReportID: id, CollectedAt: now, Host: r.host, Config: CollectConfig{
		ConfigVersion: cfg.ConfigVersion, Cadence: cfg.Cadence, Sources: cloneBoolMap(cfg.Collect),
		ExpectedTags: append([]InboundTag(nil), cfg.Tags...), DeviceSalt: cfg.DeviceSalt,
	}}
	var body []byte
	switch kind {
	case "snapshot":
		body, err = r.collector.Snapshot(ctx, rc)
	case "metrics":
		body, err = r.collector.Metrics(ctx, rc)
	case "events":
		body, err = r.collector.Events(ctx, rc)
	default:
		return "", fmt.Errorf("agent: unknown report kind %q", kind)
	}
	if err != nil {
		return "", err
	}
	a, err := r.nextAttempt()
	if err != nil {
		return "", err
	}
	ident, _ := r.state.Identity()
	a.Fingerprint, err = wire.Fingerprint(ReportFields(ident, a), body)
	if err != nil {
		return "", err
	}
	rec := SpoolRecord{Version: stateVersion, ID: id, Kind: kind, CreatedAt: now, Attempt: a, Body: body}
	if err := r.state.spool.Enqueue(rec); err != nil {
		return "", err
	}
	return id, nil
}

// Flush sends pending control/report records once. Transient failures return an
// error for the caller's retry loop; acknowledged records are removed only after
// a durable ACK.
func (r *Runtime) Flush(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked(ctx)
}

func (r *Runtime) flushLocked(ctx context.Context) error {
	if err := r.isTerminal(); err != nil {
		return err
	}
	ident, ok := r.state.Identity()
	if !ok {
		return ErrNotEnrolled
	}
	if ctl, ok := r.state.Control(); ok {
		if ctl.Kind == "rotate" {
			if err := r.driveRotationLocked(ctx, ident, ctl); err != nil {
				return err
			}
		} else if err := r.pullConfigLocked(ctx); err != nil {
			return err
		}
	}
	if rot, ok := r.state.Rotation(); ok && rot.NewKeyID != "" {
		if err := r.driveProofLocked(ctx, ident, rot); err != nil {
			return err
		}
	}
	recs, err := r.state.spool.List()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if err := r.sendRecordLocked(ctx, ident, rec); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) sendRecordLocked(ctx context.Context, ident Identity, rec SpoolRecord) error {
	if r.nowUnix()-rec.Attempt.SentAt > 240 {
		a, err := r.nextAttempt()
		if err != nil {
			return err
		}
		// Preserve payload identity; only transport fields are refreshed.
		a.Fingerprint, err = wire.Fingerprint(ReportFields(ident, a), rec.Body)
		if err != nil {
			return err
		}
		if err := r.state.spool.UpdateAttempt(rec.ID, a); err != nil {
			return err
		}
		rec.Attempt = a
	}
	ack, err := r.client.Report(ctx, ident, rec.Attempt, rec.Kind, rec.Body)
	if err != nil {
		var ce *CenterError
		if errors.As(err, &ce) && ce.Code == "stale_timestamp" {
			r.learnClock(ce)
			a, rerr := r.nextAttempt()
			if rerr != nil {
				return rerr
			}
			a.Fingerprint, rerr = wire.Fingerprint(ReportFields(ident, a), rec.Body)
			if rerr != nil {
				return rerr
			}
			if rerr := r.state.spool.UpdateAttempt(rec.ID, a); rerr != nil {
				return rerr
			}
			rec.Attempt = a
			ack, err = r.client.Report(ctx, ident, rec.Attempt, rec.Kind, rec.Body)
		}
		if err != nil {
			return r.handleReportError(err, rec)
		}
	}
	if ack.ReportID != rec.ID {
		return r.fail(errors.New("agent: ACK report id mismatch"))
	}
	exhausted := ack.NextSeq == nil
	if err := r.applyAck(ack); err != nil && !exhausted {
		return err
	}
	if ack.Result == "accepted" || ack.Result == "duplicate" || ack.Result == "stale_ignored" {
		if err := r.state.spool.Remove(rec.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if exhausted {
		return ErrGenerationExhausted
	}
	r.backoff = time.Second
	r.lastResult = ack.Result
	return nil
}

// LastResult reports the last ACK result for diagnostics.
func (r *Runtime) LastResult() string { r.mu.Lock(); defer r.mu.Unlock(); return r.lastResult }

func (r *Runtime) applyAck(ack Ack) error {
	boot, ok := r.state.Boot()
	if !ok {
		return ErrBootStateCorrupt
	}
	if ack.NextSeq == nil {
		boot.Exhausted = true
		if err := r.state.saveBoot(boot); err != nil {
			return err
		}
		return ErrGenerationExhausted
	}
	n := *ack.NextSeq
	if n < 1 || n > wire.MaxNumeric {
		return r.fail(errors.New("agent: invalid ACK next_seq"))
	}
	if n > boot.NextSeq {
		boot.NextSeq = n
		boot.Exhausted = false
		if err := r.state.saveBoot(boot); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) handleReportError(err error, rec SpoolRecord) error {
	var ce *CenterError
	if !errors.As(err, &ce) {
		return err
	}
	switch ce.Code {
	case "revoked_key", "unknown_node":
		return r.failRevoked()
	case "stale_boot_generation":
		return r.fail(ErrStaleGeneration)
	case "sequence_conflict":
		return r.fail(ErrSequenceConflict)
	case "generation_exhausted", "sequence_exhausted":
		return r.fail(ErrGenerationExhausted)
	case "invalid_request", "platform_mismatch":
		// Preserve the record for operator inspection; never silently delete a
		// payload the center did not accept.
		if qerr := r.state.spool.Quarantine(rec.ID, ce.Code); qerr != nil && !errors.Is(qerr, os.ErrNotExist) {
			return qerr
		}
		return &CenterError{Status: ce.Status, Code: ce.Code, Retryable: false, ServerTime: ce.ServerTime}
	default:
		return ce
	}
}

func (r *Runtime) handleControlError(err error) error {
	var ce *CenterError
	if !errors.As(err, &ce) {
		return err
	}
	switch ce.Code {
	case "revoked_key", "unknown_node":
		return r.failRevoked()
	case "stale_boot_generation":
		return r.fail(ErrStaleGeneration)
	case "sequence_conflict":
		return r.fail(ErrSequenceConflict)
	case "generation_exhausted":
		return r.fail(ErrGenerationExhausted)
	default:
		return ce
	}
}

// Drive sends pending records with bounded 1..60s exponential backoff until the
// queue drains, a terminal condition occurs, or ctx is canceled.
func (r *Runtime) Drive(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := r.Flush(ctx)
		if err == nil {
			return nil
		}
		if !IsRetryable(err) {
			return err
		}
		if err := r.opts.Sleep(ctx, r.backoff); err != nil {
			return err
		}
		if r.backoff < r.opts.MaxBackoff {
			r.backoff *= 2
			if r.backoff > r.opts.MaxBackoff {
				r.backoff = r.opts.MaxBackoff
			}
		}
	}
}

// Run performs the periodic collection/report loop. Transient network failures
// are retried with the same backoff; revoked/stale/corrupt states stop.
func (r *Runtime) Run(ctx context.Context) error {
	r.mu.Lock()
	ident, ok := r.state.Identity()
	r.mu.Unlock()
	if !ok {
		return ErrNotEnrolled
	}
	_ = ident
	if _, ok := r.state.Config(); !ok {
		if err := r.PullConfig(ctx); err != nil {
			return err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Refresh center-managed collection authorization on a bounded cadence.
		if now := r.nowUnix(); now-r.lastConfigCheck >= 300 {
			if err := r.PullConfig(ctx); err != nil {
				return r.retryOrFail(ctx, err)
			}
			r.lastConfigCheck = now
		}
		if !r.sentStartupEvent {
			if _, err := r.QueueReport(ctx, "events"); err == nil {
				r.sentStartupEvent = true
			} else if !errors.Is(err, ErrUnsupported) {
				return err
			} else {
				r.sentStartupEvent = true
			}
		}
		cfg, ok := r.state.Config()
		if !ok {
			if err := r.PullConfig(ctx); err != nil {
				return r.retryOrFail(ctx, err)
			}
			continue
		}
		now := r.nowUnix()
		if now-r.lastCollect >= int64(cfg.Cadence) {
			if _, err := r.QueueReport(ctx, "snapshot"); err != nil {
				return err
			}
			r.mu.Lock()
			r.lastCollect = now
			r.mu.Unlock()
		}
		if err := r.Drive(ctx); err != nil {
			return err
		}
		wait := time.Duration(cfg.Cadence) * time.Second
		if wait < time.Second {
			wait = time.Second
		}
		if err := r.opts.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func (r *Runtime) retryOrFail(ctx context.Context, err error) error {
	if !IsRetryable(err) {
		return err
	}
	return r.Drive(ctx)
}

// Rotate begins a persisted key rotation intent. The provisional key is not
// switched into the identity until a valid proof report is accepted.
func (r *Runtime) Rotate(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ident, ok := r.state.Identity()
	if !ok {
		return ErrNotEnrolled
	}
	if rot, ok := r.state.Rotation(); ok {
		if rot.NewKeyID != "" {
			return r.driveProofLocked(ctx, ident, rot)
		}
		ctl, has := r.state.Control()
		if !has {
			a, err := r.nextAttempt()
			if err != nil {
				return err
			}
			a.Nonce = rot.Nonce
			ctl = ControlState{Version: stateVersion, Kind: "rotate", Attempt: a,
				NewPublicKey: rot.NewPublicKey, NewPrivateKey: rot.NewPrivateKey}
			if err := r.state.saveControl(ctl); err != nil {
				return err
			}
		}
		return r.driveRotationLocked(ctx, ident, ctl)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	a, err := r.nextAttempt()
	if err != nil {
		return err
	}
	rot := RotationState{Version: stateVersion, Nonce: a.Nonce, NewPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		NewPrivateKey: base64.RawURLEncoding.EncodeToString(priv), State: "awaiting_proof"}
	ctl := ControlState{Version: stateVersion, Kind: "rotate", Attempt: a, Body: []byte(`{}`),
		NewPublicKey: rot.NewPublicKey, NewPrivateKey: rot.NewPrivateKey}
	if err := r.state.saveRotation(rot); err != nil {
		return err
	}
	if err := r.state.saveControl(ctl); err != nil {
		return err
	}
	return r.driveRotationLocked(ctx, ident, ctl)
}

func (r *Runtime) driveRotationLocked(ctx context.Context, ident Identity, ctl ControlState) error {
	if ctl.Attempt.Generation == 0 {
		a, err := r.nextAttempt()
		if err != nil {
			return err
		}
		ctl.Attempt = a
		if err := r.state.saveControl(ctl); err != nil {
			return err
		}
	}
	if ctl.Attempt.SentAt > 0 && r.nowUnix()-ctl.Attempt.SentAt > 240 {
		if err := r.refreshControlLocked(ctl); err != nil {
			return err
		}
		if updated, ok := r.state.Control(); ok {
			ctl = updated
		}
	}
	resp, err := r.client.Rotate(ctx, ident, ctl.Attempt, ctl.Attempt.Nonce, ctl.NewPublicKey)
	if err != nil {
		var ce *CenterError
		if errors.As(err, &ce) && ce.Code == "stale_timestamp" {
			r.learnClock(ce)
			if rerr := r.refreshControlLocked(ctl); rerr != nil {
				return rerr
			}
			if updated, ok := r.state.Control(); ok {
				ctl = updated
			}
			resp, err = r.client.Rotate(ctx, ident, ctl.Attempt, ctl.Attempt.Nonce, ctl.NewPublicKey)
		}
	}
	if err != nil {
		var ce *CenterError
		if errors.As(err, &ce) && ce.Code == "rotation_expired" {
			// Frozen §7: the provisional key is discarded; the old active key
			// remains usable and a later fresh rotation may be started.
			_ = r.state.clearControl()
			_ = r.state.clearRotation()
			return nil
		}
		return r.handleControlError(err)
	}
	rot, ok := r.state.Rotation()
	if !ok {
		return ErrRotationMismatch
	}
	rot.NewKeyID = resp.NewKeyID
	rot.Response = nil
	rot.State = "awaiting_proof"
	if err := r.state.saveRotation(rot); err != nil {
		return err
	}
	return r.state.clearControl()
}

func (r *Runtime) driveProofLocked(ctx context.Context, ident Identity, rot RotationState) error {
	if r.collector == nil {
		return ErrRotationMismatch
	}
	cfg, ok := r.state.Config()
	if !ok {
		return ErrNotEnrolled
	}
	proofIdentity := ident
	proofIdentity.KeyID = rot.NewKeyID
	proofIdentity.PrivateKey = rot.NewPrivateKey
	proofIdentity.PublicKey = rot.NewPublicKey
	id, err := newUUIDv4()
	if err != nil {
		return err
	}
	now := r.nowUnix()
	body, err := r.collector.Snapshot(ctx, ReportContext{ReportID: id, CollectedAt: now, Host: r.host,
		Config: CollectConfig{ConfigVersion: cfg.ConfigVersion, Cadence: cfg.Cadence, Sources: cloneBoolMap(cfg.Collect),
			ExpectedTags: append([]InboundTag(nil), cfg.Tags...), DeviceSalt: cfg.DeviceSalt}})
	if err != nil {
		return err
	}
	a, err := r.nextAttempt()
	if err != nil {
		return err
	}
	a.Fingerprint, err = wire.Fingerprint(ReportFields(proofIdentity, a), body)
	if err != nil {
		return err
	}
	ack, err := r.client.Report(ctx, proofIdentity, a, "snapshot", body)
	if err != nil {
		var ce *CenterError
		if errors.As(err, &ce) && ce.Code == "revoked_key" {
			// Provisional key was rejected/expired: discard the local intent and
			// continue with the still-active old key.
			_ = r.state.clearRotation()
			_ = r.state.clearControl()
			return nil
		}
		return r.handleControlError(err)
	}
	if ack.ReportID != id {
		return r.fail(errors.New("agent: proof ACK id mismatch"))
	}
	if err := r.applyAck(ack); err != nil {
		return err
	}
	ident.KeyID = rot.NewKeyID
	ident.PublicKey = rot.NewPublicKey
	ident.PrivateKey = rot.NewPrivateKey
	if err := r.state.saveIdentity(ident); err != nil {
		return err
	}
	if err := r.state.clearRotation(); err != nil {
		return err
	}
	return nil
}

// Close releases the single-instance lock. It never deletes durable state.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.state.Close()
}
