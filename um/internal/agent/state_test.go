package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testIdentity(t *testing.T) Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return Identity{Version: stateVersion, CenterURL: "https://center.example",
		NodeID:    "11111111-1111-4111-8111-111111111111",
		EventID:   "22222222-2222-4222-8222-222222222222",
		NodeClass: "linux_vps", KeyID: "key-1234abcd",
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv)}
}

func testRecord(id string, createdAt int64) SpoolRecord {
	return SpoolRecord{Version: stateVersion, ID: id, Kind: "snapshot", CreatedAt: createdAt,
		Attempt: Attempt{Generation: 1, BootID: strings.Repeat("a", 32), Seq: 1, SentAt: createdAt, Nonce: "nonce"},
		Body:    []byte(`{"v":1}`)}
}

func TestStateAtomicLockAndBootCorruption(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenState(dir)
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	id := testIdentity(t)
	if err := s.saveIdentity(id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if err := s.saveBoot(BootState{Version: stateVersion, Generation: 1, BootID: strings.Repeat("b", 32), NextSeq: 1}); err != nil {
		t.Fatalf("save boot: %v", err)
	}
	if _, err := OpenState(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open = %v, want ErrLocked", err)
	}
	info, err := os.Stat(filepath.Join(dir, identityFile))
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %o, want 600", info.Mode().Perm())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := OpenState(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, ok := s2.Boot(); !ok || got.Generation != 1 || got.NextSeq != 1 {
		t.Fatalf("boot after reopen = %+v", got)
	}
	_ = s2.Close()
	// Corrupt boot is fail-closed; no auto-recreation.
	if err := os.WriteFile(filepath.Join(dir, bootStateFile), []byte("{bad"), 0o600); err != nil {
		t.Fatalf("corrupt boot: %v", err)
	}
	if _, err := OpenState(dir); !errors.Is(err, ErrBootStateCorrupt) {
		t.Fatalf("corrupt boot open = %v, want ErrBootStateCorrupt", err)
	}
}

func TestSpoolCorruptionQuarantineAndLimits(t *testing.T) {
	dir := t.TempDir()
	sp, err := openSpool(filepath.Join(dir, "spool"), filepath.Join(dir, "quarantine"))
	if err != nil {
		t.Fatalf("openSpool: %v", err)
	}
	now := time.Now().Unix()
	if err := sp.Enqueue(testRecord("a", now)); err != nil {
		t.Fatalf("enqueue a: %v", err)
	}
	if err := sp.Enqueue(testRecord("b", now+1)); err != nil {
		t.Fatalf("enqueue b: %v", err)
	}
	recs, err := sp.List()
	if err != nil || len(recs) != 2 {
		t.Fatalf("list: %v len=%d", err, len(recs))
	}
	if err := sp.UpdateAttempt("a", Attempt{Generation: 1, BootID: strings.Repeat("a", 32), Seq: 2, SentAt: now + 2, Nonce: "n2"}); err != nil {
		t.Fatalf("update attempt: %v", err)
	}
	recs, _ = sp.List()
	if recs[0].Attempt.Seq != 2 {
		t.Fatalf("attempt not updated: %+v", recs[0])
	}
	// Corrupt a record file: List moves it to quarantine, never deletes silently.
	entries, _ := os.ReadDir(filepath.Join(dir, "spool"))
	for _, e := range entries {
		if strings.Contains(e.Name(), "-b.json") {
			if err := os.WriteFile(filepath.Join(dir, "spool", e.Name()), []byte("not-json"), 0o600); err != nil {
				t.Fatalf("corrupt: %v", err)
			}
		}
	}
	recs, err = sp.List()
	if err != nil {
		t.Fatalf("list after corrupt: %v", err)
	}
	if len(recs) != 1 || sp.QuarantinedCount() != 1 {
		t.Fatalf("after corrupt records=%d quarantined=%d", len(recs), sp.QuarantinedCount())
	}
	if err := sp.Remove("a"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if recs, _ = sp.List(); len(recs) != 0 {
		t.Fatalf("records after remove=%d", len(recs))
	}

	// Age and byte caps are deterministic and never touch the newest record.
	sp2, _ := openSpool(filepath.Join(dir, "spool2"), filepath.Join(dir, "quarantine2"))
	sp2.SetLimits(2200, 24*time.Hour)
	old := now - 2*3600
	rec := testRecord("c1", old)
	rec.Body = make([]byte, 700)
	if err := sp2.Enqueue(rec); err != nil {
		t.Fatalf("first capped enqueue: %v", err)
	}
	rec2 := testRecord("c2", old+1)
	rec2.Body = make([]byte, 700)
	if err := sp2.Enqueue(rec2); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("over-capacity enqueue = %v, want ErrSpoolFull", err)
	}
	if recs, _ = sp2.List(); len(recs) != 1 {
		t.Fatalf("fail-closed spool should retain exactly the existing record, got %d", len(recs))
	}
	if err := sp2.Prune(now + 48*3600); err != nil {
		t.Fatalf("prune age: %v", err)
	}
	if recs, _ = sp2.List(); len(recs) != 0 {
		t.Fatalf("expired records remain: %d", len(recs))
	}
}

func TestUUIDAndNonceShapes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		u, err := newUUIDv4()
		if err != nil {
			t.Fatalf("uuid: %v", err)
		}
		if !nodeIDRe.MatchString(u) || seen[u] {
			t.Fatalf("bad/duplicate UUID %q", u)
		}
		seen[u] = true
		n, err := newNonce()
		if err != nil || len(n) != 22 {
			t.Fatalf("nonce %q err=%v", n, err)
		}
	}
}

func TestClientURLRules(t *testing.T) {
	if _, err := NewClient("http://example.com", nil, nil); err == nil {
		t.Fatal("non-loopback plain HTTP accepted")
	}
	if _, err := NewClient("http://127.0.0.1:8080", nil, nil); err != nil {
		t.Fatalf("loopback HTTP rejected: %v", err)
	}
	if _, err := NewClient("https://center.example", nil, nil); err != nil {
		t.Fatalf("https center rejected: %v", err)
	}
	if _, err := NewClient("https://center.example/path", nil, nil); err == nil {
		t.Fatal("center URL with path accepted")
	}
}

func TestControlStateJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenState(dir)
	defer s.Close()
	ctl := ControlState{Version: stateVersion, Kind: "rotate", Attempt: Attempt{Generation: 1, BootID: strings.Repeat("a", 32), Seq: 1, SentAt: 1, Nonce: "n"},
		NewPublicKey: "pub", NewPrivateKey: "priv"}
	if err := s.saveControl(ctl); err != nil {
		t.Fatalf("save control: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, controlFile))
	if err != nil || !json.Valid(raw) {
		t.Fatalf("control file invalid: %v", err)
	}
	got, ok := s.Control()
	if !ok || got.Kind != "rotate" || got.NewPrivateKey != "priv" {
		t.Fatalf("control roundtrip: %+v", got)
	}
}

func TestStateStaleLockRecoveredOnlyWhenOwnerDead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, lockFile), []byte("deadbeef 999999\n"), 0o600); err != nil {
		t.Fatalf("seed stale lock: %v", err)
	}
	s, err := OpenState(dir)
	if err != nil {
		t.Fatalf("OpenState with provably-dead lock owner: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// A lock owned by this live process must never be stolen.
	if err := os.WriteFile(filepath.Join(dir, lockFile), []byte("livetoken "+strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatalf("seed live lock: %v", err)
	}
	if _, err := OpenState(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("live lock open = %v, want ErrLocked", err)
	}
}
