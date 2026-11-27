package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// SpoolMaxBytes is the frozen B3 spool capacity.
	SpoolMaxBytes int64 = 32 << 20
	// SpoolMaxAge is the frozen B3 spool retention.
	SpoolMaxAge = 7 * 24 * time.Hour
	// QuarantineMaxBytes bounds terminal-rejected/corrupt records kept for
	// operator inspection. Quarantine is deliberately smaller than the spool and
	// is pruned oldest-first; it is never part of the send path.
	QuarantineMaxBytes int64 = 8 << 20
)

// Attempt is the immutable transport attempt persisted with a spool record.
// Exact retries reuse it; after the freshness window the runtime may create a
// new attempt for the same report body, preserving the payload identity.
type Attempt struct {
	Generation  uint64 `json:"generation"`
	BootID      string `json:"boot_id"`
	Seq         uint64 `json:"seq"`
	SentAt      int64  `json:"sent_at"`
	Nonce       string `json:"nonce"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// SpoolRecord is one durable report payload plus its current transport attempt.
type SpoolRecord struct {
	Version   int     `json:"version"`
	ID        string  `json:"id"`
	Kind      string  `json:"kind"`
	CreatedAt int64   `json:"created_at"`
	Attempt   Attempt `json:"attempt"`
	Body      []byte  `json:"body"`

	path string
}

// Spool is a single-writer durable queue. All writes are fsync'ed before the
// caller may send the record.
type Spool struct {
	dir             string
	quarantine      string
	maxBytes        int64
	maxAge          time.Duration
	quarantineBytes int64
	prepared        int64
}

func openSpool(dir, quarantine string) (*Spool, error) {
	if err := rejectLinksInPath(dir); err != nil {
		return nil, err
	}
	if err := rejectLinksInPath(quarantine); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(quarantine, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(quarantine, 0o700); err != nil {
		return nil, err
	}
	return &Spool{dir: dir, quarantine: quarantine, maxBytes: SpoolMaxBytes,
		maxAge: SpoolMaxAge, quarantineBytes: QuarantineMaxBytes}, nil
}

// Close is a no-op: the State lock owns single-writer exclusion.
func (s *Spool) Close() error { return nil }

// SetLimits overrides spool limits for tests only.
func (s *Spool) SetLimits(maxBytes int64, maxAge time.Duration) {
	if maxBytes > 0 {
		s.maxBytes = maxBytes
	}
	if maxAge > 0 {
		s.maxAge = maxAge
	}
}

// SetQuarantineLimit overrides the quarantine byte budget for tests only.
func (s *Spool) SetQuarantineLimit(maxBytes int64) {
	if maxBytes > 0 {
		s.quarantineBytes = maxBytes
	}
}

func (s *Spool) filename(rec SpoolRecord) string {
	return filepath.Join(s.dir, fmt.Sprintf("%020d-%s.json", rec.CreatedAt, rec.ID))
}

// Enqueue fsyncs a record before returning. Capacity is fail-closed: a record
// that would exceed the hard byte cap is rejected and every already-fsynced
// record is left untouched. Expired records are removed by the age policy
// before the capacity check.
func (s *Spool) Enqueue(rec SpoolRecord) error {
	if rec.Version == 0 {
		rec.Version = stateVersion
	}
	if rec.ID == "" || rec.Kind == "" || len(rec.Body) == 0 || rec.CreatedAt <= 0 {
		return errors.New("agent: invalid spool record")
	}
	if rec.Attempt.Generation == 0 || rec.Attempt.Seq == 0 || rec.Attempt.BootID == "" {
		return errors.New("agent: spool record missing transport attempt")
	}
	if err := s.Prune(rec.CreatedAt); err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	total, err := s.usedBytes()
	if err != nil {
		return err
	}
	if int64(len(data)) > s.maxBytes || total+int64(len(data)) > s.maxBytes {
		// Capacity is fail-closed: never silently evict already-fsynced payloads.
		// The runtime surfaces ErrSpoolFull and the operator restores connectivity
		// or follows the documented recovery procedure.
		return ErrSpoolFull
	}
	path := s.filename(rec)
	return writeAtomic(path, data)
}

func (s *Spool) usedBytes() (int64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// List returns valid records oldest-first. Corrupt entries are atomically moved
// to quarantine and are not returned as data; they are never silently deleted.
func (s *Spool) List() ([]SpoolRecord, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := make([]SpoolRecord, 0, len(names))
	for _, name := range names {
		path := filepath.Join(s.dir, name)
		if err := rejectLink(path); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var rec SpoolRecord
		if err := json.Unmarshal(data, &rec); err != nil || rec.Version != stateVersion ||
			rec.ID == "" || rec.Kind == "" || len(rec.Body) == 0 ||
			rec.Attempt.Generation == 0 || rec.Attempt.Seq == 0 || rec.Attempt.BootID == "" {
			_ = s.quarantineFile(path, "corrupt")
			continue
		}
		rec.path = path
		out = append(out, rec)
	}
	// A spool record's attempt is allocated before the record is enqueued, so
	// records created in the same epoch second must be sent in sequence order.
	// Keep the oldest collection time first, but use the persisted enqueue
	// sequence as the tie-breaker instead of the random report UUID.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		if out[i].Attempt.Generation != out[j].Attempt.Generation {
			return out[i].Attempt.Generation < out[j].Attempt.Generation
		}
		if out[i].Attempt.BootID != out[j].Attempt.BootID {
			return out[i].Attempt.BootID < out[j].Attempt.BootID
		}
		if out[i].Attempt.Seq != out[j].Attempt.Seq {
			return out[i].Attempt.Seq < out[j].Attempt.Seq
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// UpdateAttempt atomically rewrites the transport attempt for a pending report
// while preserving its report_id/body identity.
func (s *Spool) UpdateAttempt(id string, attempt Attempt) error {
	recs, err := s.List()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.ID != id {
			continue
		}
		path := rec.path
		rec.Attempt = attempt
		rec.path = ""
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return writeAtomic(path, data)
	}
	return os.ErrNotExist
}

// Remove removes one acknowledged record. It is called only after a durable
// center ACK (accepted/duplicate/stale_ignored), never on transport failure.
func (s *Spool) Remove(id string) error {
	recs, err := s.List()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.ID == id {
			if err := os.Remove(rec.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return syncDir(s.dir)
		}
	}
	return os.ErrNotExist
}

// Quarantine moves one record out of the send path with a reason tag.
func (s *Spool) Quarantine(id, reason string) error {
	recs, err := s.List()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.ID == id {
			return s.quarantineFile(rec.path, reason)
		}
	}
	return os.ErrNotExist
}

func (s *Spool) quarantineFile(path, reason string) error {
	if err := os.MkdirAll(s.quarantine, 0o700); err != nil {
		return err
	}
	target := filepath.Join(s.quarantine,
		fmt.Sprintf("%d-%s-%s", time.Now().UnixNano(), sanitizeReason(reason), filepath.Base(path)))
	if err := os.Rename(path, target); err != nil {
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	if err := s.pruneQuarantine(); err != nil {
		return err
	}
	return syncDir(s.quarantine)
}

// pruneQuarantine enforces the bounded operator-inspection budget. Only files
// already moved out of the send path are eligible; unsent spool records are
// never touched here.
func (s *Spool) pruneQuarantine() error {
	entries, err := os.ReadDir(s.quarantine)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	type qfile struct {
		path    string
		size    int64
		modTime int64
	}
	files := make([]qfile, 0, len(entries))
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		files = append(files, qfile{path: filepath.Join(s.quarantine, e.Name()), size: info.Size(), modTime: info.ModTime().UnixNano()})
		total += info.Size()
	}
	if total <= s.quarantineBytes {
		return nil
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].modTime == files[j].modTime {
			return files[i].path < files[j].path
		}
		return files[i].modTime < files[j].modTime
	})
	for _, f := range files {
		if total <= s.quarantineBytes {
			break
		}
		if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		total -= f.size
	}
	return nil
}

func sanitizeReason(v string) string {
	v = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, v)
	if v == "" {
		return "invalid"
	}
	return v
}

// Prune removes records older than the frozen 7-day retention. It never evicts
// records for byte pressure: over-capacity enqueue is fail-closed in Enqueue.
// Removal failures are returned so a retention failure is not silently ignored.
func (s *Spool) Prune(now int64) error {
	recs, err := s.List()
	if err != nil {
		return err
	}
	cutoff := now - int64(s.maxAge/time.Second)
	removed := false
	for _, rec := range recs {
		if rec.CreatedAt >= cutoff {
			continue
		}
		if err := os.Remove(rec.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return syncDir(s.dir)
}

// QuarantinedCount counts quarantined files for diagnostics.
func (s *Spool) QuarantinedCount() int {
	entries, err := os.ReadDir(s.quarantine)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n
}
