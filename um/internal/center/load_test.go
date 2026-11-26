package center_test

// B2 load/concurrency smoke tests. They are not a 200-node performance SLA and
// are not production-event acceptance: they use synthetic identities only.

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

func b2EventUUID(n int) string {
	return fmt.Sprintf("2a2b3c4d-5e6f-4a7b-8c9d-%012x", n)
}

func TestB2ConcurrentDuplicateReport(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgentA(t, tc, store.NodeClassLinuxVPS, "linux", b2EventUUID(1))
	doc := b2SnapshotDoc(t, b2BaseCollected(t))
	body := b2JSON(t, doc)
	type outcome struct {
		status int
		result string
	}
	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aa := *a
			aa.seq = 1
			h, err := aa.headers(wire.Report, b2SentAt(t, body), b2Nonce(t), body)
			if err != nil {
				outcomes <- outcome{status: 0}
				return
			}
			status, resp := doPost(t, tc, "/v1/agent/report", h, body)
			result, _ := resp["result"].(string)
			outcomes <- outcome{status: status, result: result}
		}()
	}
	wg.Wait()
	close(outcomes)
	accepted, duplicate, conflict := 0, 0, 0
	for o := range outcomes {
		switch {
		case o.status == 200 && o.result == "accepted":
			accepted++
		case o.status == 200 && o.result == "duplicate":
			duplicate++
		case o.status == 409:
			conflict++
		default:
			t.Fatalf("unexpected concurrent outcome status=%d result=%q", o.status, o.result)
		}
	}
	if accepted > 1 {
		t.Fatalf("concurrent duplicate produced %d accepted outcomes", accepted)
	}
	if accepted+duplicate+conflict != 2 {
		t.Fatalf("concurrent outcomes accepted=%d duplicate=%d conflict=%d", accepted, duplicate, conflict)
	}
	count := queryRawInt(t, tc, `SELECT COUNT(*) FROM snapshots WHERE node_id=?`, a.nodeID)
	if count != 1 {
		t.Fatalf("concurrent duplicate stored %d snapshots, want 1", count)
	}
}

func TestB2SyntheticLoadSmoke(t *testing.T) {
	tc := startTestCenter(t)
	started := time.Now()
	const linuxNodes = 4
	const windowsNodes = 30
	base := b2BaseCollected(t)
	// 4 Linux VPS identities across two synthetic events.
	for i := 0; i < linuxNodes; i++ {
		event := b2EventUUID(i % 2)
		a := enrollAgentA(t, tc, store.NodeClassLinuxVPS, "linux", event)
		doc := b2SnapshotDoc(t, base+int64(i))
		if status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
			t.Fatalf("linux smoke node %d: %d %v", i, status, resp)
		}
	}
	// 30 Windows terminal identities across the same two synthetic events.
	for i := 0; i < windowsNodes; i++ {
		event := b2EventUUID(i % 2)
		a := enrollAgentA(t, tc, store.NodeClassWindowsTerminal, "windows", event)
		if _, err := tc.store.UpdateNodeConfig(context.Background(), a.nodeID, map[string]bool{
			"system": false, "services": false, "singbox_api": false,
			"mihomo_api": true, "terminal": true, "events": true,
		}, nil, 60, time.Now().Unix()); err != nil {
			t.Fatalf("windows config %d: %v", i, err)
		}
		doc := b2Example(t, "terminal-snapshot.v1.json")
		doc["report_id"] = b2UUID(t)
		doc["collected_at"] = base + int64(i)
		b2ShiftReportTimes(doc, base+int64(i))
		if status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t)); status != 200 || resp["result"] != "accepted" {
			t.Fatalf("windows smoke node %d: %d %v", i, status, resp)
		}
	}
	stats, err := tc.store.CapacityStats(context.Background())
	if err != nil {
		t.Fatalf("capacity: %v", err)
	}
	if stats.Nodes != linuxNodes+windowsNodes || stats.Snapshots != linuxNodes+windowsNodes {
		t.Fatalf("smoke capacity nodes=%d snapshots=%d want %d", stats.Nodes, stats.Snapshots, linuxNodes+windowsNodes)
	}
	if got := queryRawInt(t, tc, `SELECT COUNT(DISTINCT event_id) FROM snapshots`); got != 2 {
		t.Fatalf("smoke stored snapshots across %d events, want 2-event isolation", got)
	}
	ext, err := tc.store.CapacityStatsExtended(context.Background())
	if err != nil {
		t.Fatalf("extended capacity: %v", err)
	}
	elapsed := time.Since(started)
	reports := linuxNodes + windowsNodes
	t.Logf("capacity smoke: db=%dB wal=%dB nodes=%dB snapshots=%dB metrics=%dB events=%dB active_events=%d archived_events=%d catalog=%d; reports=%d elapsed=%s avg_tx=%s",
		ext.DBSizeBytes, ext.WALSizeBytes, ext.NodesBytes, ext.SnapshotsBytes, ext.MetricsBytes, ext.EventsBytes,
		ext.ActiveEvents, ext.ArchivedEvents, ext.EventsCatalog, reports, elapsed, elapsed/time.Duration(reports))
}

func queryRawInt(t *testing.T, tc *testCenter, query string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", tc.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	return n
}

func TestB2SustainedSyntheticAgent(t *testing.T) {
	tc := startTestCenter(t)
	a := enrollAgentA(t, tc, store.NodeClassLinuxVPS, "linux", b2EventUUID(0))
	base := b2BaseCollected(t)
	for i := 0; i < 10; i++ {
		doc := b2SnapshotDoc(t, base+int64(i))
		status, resp := b2SendReport(t, tc, a, doc, b2Nonce(t))
		if status != 200 || resp["result"] != "accepted" {
			t.Fatalf("sustained report %d: %d %v", i, status, resp)
		}
	}
	boot, err := tc.store.GetBoot(context.Background(), a.nodeID)
	if err != nil || boot.LastSeq != 10 {
		t.Fatalf("sustained high-water = %+v err=%v", boot, err)
	}
	if got := queryRawInt(t, tc, `SELECT COUNT(*) FROM snapshots WHERE node_id=?`, a.nodeID); got != 10 {
		t.Fatalf("sustained snapshots = %d, want 10", got)
	}
}
