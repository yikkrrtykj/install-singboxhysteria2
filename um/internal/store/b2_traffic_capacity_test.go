package store

// Reproducible SQLite capacity measurement for the normalized rev-7 traffic
// tables. It is opt-in because it creates tens of thousands of synthetic rows;
// CI/lab can run it with UM_LT_CAPACITY=1. The output records actual bytes on
// disk and extrapolates the agreed 150-node / 30-day / 30-300 s planning basis.
// The store keeps a bounded 64-report raw ring per node and 15-minute monotone
// lower-bound buckets for the 30-day history; this test verifies that model was
// actually applied rather than sampling only the raw tables.
// It never touches production data and never shortens retention.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUMTLTrafficCapacityMeasurement(t *testing.T) {
	if os.Getenv("UM_LT_CAPACITY") != "1" {
		t.Skip("set UM_LT_CAPACITY=1 to run the opt-in SQLite capacity measurement")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "private", "capacity.db")
	s := openTestStore(t, path)
	ctx := context.Background()
	base := time.Now().Unix() - 86400
	const (
		nodes       = 150
		reportsEach = 96 // 48 minutes at the 30 s worst-case cadence
	)
	for scenarioIndex, inbounds := range []int64{2, 8} {
		startSize := dbFileSizeForCapacity(t, path)
		startReports, startRawObs, startBuckets := trafficRowCounts(t, s)
		startBucketBytes := tableBytesForCapacity(t, s, "traffic_observation_buckets")
		startRawBytes := tableBytesForCapacity(t, s, "traffic_observation_reports") +
			tableBytesForCapacity(t, s, "traffic_observations")
		for node := 0; node < nodes; node++ {
			nodeID := fmt.Sprintf("%08x-1111-4111-8111-%012x", node+1, node+1)
			eventID := fmt.Sprintf("%08x-2222-4222-8222-%012x", node+1, node+1)
			for report := 0; report < reportsEach; report++ {
				at := base + int64(report*30)
				obs := &TrafficObservationRecord{
					Source: "monitor_readonly_export", SourceEpoch: fmt.Sprintf("%032x", node+1),
					Sequence: int64(report), ObservedAt: at, CollectedAt: at, ReceivedAt: at,
					Availability: "ok", Freshness: "fresh", CounterScope: "observation_epoch",
					Exactness: "lower_bound", BytesEstimate: 256,
				}
				for inbound := int64(0); inbound < inbounds; inbound++ {
					tag := fmt.Sprintf("in-%d", inbound)
					uplink := int64(report*1000) + inbound
					downlink := int64(report*5000) + inbound
					obs.Inbounds = append(obs.Inbounds, TrafficInboundRecord{
						InboundTag: tag, Kind: "reality", ObservedAt: at,
						Availability: "ok", Quality: "lower_bound",
						UplinkObservedLowerBoundBytes: &uplink, DownlinkObservedLowerBoundBytes: &downlink,
						ActiveConnections: 1,
					})
				}
				rec := SnapshotRecord{
					NodeID: nodeID, EventID: eventID, NodeClass: "linux_vps",
					ReportID: fmt.Sprintf("%08x-3333-4333-8333-%012x",
						int64(scenarioIndex)*1000000+int64(node)*1000+int64(report)+1,
						int64(scenarioIndex)*1000000+int64(node)*1000+int64(report)+1),
					CollectedAt: at, ReceivedAt: at,
					BodySHA256:         fmt.Sprintf("%064x", int64(scenarioIndex)*1000000+int64(node)*1000+int64(report)+1),
					TrafficObservation: obs,
				}
				if err := s.SeedTrafficObservationForTest(ctx, rec); err != nil {
					t.Fatal(err)
				}
			}
		}
		endSize := dbFileSizeForCapacity(t, path)
		endReports, endRawObs, endBuckets := trafficRowCounts(t, s)
		endBucketBytes := tableBytesForCapacity(t, s, "traffic_observation_buckets")
		endRawBytes := tableBytesForCapacity(t, s, "traffic_observation_reports") +
			tableBytesForCapacity(t, s, "traffic_observations")
		reports := endReports - startReports
		rawObs := endRawObs - startRawObs
		buckets := endBuckets - startBuckets
		delta := endSize - startSize
		// 150 nodes * 96 buckets/day (15 min) * 30 days.
		projectedBuckets := int64(150) * 96 * 30 * inbounds
		bucketBytes := endBucketBytes - startBucketBytes
		rawBytes := endRawBytes - startRawBytes
		projectedBucketBytes := int64(0)
		if buckets > 0 {
			projectedBucketBytes = int64(float64(bucketBytes) / float64(buckets) * float64(projectedBuckets))
		}
		t.Logf("CAPACITY inbounds=%d nodes=%d reports_delta=%d raw_observations_delta=%d buckets_delta=%d file_delta=%d bucket_table_bytes=%d raw_table_bytes=%d projected_bucket_rows=%d projected_bucket_bytes=%d projected_steady_state_bytes=%d",
			inbounds, nodes, reports, rawObs, buckets, delta, bucketBytes, rawBytes,
			projectedBuckets, projectedBucketBytes, projectedBucketBytes+rawBytes)
		if rawObs <= 0 || buckets <= 0 {
			t.Fatalf("capacity scenario did not exercise raw ring + bucket aggregation")
		}
		if reports > nodes*64 {
			t.Fatalf("raw report ring was not bounded: reports=%d cap=%d", reports, nodes*64)
		}
		if projectedBucketBytes+rawBytes > 5*1024*1024*1024 {
			t.Fatalf("projected steady-state traffic bytes exceed the 5 GiB planning basis: %d", projectedBucketBytes+rawBytes)
		}
	}
}

func dbFileSizeForCapacity(t *testing.T, path string) int64 {
	t.Helper()
	total := int64(0)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if info, err := os.Stat(path + suffix); err == nil {
			total += info.Size()
		}
	}
	return total
}

func tableBytesForCapacity(t *testing.T, s *Store, table string) int64 {
	t.Helper()
	var bytes sql.NullInt64
	if err := s.db.QueryRow(`SELECT SUM(pgsize) FROM dbstat WHERE name=?`, table).Scan(&bytes); err != nil {
		t.Fatalf("dbstat %s: %v", table, err)
	}
	if !bytes.Valid {
		return 0
	}
	return bytes.Int64
}

func trafficRowCounts(t *testing.T, s *Store) (reports, rawObservations, buckets int64) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM traffic_observation_reports`).Scan(&reports); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM traffic_observations`).Scan(&rawObservations); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM traffic_observation_buckets`).Scan(&buckets); err != nil {
		t.Fatal(err)
	}
	return reports, rawObservations, buckets
}
