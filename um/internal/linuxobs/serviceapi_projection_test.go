package linuxobs

import (
	"context"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/agent"
)

type fakeServiceAPIObserver struct {
	obs ServiceAPIObservation
	err error
}

func (f fakeServiceAPIObserver) ObserveServiceAPI(context.Context) (ServiceAPIObservation, error) {
	return f.obs, f.err
}

func TestServiceAPIProjectionUsesCumulativeTotals(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	collector.ServiceAPIProbe = fakeServiceAPIObserver{obs: ServiceAPIObservation{
		Connected: true,
		Inbounds: map[string]ServiceAPIInboundEvidence{
			"vless-in": {ActiveConnections: 2, UplinkBytes: 10, DownlinkBytes: 20,
				UplinkTotalBytes: 4000, DownlinkTotalBytes: 8000, TotalsAvailable: true},
			"hy2-in": {ActiveConnections: 1, UplinkBytes: 1, DownlinkBytes: 2,
				UplinkTotalBytes: 1000, DownlinkTotalBytes: 2000, TotalsAvailable: true},
		},
	}}
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"system", "services", "singbox_api", "events"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	if body.Availability.Traffic != availabilityOK || body.Availability.Protocols != availabilityOK {
		t.Fatalf("availability = %+v, want traffic/protocols ok", body.Availability)
	}
	wantTraffic := []trafficEntry{
		{Scope: "protocol", InboundTag: "vless-in", UplinkTotalBytes: int64Ptr(4000), DownlinkTotalBytes: int64Ptr(8000)},
		{Scope: "protocol", InboundTag: "hy2-in", UplinkTotalBytes: int64Ptr(1000), DownlinkTotalBytes: int64Ptr(2000)},
	}
	if len(body.Traffic) != len(wantTraffic) {
		t.Fatalf("traffic = %+v", body.Traffic)
	}
	for i := range wantTraffic {
		if body.Traffic[i].InboundTag != wantTraffic[i].InboundTag ||
			body.Traffic[i].UplinkTotalBytes == nil || *body.Traffic[i].UplinkTotalBytes != *wantTraffic[i].UplinkTotalBytes ||
			body.Traffic[i].DownlinkTotalBytes == nil || *body.Traffic[i].DownlinkTotalBytes != *wantTraffic[i].DownlinkTotalBytes {
			t.Fatalf("traffic[%d] = %+v, want %+v", i, body.Traffic[i], wantTraffic[i])
		}
	}
	// The active-connection aggregate comes from the same observation, never
	// from the cumulative totals.
	metricsRaw, err := collector.Metrics(context.Background(),
		reportContext([]string{"system", "services", "singbox_api", "events"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	metrics := unmarshalMetrics(t, metricsRaw)
	if len(metrics.Samples) != 1 {
		t.Fatalf("samples = %d", len(metrics.Samples))
	}
	requireInt64Ptr(t, "metrics.active_connections", metrics.Samples[0].ActiveConnections, 3)
}

func TestServiceAPIProjectionRequiresAuthorization(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	collector.SingBoxSourceAuthorized = false
	probe := &countingServiceAPIProbe{obs: ServiceAPIObservation{
		Connected: true,
		Inbounds: map[string]ServiceAPIInboundEvidence{
			"vless-in": {ActiveConnections: 1, UplinkTotalBytes: 10, DownlinkTotalBytes: 20, TotalsAvailable: true},
		},
	}}
	collector.ServiceAPIProbe = probe
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"singbox_api"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	if body.Availability.Protocols != availabilityUnavailable || body.Availability.Traffic != availabilityUnavailable {
		t.Fatalf("unauthorized source collected data: %+v", body.Availability)
	}
	if len(body.Protocols) != 0 || len(body.Traffic) != 0 {
		t.Fatalf("unauthorized source produced protocols/traffic: %+v %+v", body.Protocols, body.Traffic)
	}
	if probe.calls != 0 {
		t.Fatalf("unauthorized probe was queried %d times", probe.calls)
	}
}

type countingServiceAPIProbe struct {
	obs   ServiceAPIObservation
	calls int
}

func (probe *countingServiceAPIProbe) ObserveServiceAPI(context.Context) (ServiceAPIObservation, error) {
	probe.calls++
	return probe.obs, nil
}

func TestServiceAPIProjectionDoesNotFabricateOnSkippedEvents(t *testing.T) {
	collector, _, _, _ := newFakeCollector(t)
	collector.ServiceAPIProbe = fakeServiceAPIObserver{obs: ServiceAPIObservation{
		Connected: true, SkippedEvents: 1,
		Inbounds: map[string]ServiceAPIInboundEvidence{
			"vless-in": {ActiveConnections: 1, UplinkTotalBytes: 4000, DownlinkTotalBytes: 8000, TotalsAvailable: true},
		},
	}}
	raw, err := collector.Snapshot(context.Background(),
		reportContext([]string{"singbox_api"}, testExpectedTags()))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	validateSnapshotBody(t, raw)
	body := unmarshalSnapshot(t, raw)
	if body.Availability.Traffic != availabilityUnavailable {
		t.Fatalf("traffic availability = %q, want unavailable when events were skipped", body.Availability.Traffic)
	}
	for _, entry := range body.Traffic {
		if entry.UplinkTotalBytes != nil || entry.DownlinkTotalBytes != nil {
			t.Fatalf("traffic fabricated after skipped events: %+v", entry)
		}
	}
}

var _ ServiceAPIObserver = fakeServiceAPIObserver{}
var _ agent.Collector = (*Collector)(nil)
