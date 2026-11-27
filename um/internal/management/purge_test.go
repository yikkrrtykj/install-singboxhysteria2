package management_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

func TestTwoEventPurgeIsolationAndIdempotence(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	createEvent(t, platform, eventB, "B")

	type pair struct {
		event string
		token string
	}
	for _, p := range []pair{{eventA, "A"}, {eventB, "B"}} {
		tok := mustToken(t, platform, p.event, "linux_vps")
		r, _ := enrollAgent(t, bc, "linux_vps", tok.Token)
		defer r.Close()
	}
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventB+"/archive", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var preview management.PurgePreviewView
	if err := platform.Call(context.Background(), http.MethodGet, "/api/v1/events/"+eventB+"/purge/preview", nil, nil, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.ConfirmPhrase != "purge:"+eventB || preview.TotalRows == 0 {
		t.Fatalf("preview=%+v", preview)
	}
	// Wrong/stale confirmation is rejected and does not purge.
	var apiErr *management.APIError
	err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventB+"/purge/confirm", nil,
		map[string]any{"confirmation": "purge:" + eventA}, nil)
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("wrong confirmation err=%v", err)
	}
	var status management.PurgeStatusView
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventB+"/purge/confirm", nil,
		map[string]any{"confirmation": "purge:" + eventB}, &status); err != nil {
		t.Fatal(err)
	}
	if !status.Graveyard {
		t.Fatalf("purge graveyard missing: %+v", status)
	}
	// Repeated request is idempotent and still safe.
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventB+"/purge/confirm", nil,
		map[string]any{"confirmation": "purge:" + eventB}, &status); err != nil {
		t.Fatalf("idempotent purge: %v", err)
	}
	// Event B cannot be recreated, token-created, or listed.
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events", nil,
		map[string]any{"event_id": eventB, "display_name": "recreated"}, nil); err == nil {
		t.Fatal("purged event id recreated")
	}
	if err := platform.Call(context.Background(), http.MethodPost, "/api/v1/events/"+eventB+"/tokens", nil,
		map[string]any{"node_class": "linux_vps", "ttl_seconds": 120}, nil); err == nil {
		t.Fatal("purged event accepted token create")
	}
	var events management.EventList
	if err := platform.Call(context.Background(), http.MethodGet, "/api/v1/events", nil, nil, &events); err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || events.Events[0].EventID != eventA {
		t.Fatalf("event A was affected by event B purge: %+v", events.Events)
	}
	// Audit contains the purge and is queryable by platform scope.
	var audit management.AuditList
	if err := platform.Call(context.Background(), http.MethodGet, "/api/v1/audit?event_id="+eventB, nil, nil, &audit); err != nil {
		t.Fatal(err)
	}
	if audit.Total == 0 {
		t.Fatal("purge audit missing")
	}
}
