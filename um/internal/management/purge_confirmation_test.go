package management_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

type purgePreviewDoc struct {
	Data struct {
		EventID       string `json:"event_id"`
		PreviewID     string `json:"preview_id"`
		ExpiresAt     int64  `json:"preview_expires_at"`
		ConfirmPhrase string `json:"confirm_phrase"`
		TotalRows     int64  `json:"total_rows"`
	} `json:"data"`
}

func purgePreview(t *testing.T, bc *b4Center, eventID, token string) purgePreviewDoc {
	t.Helper()
	status, raw := rawRequest(t, http.MethodGet,
		bc.adminURL+"/api/v1/events/"+eventID+"/purge/preview", token, nil)
	if status != http.StatusOK {
		t.Fatalf("purge preview status=%d body=%s", status, raw)
	}
	var doc purgePreviewDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Data.PreviewID == "" || doc.Data.ExpiresAt == 0 {
		t.Fatalf("preview did not return a bound confirmation: %s", raw)
	}
	return doc
}

func purgeConfirm(t *testing.T, bc *b4Center, eventID, token, previewID, phrase string) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"confirmation": phrase,
		"preview_id":   previewID,
	})
	return rawRequest(t, http.MethodPost,
		bc.adminURL+"/api/v1/events/"+eventID+"/purge/confirm", token, body)
}

func TestPurgeConfirmationBindsPreviewActorEventAndState(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	createEvent(t, platform, eventB, "B")
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/archive", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"viewer-a", "admin-a"} {
		c := clientFor(t, bc, name)
		if err := c.Call(context.Background(), http.MethodGet,
			"/api/v1/events/"+eventA+"/purge/preview", nil, nil, nil); err == nil {
			t.Fatalf("%s read purge preview", name)
		}
		if err := c.Call(context.Background(), http.MethodPost,
			"/api/v1/events/"+eventA+"/purge/confirm", nil,
			map[string]any{"confirmation": "purge:" + eventA, "preview_id": "x"}, nil); err == nil {
			t.Fatalf("%s purged event", name)
		}
	}

	preview := purgePreview(t, bc, eventA, "platform-token-0123456789abcdef")
	if preview.Data.PreviewID == "" || preview.Data.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("preview not short-lived: %+v", preview.Data)
	}
	// No preview receipt is not authorization for a first permanent deletion.
	if status, raw := purgeConfirm(t, bc, eventA,
		"platform-token-0123456789abcdef", "", preview.Data.ConfirmPhrase); status < 400 {
		t.Fatalf("static phrase alone purged: status=%d body=%s", status, raw)
	}
	// A preview receipt is bound to its event.
	if status, raw := purgeConfirm(t, bc, eventB,
		"platform-token-0123456789abcdef", preview.Data.PreviewID, "purge:"+eventB); status < 400 {
		t.Fatalf("preview for event A authorized event B: status=%d body=%s", status, raw)
	}
	// A preview receipt is bound to the authenticated actor.
	if status, raw := purgeConfirm(t, bc, eventA,
		"platform-b-token-0123456789abcdef", preview.Data.PreviewID, preview.Data.ConfirmPhrase); status < 400 {
		t.Fatalf("preview authorized a different actor: status=%d body=%s", status, raw)
	}

	if status, raw := purgeConfirm(t, bc, eventA,
		"platform-token-0123456789abcdef", preview.Data.PreviewID, preview.Data.ConfirmPhrase); status != http.StatusOK {
		t.Fatalf("valid bound confirmation status=%d body=%s", status, raw)
	}
	// A completed operation remains idempotently queryable after expiry.
	bc.mgmt.Now = func() time.Time { return time.Now().Add(30 * time.Minute) }
	if status, raw := purgeConfirm(t, bc, eventA,
		"platform-token-0123456789abcdef", preview.Data.PreviewID, preview.Data.ConfirmPhrase); status != http.StatusOK {
		t.Fatalf("completed purge idempotence status=%d body=%s", status, raw)
	}
}

func TestPurgeConfirmationExpiryAndPreviewStateChange(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	createEvent(t, platform, eventB, "B")

	expired := purgePreview(t, bc, eventA, "platform-token-0123456789abcdef")
	bc.mgmt.Now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if status, raw := purgeConfirm(t, bc, eventA,
		"platform-token-0123456789abcdef", expired.Data.PreviewID, expired.Data.ConfirmPhrase); status < 400 {
		t.Fatalf("expired confirmation accepted: status=%d body=%s", status, raw)
	}
	bc.mgmt.Now = time.Now

	// Preview while active, change lifecycle to archived before confirm: the
	// receipt is bound to the preview lifecycle and must be re-issued.
	changed := purgePreview(t, bc, eventB, "platform-token-0123456789abcdef")
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventB+"/archive", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if status, raw := purgeConfirm(t, bc, eventB,
		"platform-token-0123456789abcdef", changed.Data.PreviewID, changed.Data.ConfirmPhrase); status < 400 {
		t.Fatalf("state-change confirmation accepted: status=%d body=%s", status, raw)
	}
	// Neither event was purged by the rejected attempts.
	for _, id := range []string{eventA, eventB} {
		status, raw := rawRequest(t, http.MethodGet, bc.adminURL+"/api/v1/events/"+id,
			"platform-token-0123456789abcdef", nil)
		if status != http.StatusOK {
			t.Fatalf("event %s was deleted by rejected confirmation: status=%d body=%s", id, status, raw)
		}
	}
}

func TestPurgeConfirmationResumeAfterAuthorizedPersistence(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/archive", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	preview := purgePreview(t, bc, eventA, "platform-token-0123456789abcdef")
	failed := false
	bc.st.SetRetentionHookForTest(func(stage string) error {
		if stage == "purge:persisted" && !failed {
			failed = true
			return errors.New("injected crash after durable authorization")
		}
		return nil
	})
	status, raw := purgeConfirm(t, bc, eventA,
		"platform-token-0123456789abcdef", preview.Data.PreviewID, preview.Data.ConfirmPhrase)
	bc.st.SetRetentionHookForTest(nil)
	if status < 500 {
		t.Fatalf("injected persistence failure status=%d body=%s", status, raw)
	}
	// The durable purge operation already exists. Its short-lived preview must
	// not block safe recovery after expiry.
	bc.mgmt.Now = func() time.Time { return time.Now().Add(30 * time.Minute) }
	status, raw = purgeConfirm(t, bc, eventA,
		"platform-token-0123456789abcdef", preview.Data.PreviewID, preview.Data.ConfirmPhrase)
	if status != http.StatusOK {
		t.Fatalf("resume after expiry status=%d body=%s", status, raw)
	}
	var statusView management.PurgeStatusView
	if err := platform.Call(context.Background(), http.MethodGet,
		"/api/v1/events/"+eventA+"/purge/status", nil, nil, &statusView); err != nil {
		t.Fatal(err)
	}
	if !statusView.Graveyard {
		t.Fatalf("resumed purge has no graveyard: %+v", statusView)
	}
}

func TestPurgeConfirmationConcurrentReplay(t *testing.T) {
	bc := startB4Center(t)
	platform := clientFor(t, bc, "platform")
	createEvent(t, platform, eventA, "A")
	if err := platform.Call(context.Background(), http.MethodPost,
		"/api/v1/events/"+eventA+"/archive", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	preview := purgePreview(t, bc, eventA, "platform-token-0123456789abcdef")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes int
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _ := purgeConfirm(t, bc, eventA,
				"platform-token-0123456789abcdef", preview.Data.PreviewID, preview.Data.ConfirmPhrase)
			if status == http.StatusOK {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes == 0 {
		t.Fatal("no concurrent confirmation completed")
	}
	var statusView management.PurgeStatusView
	if err := platform.Call(context.Background(), http.MethodGet,
		"/api/v1/events/"+eventA+"/purge/status", nil, nil, &statusView); err != nil {
		t.Fatal(err)
	}
	if !statusView.Graveyard || statusView.DeletedRows < 0 {
		t.Fatalf("concurrent purge status=%+v", statusView)
	}
}
