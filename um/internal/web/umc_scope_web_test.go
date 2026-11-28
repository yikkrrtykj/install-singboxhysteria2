package web_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

func TestUMCEventScopeIsolationThroughWebBridge(t *testing.T) {
	tw := newTestWeb(t)
	now := time.Now()
	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	eventB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for _, id := range []string{eventA, eventB} {
		if _, err := tw.store.CreateEvent(context.Background(), id, id, now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	if err != nil {
		t.Fatal(err)
	}
	user, err := tw.store.CreateAuthUser(context.Background(), store.AuthUserInput{
		Username: "scoped-admin", PasswordHash: hash, Role: store.AuthRoleEventAdmin,
		EventIDs: []string{eventA}, Now: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := umcauth.NewTOTPSecret()
	sealed, _ := umcauth.Seal(tw.master, []byte(secret), []byte("umc-totp:"+user.UserID+":v1"))
	if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pre := tw.startContext(t)
	status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
		map[string]any{"username": "scoped-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("scoped login status=%d body=%s", status, raw)
	}
	pendingCSRF, _ := decodeMap(t, raw)["csrf_token"].(string)
	code, _ := umcauth.TOTPCode(secret, time.Now())
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pendingCSRF, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("scoped TOTP status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodGet, "/api/v1/events/"+eventA, "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("assigned event read status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodGet, "/api/v1/events/"+eventB, "", nil, tw.jwt)
	if status != http.StatusForbidden && status != http.StatusNotFound {
		t.Fatalf("unassigned event read status=%d body=%s", status, raw)
	}
	// Event list must not leak the unassigned event.
	status, raw = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("event list status=%d body=%s", status, raw)
	}
	if bytesContains(raw, eventB) {
		t.Fatalf("event list leaked unassigned event: %s", raw)
	}
	// User administration is platform_admin only.
	status, _ = tw.request(t, http.MethodGet, "/web/api/users", "", nil, tw.jwt)
	if status != http.StatusForbidden {
		t.Fatalf("event_admin reached user admin: %d", status)
	}
}

func bytesContains(haystack []byte, needle string) bool {
	return len(haystack) >= len(needle) && bytesIndex(haystack, []byte(needle))
}

func bytesIndex(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
