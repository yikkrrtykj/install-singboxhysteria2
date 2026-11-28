package web_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

func TestUMCAccountAdminEndpointsAndTOTPUpdate(t *testing.T) {
	tw := newTestWeb(t)
	now := time.Now()
	hash, _ := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	user, err := tw.store.BootstrapAuthUser(context.Background(), "admin-endpoints", hash, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	eventA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	eventB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for _, id := range []string{eventA, eventB} {
		if _, err := tw.store.CreateEvent(context.Background(), id, id, now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	totpSecret, _ := umcauth.NewTOTPSecret()
	sealed, _ := umcauth.Seal(tw.master, []byte(totpSecret), []byte("umc-totp:"+user.UserID+":v1"))
	if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pre := tw.startContext(t)
	status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
		map[string]any{"username": "admin-endpoints", "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", status, raw)
	}
	pending, _ := decodeMap(t, raw)["csrf_token"].(string)
	code, _ := umcauth.TOTPCode(totpSecret, *tw.clock)
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pending, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP status=%d body=%s", status, raw)
	}
	csrf, _ := decodeMap(t, raw)["csrf_token"].(string)

	// Create, list, role/scope update, disable/enable and reset-password.
	status, raw = tw.request(t, http.MethodPost, "/web/api/users", csrf,
		map[string]any{"username": "managed-user", "role": "viewer", "event_ids": []string{eventA}}, tw.jwt)
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d body=%s", status, raw)
	}
	created := decodeMap(t, raw)["user"].(map[string]any)
	managedID, _ := created["user_id"].(string)
	if managedID == "" {
		t.Fatalf("created user id missing: %s", raw)
	}
	for _, action := range []string{"disable", "enable", "reset-password"} {
		status, raw = tw.request(t, http.MethodPost, "/web/api/users/"+managedID+"/"+action, csrf, nil, tw.jwt)
		if status != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", action, status, raw)
		}
	}
	status, raw = tw.request(t, http.MethodPost, "/web/api/users/"+managedID+"/role", csrf,
		map[string]any{"role": "event_admin", "event_ids": []string{eventA, eventB}}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("role update status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodGet, "/web/api/users/"+managedID, "", nil, tw.jwt)
	if status != http.StatusOK || !bytesContains(raw, eventB) {
		t.Fatalf("user detail status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodGet, "/web/api/users/"+managedID+"/sessions", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("admin session list status=%d body=%s", status, raw)
	}

	// Recovery-code regeneration and TOTP re-enrollment for the current admin.
	status, raw = tw.request(t, http.MethodPost, "/auth/recovery-codes", csrf, nil, tw.jwt)
	if status != http.StatusOK || !bytesContains(raw, "recovery_codes") {
		t.Fatalf("recovery code regeneration status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodPost, "/auth/totp/update", csrf,
		map[string]any{"password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP update start status=%d body=%s", status, raw)
	}
	update := decodeMap(t, raw)
	newSecret, _ := update["secret"].(string)
	updateCSRF, _ := update["csrf_token"].(string)
	newCode, _ := umcauth.TOTPCode(newSecret, *tw.clock)
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", updateCSRF, map[string]any{"code": newCode}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP update confirm status=%d body=%s", status, raw)
	}
	active := decodeMap(t, raw)
	if active["authenticated"] != true {
		t.Fatalf("TOTP update did not activate: %s", raw)
	}
}
