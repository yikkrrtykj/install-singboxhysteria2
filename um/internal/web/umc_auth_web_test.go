package web_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

func (tw *testWeb) startContext(t *testing.T) string {
	t.Helper()
	status, raw := tw.request(t, http.MethodGet, "/auth/context", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("context status=%d body=%s", status, raw)
	}
	csrf, _ := decodeMap(t, raw)["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("context missing csrf: %s", raw)
	}
	return csrf
}

func (tw *testWeb) loginWithPassword(t *testing.T, password string, csrf string) map[string]any {
	t.Helper()
	status, raw := tw.request(t, http.MethodPost, "/auth/login", csrf,
		map[string]any{"username": "recovery-admin", "password": password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", status, raw)
	}
	return decodeMap(t, raw)
}

func TestUMCRecoveryPasswordSessionsAndLastAdmin(t *testing.T) {
	tw := newTestWeb(t)
	now := time.Now()
	hash, err := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	if err != nil {
		t.Fatal(err)
	}
	user, err := tw.store.BootstrapAuthUser(context.Background(), "recovery-admin", hash, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	eventID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := tw.store.CreateEvent(context.Background(), eventID, "A", now.Unix()); err != nil {
		t.Fatal(err)
	}
	totpSecret, _ := umcauth.NewTOTPSecret()
	sealed, err := umcauth.Seal(tw.master, []byte(totpSecret), []byte("umc-totp:"+user.UserID+":v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	recoveryCodes, err := umcauth.GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]string, len(recoveryCodes))
	for i, code := range recoveryCodes {
		hashes[i] = umcauth.HashRecoveryCode(code)
	}
	if err := tw.store.ReplaceRecoveryCodes(context.Background(), user.UserID, hashes, now.Unix()); err != nil {
		t.Fatal(err)
	}

	// Password + TOTP normal login.
	preCSRF := tw.startContext(t)
	login := tw.loginWithPassword(t, tw.password, preCSRF)
	if login["totp_required"] != true {
		t.Fatalf("expected TOTP challenge: %v", login)
	}
	pendingCSRF, _ := login["csrf_token"].(string)
	code, err := umcauth.TOTPCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, raw := tw.request(t, http.MethodPost, "/auth/totp", pendingCSRF, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP login status=%d body=%s", status, raw)
	}
	active := decodeMap(t, raw)
	csrf, _ := active["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("active csrf missing: %s", raw)
	}
	// Session list works and exposes only an opaque public session id.
	status, raw = tw.request(t, http.MethodGet, "/auth/sessions", "", nil, tw.jwt)
	if status != http.StatusOK || !bytes.Contains(raw, []byte("session_id")) {
		t.Fatalf("session list status=%d body=%s", status, raw)
	}
	// Wrong CSRF and cross-origin are rejected on protected mutations.
	status, _ = tw.request(t, http.MethodPost, "/auth/password", "wrong",
		map[string]any{"current_password": tw.password, "new_password": "A-New-Password-2026!"}, tw.jwt)
	if status != http.StatusForbidden {
		t.Fatalf("wrong CSRF password change status=%d", status)
	}
	req, _ := http.NewRequest(http.MethodPost, tw.server.URL+"/auth/password", stringsReader(`{"current_password":"x","new_password":"y"}`))
	req.Header.Set("Cf-Access-Jwt-Assertion", tw.jwt)
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	resp, err := tw.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin mutation status=%d", resp.StatusCode)
	}
	// Logout revokes the active session, then recovery consumes one code and
	// starts a new forced TOTP enrollment.
	status, _ = tw.request(t, http.MethodPost, "/auth/logout", csrf, nil, tw.jwt)
	if status != http.StatusNoContent {
		t.Fatalf("logout status=%d", status)
	}
	recoveryCSRF := tw.startContext(t)
	status, raw = tw.request(t, http.MethodPost, "/auth/recovery", recoveryCSRF,
		map[string]any{"username": "recovery-admin", "password": tw.password, "recovery_code": recoveryCodes[0]}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("recovery status=%d body=%s", status, raw)
	}
	recoveryStart := decodeMap(t, raw)
	newSecret, _ := recoveryStart["secret"].(string)
	setupCSRF, _ := recoveryStart["csrf_token"].(string)
	if newSecret == "" || setupCSRF == "" {
		t.Fatalf("recovery setup missing: %s", raw)
	}
	setupCode, _ := umcauth.TOTPCode(newSecret, time.Now())
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", setupCSRF, map[string]any{"code": setupCode}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("recovery TOTP confirm status=%d body=%s", status, raw)
	}
	active = decodeMap(t, raw)
	csrf, _ = active["csrf_token"].(string)
	// Logout, then prove the consumed recovery code is single-use.
	status, _ = tw.request(t, http.MethodPost, "/auth/logout", csrf, nil, tw.jwt)
	if status != http.StatusNoContent {
		t.Fatalf("post-recovery logout status=%d", status)
	}
	status, _ = tw.request(t, http.MethodPost, "/auth/recovery", tw.startContext(t),
		map[string]any{"username": "recovery-admin", "password": tw.password, "recovery_code": recoveryCodes[0]}, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("reused recovery code status=%d", status)
	}
	// Restore an active session for the password-change leg.
	preAuth := tw.startContext(t)
	login = tw.loginWithPassword(t, tw.password, preAuth)
	pendingCSRF, _ = login["csrf_token"].(string)
	code2, _ := umcauth.TOTPCode(newSecret, time.Now().Add(30*time.Second))
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pendingCSRF, map[string]any{"code": code2}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("re-login for password change status=%d body=%s", status, raw)
	}
	csrf, _ = decodeMap(t, raw)["csrf_token"].(string)

	// Password change revokes every session and requires a fresh full login.
	newPassword := "B-Another-Password-2026!"
	status, raw = tw.request(t, http.MethodPost, "/auth/password", csrf,
		map[string]any{"current_password": tw.password, "new_password": newPassword}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("password change status=%d body=%s", status, raw)
	}
	status, _ = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("old session survived password change: %d", status)
	}
	preOld := tw.startContext(t)
	status, _ = tw.request(t, http.MethodPost, "/auth/login", preOld,
		map[string]any{"username": "recovery-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("old password accepted: %d", status)
	}
	preNew := tw.startContext(t)
	login = tw.loginWithPassword(t, newPassword, preNew)
	pendingCSRF, _ = login["csrf_token"].(string)
	if pendingCSRF == "" || login["totp_required"] != true {
		t.Fatalf("new password login shape: %v", login)
	}
	nextCode, _ := umcauth.TOTPCode(newSecret, time.Now().Add(-30*time.Second))
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pendingCSRF, map[string]any{"code": nextCode}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("new password TOTP status=%d body=%s", status, raw)
	}
	csrf, _ = decodeMap(t, raw)["csrf_token"].(string)

	// Platform-admin user administration and last-admin protection.
	status, raw = tw.request(t, http.MethodPost, "/web/api/users", csrf,
		map[string]any{"username": "event-admin", "role": "event_admin", "event_ids": []string{eventID}}, tw.jwt)
	if status != http.StatusCreated {
		t.Fatalf("create event admin status=%d body=%s", status, raw)
	}
	createResponse := decodeMap(t, raw)
	created := createResponse["user"].(map[string]any)
	if created["role"] != "event_admin" {
		t.Fatalf("created role=%v", created["role"])
	}
	if _, ok := created["password_hash"]; ok {
		t.Fatalf("user view leaked password hash: %v", created)
	}
	if initial, _ := createResponse["initial_password"].(string); initial == "" {
		t.Fatalf("one-time initial password missing: %s", raw)
	}
	status, _ = tw.request(t, http.MethodPost, "/web/api/users/"+user.UserID+"/disable", csrf, nil, tw.jwt)
	if status != http.StatusConflict {
		t.Fatalf("last platform admin disable status=%d", status)
	}
	status, _ = tw.request(t, http.MethodPost, "/web/api/users", csrf,
		map[string]any{"username": "bad-admin", "role": "platform_admin", "event_ids": []string{eventID}}, tw.jwt)
	if status != http.StatusBadRequest {
		t.Fatalf("web platform_admin expansion status=%d", status)
	}
	// Revoke the current session through the owner session endpoint by its id.
	status, raw = tw.request(t, http.MethodGet, "/auth/sessions", "", nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("sessions status=%d body=%s", status, raw)
	}
	sessions := decodeMap(t, raw)["sessions"].([]any)
	publicID := ""
	for _, item := range sessions {
		entry := item.(map[string]any)
		if entry["current"] == true {
			publicID, _ = entry["session_id"].(string)
			break
		}
	}
	if publicID == "" {
		t.Fatal("no current session")
	}
	status, _ = tw.request(t, http.MethodPost, "/auth/sessions/"+publicID+"/revoke", csrf, nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("revoke own session status=%d", status)
	}
	status, _ = tw.request(t, http.MethodGet, "/api/v1/events", "", nil, tw.jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked session accepted: %d", status)
	}
}

func stringsReader(s string) *bytes.Reader { return bytes.NewReader([]byte(s)) }
