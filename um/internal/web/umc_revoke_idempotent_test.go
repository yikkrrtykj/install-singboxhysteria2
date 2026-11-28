package web_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

// TestUMCAdminSessionRevokeIsIdempotentOnlyAfterProof proves a repeated revoke
// returns success only after the store proves the target row is already revoked;
// the first revoke is audited atomically and the second is not a false revoke.
func TestUMCAdminSessionRevokeIsIdempotentOnlyAfterProof(t *testing.T) {
	tw := newTestWeb(t)
	now := *tw.clock
	hash, _ := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	admin, err := tw.store.BootstrapAuthUser(context.Background(), "revoke-admin", hash, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	eventID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := tw.store.CreateEvent(context.Background(), eventID, "A", now.Unix()); err != nil {
		t.Fatal(err)
	}
	target, err := tw.store.CreateAuthUser(context.Background(), store.AuthUserInput{
		Username: "revoke-target", PasswordHash: hash, Role: store.AuthRoleViewer,
		EventIDs: []string{eventID}, Now: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	targetSession := store.AuthSession{
		IDHash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PublicID: "revoke-target-session", UserID: target.UserID, State: store.AuthSessionActive,
		AccessSubject: "s", AccessIssuer: "i",
		CSRFHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: now.Unix(), LastSeenAt: now.Unix(), IdleExpiresAt: now.Unix() + 600,
		AbsoluteExpiresAt: now.Unix() + 3600, AuthEpoch: target.AuthEpoch,
	}
	if err := tw.store.CreateSession(context.Background(), targetSession); err != nil {
		t.Fatal(err)
	}
	secret, _ := umcauth.NewTOTPSecret()
	sealed, _ := umcauth.Seal(tw.master, []byte(secret), []byte("umc-totp:"+admin.UserID+":v1"))
	if err := tw.store.SetAuthUserTOTP(context.Background(), admin.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pre := tw.startContext(t)
	status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
		map[string]any{"username": "revoke-admin", "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", status, raw)
	}
	pending, _ := decodeMap(t, raw)["csrf_token"].(string)
	code, _ := umcauth.TOTPCode(secret, *tw.clock)
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pending, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP status=%d body=%s", status, raw)
	}
	csrf, _ := decodeMap(t, raw)["csrf_token"].(string)
	path := "/web/api/users/" + target.UserID + "/sessions/" + targetSession.PublicID + "/revoke"
	status, raw = tw.request(t, http.MethodPost, path, csrf, nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("first revoke status=%d body=%s", status, raw)
	}
	status, raw = tw.request(t, http.MethodPost, path, csrf, nil, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("second revoke status=%d body=%s, want idempotent 200", status, raw)
	}
	if already, _ := decodeMap(t, raw)["already_revoked"].(bool); !already {
		t.Fatalf("second revoke body=%s, want already_revoked", raw)
	}
}
