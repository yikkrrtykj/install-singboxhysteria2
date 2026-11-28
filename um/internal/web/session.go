package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

type accessContextKey struct{}

type identity struct {
	User      store.AuthUser
	Session   store.AuthSession
	Principal management.Principal
	Claims    *umcauth.VerifiedToken
}

type identityContextKey struct{}

func identityFromContext(ctx context.Context) (*identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(*identity)
	return id, ok
}

func withIdentity(ctx context.Context, id *identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

func accessFromContext(ctx context.Context) (*umcauth.VerifiedToken, error) {
	claims, ok := ctx.Value(accessContextKey{}).(*umcauth.VerifiedToken)
	if !ok || claims == nil {
		return nil, ErrIdentityMissing
	}
	return claims, nil
}

// SessionAuthenticator is the management.Authenticator bridge. The Web wrapper
// authenticates Access JWT + local server-side session once, caches the trusted
// identity in request context, and the existing B4 handler consumes that exact
// principal. It cannot be used by the local bearer admin listener.
type SessionAuthenticator struct {
	store  *store.Store
	access *umcauth.Verifier
	now    func() time.Time
}

func NewSessionAuthenticator(st *store.Store, access *umcauth.Verifier, now func() time.Time) (*SessionAuthenticator, error) {
	if st == nil || access == nil {
		return nil, errors.New("web: session authenticator requires store and Access verifier")
	}
	if now == nil {
		now = time.Now
	}
	return &SessionAuthenticator{store: st, access: access, now: now}, nil
}

func (a *SessionAuthenticator) Authenticate(r *http.Request) (management.Principal, error) {
	id, ok := identityFromContext(r.Context())
	if !ok || id == nil || id.Principal.Role == "" {
		return management.Principal{}, ErrIdentityMissing
	}
	return id.Principal, nil
}

// authenticate resolves the Access JWT from context plus the HttpOnly session
// cookie into a fresh local account/role/scope. It never trusts client role or
// event headers and always reads the current persisted authorization.
func (h *Handler) authenticate(r *http.Request, allowedStates ...string) (*identity, error) {
	claims, err := accessFromContext(r.Context())
	if err != nil {
		return nil, err
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" || len(cookie.Value) > 512 {
		return nil, ErrIdentityMissing
	}
	hash := umcauth.HashToken(cookie.Value)
	sess, err := h.store.GetSession(r.Context(), hash)
	if err != nil {
		return nil, ErrIdentityMissing
	}
	now := h.now().Unix()
	if sess.RevokedAt != nil || now >= sess.AbsoluteExpiresAt || now >= sess.IdleExpiresAt {
		return nil, ErrIdentityMissing
	}
	if sess.AccessSubject != claims.Claims.Subject || sess.AccessIssuer != claims.Claims.Issuer {
		return nil, ErrIdentityMissing
	}
	stateAllowed := false
	for _, state := range allowedStates {
		if sess.State == state {
			stateAllowed = true
			break
		}
	}
	if !stateAllowed {
		return nil, ErrIdentityMissing
	}
	user, err := h.store.GetAuthUserByID(r.Context(), sess.UserID)
	if err != nil || !user.Enabled {
		return nil, ErrIdentityMissing
	}
	if err := h.store.TouchSession(r.Context(), hash, now, now+int64(h.idle/time.Second)); err != nil {
		return nil, ErrIdentityMissing
	}
	scopes := make(map[string]bool, len(user.EventIDs))
	for _, eventID := range user.EventIDs {
		scopes[eventID] = true
	}
	role := management.Role(user.Role)
	if !role.Valid() {
		return nil, ErrIdentityMissing
	}
	id := &identity{
		User: user, Session: sess, Claims: claims,
		Principal: management.Principal{ID: "user:" + user.Username, Role: role, EventIDs: scopes},
	}
	return id, nil
}

// ErrIdentityMissing is a closed authentication failure.
var ErrIdentityMissing = errors.New("web: authenticated session required")
