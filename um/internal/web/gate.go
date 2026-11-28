package web

import (
	"errors"
	"net/http"
	"sort"
	"sync"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
)

// Per-account authorization gates are the linearization boundary between a Web
// request that was authenticated and a mutation that changes that account's
// sessions, credential epoch, role or event scopes. A management mutation holds
// a read lock for its authenticated principal while the existing B4 management
// service executes; security-state mutations take a write lock on the target
// account. Thus a revocation either completes before a new mutation is
// authorized, or waits until a mutation that already started under the old
// authorization finishes. Locks are per-account, never global, and acquired in
// account-id order to avoid deadlock when administrators mutate each other.
type authLock struct {
	id    string
	write bool
}

type authGateEntry struct {
	mu   sync.RWMutex
	refs int
}

func (h *Handler) lockAuthGates(locks ...authLock) func() {
	// Canonical ordering and duplicate coalescing (a write request wins).
	byID := make(map[string]authLock, len(locks))
	for _, l := range locks {
		if l.id == "" {
			continue
		}
		if existing, ok := byID[l.id]; ok {
			if l.write {
				existing.write = true
			}
			byID[l.id] = existing
			continue
		}
		byID[l.id] = l
	}
	ordered := make([]authLock, 0, len(byID))
	for _, l := range byID {
		ordered = append(ordered, l)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].id < ordered[j].id })

	h.gateMu.Lock()
	if h.gates == nil {
		h.gates = make(map[string]*authGateEntry)
	}
	entries := make([]*authGateEntry, 0, len(ordered))
	for _, l := range ordered {
		entry := h.gates[l.id]
		if entry == nil {
			entry = &authGateEntry{}
			h.gates[l.id] = entry
		}
		entry.refs++
		entries = append(entries, entry)
	}
	h.gateMu.Unlock()

	for i, entry := range entries {
		if ordered[i].write {
			entry.mu.Lock()
		} else {
			entry.mu.RLock()
		}
	}
	return func() {
		for i := len(entries) - 1; i >= 0; i-- {
			if ordered[i].write {
				entries[i].mu.Unlock()
			} else {
				entries[i].mu.RUnlock()
			}
		}
		h.gateMu.Lock()
		for _, l := range ordered {
			entry := h.gates[l.id]
			if entry == nil {
				continue
			}
			entry.refs--
			if entry.refs == 0 {
				delete(h.gates, l.id)
			}
		}
		h.gateMu.Unlock()
	}
}

func (h *Handler) authenticateForMutation(r *http.Request, states ...string) (*identity, func(), error) {
	id, err := h.authenticate(r, states...)
	if err != nil {
		return nil, nil, err
	}
	release := h.lockAuthGates(authLock{id: id.User.UserID, write: true})
	fresh, err := h.authenticate(r, states...)
	if err != nil {
		release()
		return nil, nil, err
	}
	return fresh, release, nil
}

// requireActiveWrite serializes an active-session security mutation with the
// account's revocation/authorization boundary and revalidates session+CSRF after
// acquiring the write gate. The returned release func must be called by defer.
func (h *Handler) requireActiveWrite(w http.ResponseWriter, r *http.Request) (*identity, func(), bool) {
	id, release, err := h.authenticateForMutation(r, store.AuthSessionActive)
	if err != nil {
		if errors.Is(err, ErrAuthUnavailable) {
			h.writeError(w, http.StatusServiceUnavailable, "auth_state_unavailable", "authentication state unavailable; retry")
			return nil, nil, false
		}
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authenticated session required")
		return nil, nil, false
	}
	if err := h.checkCSRFFor(r, id); err != nil {
		release()
		h.auditIdentity(r, id, "csrf_rejected", "session", "denied")
		h.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF validation failed")
		return nil, nil, false
	}
	return id, release, true
}

// requireAdminMutation locks the administrator's authorization read-side and
// the target account write-side after the normal platform_admin check, then
// revalidates the administrator after any wait. This makes role/scope/disable/
// password/session changes linearizable with B4 mutations of the same actor.
func (h *Handler) requireAdminMutation(w http.ResponseWriter, r *http.Request, targetID string) (*identity, func(), bool) {
	actor, ok := h.requirePlatformAdmin(w, r)
	if !ok {
		return nil, nil, false
	}
	release := h.lockAuthGates(authLock{id: actor.User.UserID, write: false}, authLock{id: targetID, write: true})
	fresh, err := h.authenticate(r, store.AuthSessionActive)
	if err != nil {
		release()
		if errors.Is(err, ErrAuthUnavailable) {
			h.writeError(w, http.StatusServiceUnavailable, "auth_state_unavailable", "authentication state unavailable; retry")
			return nil, nil, false
		}
		h.writeError(w, http.StatusUnauthorized, "unauthenticated", "authorization changed; re-authenticate")
		return nil, nil, false
	}
	if fresh.Principal.Role != "platform_admin" {
		release()
		h.writeError(w, http.StatusForbidden, "forbidden", "platform_admin required")
		return nil, nil, false
	}
	return fresh, release, true
}

func (h *Handler) requireAdminActor(w http.ResponseWriter, r *http.Request) (*identity, func(), bool) {
	return h.requireAdminMutation(w, r, "")
}
