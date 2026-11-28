package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// UM-C authentication persistence. This is the same SQLite store/database as
// B1-B4; there is no second center, database or authorization engine. The web
// auth service resolves a local account into the existing management.Principal
// and calls the existing management.Service/RBAC layer.

const (
	AuthRolePlatformAdmin = "platform_admin"
	AuthRoleEventAdmin    = "event_admin"
	AuthRoleViewer        = "viewer"

	AuthSessionTOTPPending = "totp_pending"
	AuthSessionTOTPSetup   = "totp_setup"
	AuthSessionActive      = "authenticated"
)

var (
	ErrAuthUserUnknown         = errors.New("store: auth user unknown")
	ErrAuthUserExists          = errors.New("store: auth username already exists")
	ErrAuthAlreadyBootstrapped = errors.New("store: auth already bootstrapped")
	ErrAuthLastPlatformAdmin   = errors.New("store: cannot remove the last enabled platform admin")
	ErrAuthTOTPReplayed        = errors.New("store: TOTP counter already consumed")
	ErrAuthRecoveryUsed        = errors.New("store: recovery code already used")
	ErrAuthSessionUnknown      = errors.New("store: auth session unknown")
)

type AuthUser struct {
	UserID          string
	Username        string
	PasswordHash    string
	Role            string
	Enabled         bool
	EventIDs        []string
	TOTPSecret      []byte
	TOTPKeyVersion  int
	TOTPEnrolledAt  *int64
	TOTPLastCounter *int64
	CreatedAt       int64
	UpdatedAt       int64
	DisabledAt      *int64
	LastLoginAt     *int64
}

type AuthSession struct {
	IDHash            string
	PublicID          string
	UserID            string
	State             string
	AccessSubject     string
	AccessIssuer      string
	CSRFHash          string
	PendingSecret     []byte
	PendingCreatedAt  *int64
	CreatedAt         int64
	LastSeenAt        int64
	IdleExpiresAt     int64
	AbsoluteExpiresAt int64
	RevokedAt         *int64
}

type AuthPreauth struct {
	TokenHash     string
	AccessSubject string
	AccessIssuer  string
	CSRFHash      string
	CreatedAt     int64
	ExpiresAt     int64
}

type AuthUserInput struct {
	UserID       string
	Username     string
	PasswordHash string
	Role         string
	EventIDs     []string
	Now          int64
}

func randomAuthID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func validateAuthRole(role string) error {
	switch role {
	case AuthRolePlatformAdmin, AuthRoleEventAdmin, AuthRoleViewer:
		return nil
	default:
		return invalidArgument("role", "must be platform_admin, event_admin or viewer")
	}
}

func validateAuthUsername(username string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(username))
	if len(u) < 3 || len(u) > 64 {
		return "", invalidArgument("username", "must be 3..64 characters")
	}
	for _, r := range u {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return "", invalidArgument("username", "contains unsupported characters")
	}
	return u, nil
}

func eventScopeSet(ids []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !validUUIDLike(id) {
			return nil, invalidArgument("event_ids", "must contain UUIDs")
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

func validUUIDLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func scanAuthUser(scanner interface {
	Scan(...any) error
}) (AuthUser, error) {
	var u AuthUser
	var enabled int
	var keyVersion sql.NullInt64
	var enrolled, lastCounter, disabled, lastLogin sql.NullInt64
	var secret []byte
	if err := scanner.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.Role, &enabled,
		&secret, &keyVersion, &enrolled, &lastCounter, &u.CreatedAt, &u.UpdatedAt, &disabled, &lastLogin); err != nil {
		return AuthUser{}, err
	}
	u.Enabled = enabled != 0
	u.TOTPSecret = secret
	u.TOTPKeyVersion = int(keyVersion.Int64)
	u.TOTPEnrolledAt = nullInt64Pointer(enrolled)
	u.TOTPLastCounter = nullInt64Pointer(lastCounter)
	u.DisabledAt = nullInt64Pointer(disabled)
	u.LastLoginAt = nullInt64Pointer(lastLogin)
	return u, nil
}

const authUserColumns = `user_id,username,password_hash,role,enabled,totp_secret,totp_key_version,
	totp_enrolled_at,totp_last_counter,created_at,updated_at,disabled_at,last_login_at`

func (s *Store) authUserEventIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id FROM umc_user_event_scopes WHERE user_id=? ORDER BY event_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) loadAuthUser(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, where string, args ...any) (AuthUser, error) {
	u, err := scanAuthUser(q.QueryRowContext(ctx, `SELECT `+authUserColumns+` FROM umc_users WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthUser{}, ErrAuthUserUnknown
	}
	if err != nil {
		return AuthUser{}, fmt.Errorf("store: read auth user: %w", err)
	}
	u.EventIDs, err = s.authUserEventIDs(ctx, u.UserID)
	if err != nil {
		return AuthUser{}, fmt.Errorf("store: read auth scopes: %w", err)
	}
	return u, nil
}

// GetAuthUserByUsername returns one account (including disabled) by normalized username.
func (s *Store) GetAuthUserByUsername(ctx context.Context, username string) (AuthUser, error) {
	u, err := validateAuthUsername(username)
	if err != nil {
		return AuthUser{}, err
	}
	return s.loadAuthUser(ctx, s.db, `username=?`, u)
}

func (s *Store) GetAuthUserByID(ctx context.Context, userID string) (AuthUser, error) {
	return s.loadAuthUser(ctx, s.db, `user_id=?`, userID)
}

// BootstrapAuthUser atomically creates the one initial platform_admin. It fails
// if any account already exists; there is no public bootstrap endpoint.
func (s *Store) BootstrapAuthUser(ctx context.Context, username, passwordHash string, now int64) (AuthUser, error) {
	username, err := validateAuthUsername(username)
	if err != nil {
		return AuthUser{}, err
	}
	if strings.TrimSpace(passwordHash) == "" {
		return AuthUser{}, invalidArgument("password", "must not be empty")
	}
	userID, err := randomAuthID("umc-user-")
	if err != nil {
		return AuthUser{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthUser{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM umc_users`).Scan(&count); err != nil {
		return AuthUser{}, err
	}
	if count != 0 {
		return AuthUser{}, ErrAuthAlreadyBootstrapped
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_users(user_id,username,password_hash,role,enabled,created_at,updated_at)
		VALUES(?,?,?,?,1,?,?)`, userID, username, passwordHash, AuthRolePlatformAdmin, now, now); err != nil {
		if isUniqueViolation(err) {
			return AuthUser{}, ErrAuthAlreadyBootstrapped
		}
		return AuthUser{}, fmt.Errorf("store: bootstrap auth user: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "umc_bootstrap_admin", userID, ledgerDetailHash("bootstrap")); err != nil {
		return AuthUser{}, err
	}
	if err := AppendAuditTx(ctx, tx, AuditMeta{Actor: "local-bootstrap", Role: AuthRolePlatformAdmin,
		Action: "umc_user_bootstrap", Target: "user", EventID: userID}, "ok"); err != nil {
		return AuthUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthUser{}, fmt.Errorf("store: commit bootstrap: %w", err)
	}
	return s.GetAuthUserByID(ctx, userID)
}

// CreateAuthUser creates a non-bootstrap account and its event scopes atomically.
func (s *Store) CreateAuthUser(ctx context.Context, input AuthUserInput) (AuthUser, error) {
	username, err := validateAuthUsername(input.Username)
	if err != nil {
		return AuthUser{}, err
	}
	if err := validateAuthRole(input.Role); err != nil {
		return AuthUser{}, err
	}
	if input.Role != AuthRolePlatformAdmin && len(input.EventIDs) == 0 {
		return AuthUser{}, invalidArgument("event_ids", "event_admin/viewer require at least one event")
	}
	scopes, err := eventScopeSet(input.EventIDs)
	if err != nil {
		return AuthUser{}, err
	}
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		userID, err = randomAuthID("umc-user-")
		if err != nil {
			return AuthUser{}, err
		}
	}
	if strings.TrimSpace(input.PasswordHash) == "" {
		return AuthUser{}, invalidArgument("password", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthUser{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_users(user_id,username,password_hash,role,enabled,created_at,updated_at)
		VALUES(?,?,?,?,1,?,?)`, userID, username, input.PasswordHash, input.Role, input.Now, input.Now); err != nil {
		if isUniqueViolation(err) {
			return AuthUser{}, ErrAuthUserExists
		}
		return AuthUser{}, fmt.Errorf("store: create auth user: %w", err)
	}
	for _, eventID := range scopes {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM event_catalog WHERE event_id=?`, eventID).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return AuthUser{}, invalidArgument("event_ids", "event does not exist")
			}
			return AuthUser{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO umc_user_event_scopes(user_id,event_id) VALUES(?,?)`, userID, eventID); err != nil {
			return AuthUser{}, fmt.Errorf("store: create auth scope: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return AuthUser{}, err
	}
	return s.GetAuthUserByID(ctx, userID)
}

func (s *Store) enabledPlatformAdminCount(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, exceptUserID string) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM umc_users WHERE role=? AND enabled=1 AND user_id<>?`,
		AuthRolePlatformAdmin, exceptUserID).Scan(&n)
	return n, err
}

// SetAuthUserEnabled disables/enables an account and revokes all its sessions on
// disable. The last enabled platform_admin cannot be disabled.
func (s *Store) SetAuthUserEnabled(ctx context.Context, userID string, enabled bool, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if !enabled {
		n, err := s.enabledPlatformAdminCount(ctx, tx, userID)
		if err != nil {
			return err
		}
		var role string
		var currentEnabled int
		if err := tx.QueryRowContext(ctx, `SELECT role,enabled FROM umc_users WHERE user_id=?`, userID).Scan(&role, &currentEnabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAuthUserUnknown
			}
			return err
		}
		if role == AuthRolePlatformAdmin && currentEnabled != 0 && n == 0 {
			return ErrAuthLastPlatformAdmin
		}
	}
	var disabled any
	if !enabled {
		disabled = now
	}
	res, err := tx.ExecContext(ctx, `UPDATE umc_users SET enabled=?,disabled_at=?,updated_at=? WHERE user_id=?`,
		boolInt(enabled), disabled, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthUserUnknown
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
			return err
		}
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAuthUserRoleAndScopes atomically replaces role/scopes, revoking all existing
// sessions so a changed permission cannot survive in an old session.
func (s *Store) SetAuthUserRoleAndScopes(ctx context.Context, userID, role string, eventIDs []string, now int64) error {
	if err := validateAuthRole(role); err != nil {
		return err
	}
	if role != AuthRolePlatformAdmin && len(eventIDs) == 0 {
		return invalidArgument("event_ids", "event_admin/viewer require at least one event")
	}
	scopes, err := eventScopeSet(eventIDs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var oldRole string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM umc_users WHERE user_id=?`, userID).Scan(&oldRole); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if oldRole == AuthRolePlatformAdmin && role != AuthRolePlatformAdmin {
		n, err := s.enabledPlatformAdminCount(ctx, tx, userID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrAuthLastPlatformAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET role=?,updated_at=? WHERE user_id=?`, role, now, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_user_event_scopes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, eventID := range scopes {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM event_catalog WHERE event_id=?`, eventID).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return invalidArgument("event_ids", "event does not exist")
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO umc_user_event_scopes(user_id,event_id) VALUES(?,?)`, userID, eventID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAuthUserPassword replaces the password hash and revokes all sessions.
func (s *Store) SetAuthUserPassword(ctx context.Context, userID, passwordHash string, now int64) error {
	if strings.TrimSpace(passwordHash) == "" {
		return invalidArgument("password", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_users SET password_hash=?,updated_at=? WHERE user_id=?`, passwordHash, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthUserUnknown
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAuthUserTOTP stores a new encrypted secret, consumes no counter, revokes all
// sessions, and clears recovery generation state for a fresh enrollment.
func (s *Store) SetAuthUserTOTP(ctx context.Context, userID string, secret []byte, keyVersion int, now int64) error {
	if len(secret) == 0 || keyVersion < 1 {
		return invalidArgument("totp", "invalid sealed secret")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_secret=?,totp_key_version=?,totp_enrolled_at=?,totp_last_counter=NULL,updated_at=? WHERE user_id=?`,
		secret, keyVersion, now, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthUserUnknown
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_totp_counters WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkAuthLogin records a successful login time.
func (s *Store) MarkAuthLogin(ctx context.Context, userID string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE umc_users SET last_login_at=?,updated_at=? WHERE user_id=?`, now, now, userID)
	return err
}

// ConsumeTOTPCounter atomically records a TOTP time-step. A duplicate counter
// (replay/restart/clock rollback) is rejected before any session is issued.
func (s *Store) ConsumeTOTPCounter(ctx context.Context, userID string, counter int64, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_totp_counters(user_id,counter,used_at) VALUES(?,?,?)`,
		userID, counter, now); err != nil {
		if isUniqueViolation(err) {
			return ErrAuthTOTPReplayed
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_last_counter=?,updated_at=? WHERE user_id=?`,
		counter, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// Recovery codes -------------------------------------------------------------

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes []string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if len(hash) != 64 {
			return invalidArgument("recovery_code", "invalid hash")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO umc_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)`,
			userID, hash, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET updated_at=? WHERE user_id=?`, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeRecoveryCode atomically consumes one unused code. A used/unknown code is
// indistinguishable to the caller (ErrAuthRecoveryUsed); the caller should still
// revoke sessions and require TOTP re-enrollment after success.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, hash string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
		now, userID, hash)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrAuthRecoveryUsed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_secret=NULL,totp_enrolled_at=NULL,totp_last_counter=NULL,updated_at=? WHERE user_id=?`,
		now, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CountRecoveryCodes(ctx context.Context, userID string) (total, unused int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN used_at IS NULL THEN 1 ELSE 0 END),0)
		FROM umc_recovery_codes WHERE user_id=?`, userID).Scan(&total, &unused)
	return
}

// Sessions -------------------------------------------------------------------

func (s *Store) CreatePreauth(ctx context.Context, p AuthPreauth) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO umc_preauth(token_hash,access_subject,access_issuer,csrf_hash,created_at,expires_at)
		 VALUES(?,?,?,?,?,?)`, p.TokenHash, p.AccessSubject, p.AccessIssuer, p.CSRFHash, p.CreatedAt, p.ExpiresAt)
	return err
}

func (s *Store) GetPreauth(ctx context.Context, tokenHash string) (AuthPreauth, error) {
	var p AuthPreauth
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,access_subject,access_issuer,csrf_hash,created_at,expires_at FROM umc_preauth WHERE token_hash=?`,
		tokenHash).Scan(&p.TokenHash, &p.AccessSubject, &p.AccessIssuer, &p.CSRFHash, &p.CreatedAt, &p.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthPreauth{}, ErrAuthSessionUnknown
	}
	return p, err
}

func (s *Store) DeletePreauth(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM umc_preauth WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) CreateSession(ctx context.Context, sess AuthSession) error {
	var pending []byte
	var pendingAt any
	if sess.PublicID == "" {
		return invalidArgument("session_public_id", "must not be empty")
	}
	if len(sess.PendingSecret) > 0 {
		pending = sess.PendingSecret
	}
	if sess.PendingCreatedAt != nil {
		pendingAt = *sess.PendingCreatedAt
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.IDHash, sess.PublicID, sess.UserID, sess.State, sess.AccessSubject, sess.AccessIssuer, sess.CSRFHash,
		pending, pendingAt, sess.CreatedAt, sess.LastSeenAt, sess.IdleExpiresAt, sess.AbsoluteExpiresAt)
	return err
}

func (s *Store) GetSession(ctx context.Context, idHash string) (AuthSession, error) {
	var sess AuthSession
	var pending []byte
	var pendingAt, revoked sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,revoked_at
		 FROM umc_sessions WHERE session_id_hash=?`, idHash).
		Scan(&sess.IDHash, &sess.PublicID, &sess.UserID, &sess.State, &sess.AccessSubject, &sess.AccessIssuer, &sess.CSRFHash,
			&pending, &pendingAt, &sess.CreatedAt, &sess.LastSeenAt, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthSession{}, ErrAuthSessionUnknown
	}
	if err != nil {
		return AuthSession{}, err
	}
	sess.PendingSecret = pending
	sess.PendingCreatedAt = nullInt64Pointer(pendingAt)
	sess.RevokedAt = nullInt64Pointer(revoked)
	return sess, nil
}

func (s *Store) TouchSession(ctx context.Context, idHash string, now, idleExpires int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE umc_sessions SET last_seen_at=?,idle_expires_at=? WHERE session_id_hash=? AND revoked_at IS NULL`,
		now, idleExpires, idHash)
	return err
}

func (s *Store) GetSessionByPublicID(ctx context.Context, publicID string) (AuthSession, error) {
	var idHash string
	if err := s.db.QueryRowContext(ctx, `SELECT session_id_hash FROM umc_sessions WHERE public_id=?`, publicID).Scan(&idHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthSession{}, ErrAuthSessionUnknown
		}
		return AuthSession{}, err
	}
	return s.GetSession(ctx, idHash)
}

func (s *Store) RevokeSessionByPublicID(ctx context.Context, publicID string, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE public_id=? AND revoked_at IS NULL`, now, publicID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, idHash string, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE session_id_hash=? AND revoked_at IS NULL`, now, idHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	return nil
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID string, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RotateSession revokes the old session and creates the replacement atomically
// (session-fixation defense after password/TOTP/recovery authentication).
func (s *Store) RotateSession(ctx context.Context, oldHash string, next AuthSession, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE session_id_hash=? AND revoked_at IS NULL`, now, oldHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	var pending []byte
	var pendingAt any
	if len(next.PendingSecret) > 0 {
		pending = next.PendingSecret
	}
	if next.PublicID == "" {
		return invalidArgument("session_public_id", "must not be empty")
	}
	if next.PendingCreatedAt != nil {
		pendingAt = *next.PendingCreatedAt
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.IDHash, next.PublicID, next.UserID, next.State, next.AccessSubject, next.AccessIssuer, next.CSRFHash,
		pending, pendingAt, next.CreatedAt, next.LastSeenAt, next.IdleExpiresAt, next.AbsoluteExpiresAt); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteTOTPLogin atomically consumes the TOTP counter, revokes the pending
// session and creates the authenticated replacement session. A replay or insert
// failure leaves the pending session untouched and never emits a usable cookie.
func (s *Store) CompleteTOTPLogin(ctx context.Context, userID string, counter int64, oldHash string, next AuthSession, now int64) error {
	if next.PublicID == "" {
		return invalidArgument("session_public_id", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_totp_counters(user_id,counter,used_at) VALUES(?,?,?)`,
		userID, counter, now); err != nil {
		if isUniqueViolation(err) {
			return ErrAuthTOTPReplayed
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_last_counter=?,last_login_at=?,updated_at=? WHERE user_id=?`,
		counter, now, now, userID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE session_id_hash=? AND revoked_at IS NULL`, now, oldHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.IDHash, next.PublicID, next.UserID, next.State, next.AccessSubject, next.AccessIssuer, next.CSRFHash,
		nil, nil, next.CreatedAt, next.LastSeenAt, next.IdleExpiresAt, next.AbsoluteExpiresAt); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]AuthSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,revoked_at
		 FROM umc_sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthSession
	for rows.Next() {
		var sess AuthSession
		var revoked sql.NullInt64
		if err := rows.Scan(&sess.IDHash, &sess.PublicID, &sess.UserID, &sess.State, &sess.AccessSubject, &sess.AccessIssuer,
			&sess.CSRFHash, &sess.CreatedAt, &sess.LastSeenAt, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &revoked); err != nil {
			return nil, err
		}
		sess.RevokedAt = nullInt64Pointer(revoked)
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Store) ListAuthUsers(ctx context.Context) ([]AuthUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+authUserColumns+` FROM umc_users ORDER BY username LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthUser
	for rows.Next() {
		u, err := scanAuthUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].EventIDs, err = s.authUserEventIDs(ctx, out[i].UserID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CleanupAuthState deletes expired preauth/session state in bounded batches.
func (s *Store) CleanupAuthState(ctx context.Context, now int64) (map[string]int64, error) {
	deleted := map[string]int64{}
	for _, spec := range []struct {
		name, table, where string
		arg                int64
	}{
		{"preauth", "umc_preauth", "expires_at < ?", now},
		{"sessions", "umc_sessions", "absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?-86400)", now},
		{"totp_counters", "umc_totp_counters", "used_at < ?", now - 180*24*60*60},
	} {
		q := `DELETE FROM ` + spec.table + ` WHERE rowid IN (SELECT rowid FROM ` + spec.table + ` WHERE ` + spec.where + ` LIMIT ?)`
		var n int64
		for {
			var args []any
			if spec.name == "sessions" {
				args = []any{now, now, RetentionBatchRows}
			} else {
				args = []any{spec.arg, RetentionBatchRows}
			}
			res, err := s.db.ExecContext(ctx, q, args...)
			if err != nil {
				return deleted, err
			}
			affected, _ := res.RowsAffected()
			deleted[spec.name] += affected
			n += affected
			if affected < RetentionBatchRows {
				break
			}
		}
		_ = n
	}
	return deleted, nil
}

// RecordAuthAudit writes one closed UM-C authentication/account audit row. The
// caller must never pass passwords, codes, secrets or tokens in target/detail.
// ResetAuthUserForLocalRecovery is the OS-protected local recovery primitive:
// it replaces the password, clears TOTP/recovery state, revokes every session,
// and requires a full TOTP re-enrollment. It does not bypass Cloudflare Access
// for later browser login.
func (s *Store) ResetAuthUserForLocalRecovery(ctx context.Context, userID, passwordHash string, now int64) error {
	if strings.TrimSpace(passwordHash) == "" {
		return invalidArgument("password", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE umc_users SET password_hash=?,totp_secret=NULL,totp_key_version=NULL,totp_enrolled_at=NULL,
		 totp_last_counter=NULL,enabled=1,disabled_at=NULL,updated_at=? WHERE user_id=?`, passwordHash, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthUserUnknown
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_totp_counters WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecordAuthAudit(ctx context.Context, actor, role, action, target, result string, now int64) error {
	return s.RecordAdminAudit(ctx, AuditMeta{Actor: actor, Role: role, Action: action, Target: target}, result)
}

// RecordAuthLedger appends a hash-chained security-ledger entry for a critical
// UM-C security-state change. detailHash must already be a SHA-256 of non-secret
// bounded context (never a password/TOTP/recovery/session token).
func (s *Store) RecordAuthLedger(ctx context.Context, kind, subject, detailHash string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := appendLedgerTx(ctx, tx, now, kind, subject, detailHash); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// AuthMutationMeta lets the Web/CLI caller make a critical UM-C security-state
// change and its audit row/security-ledger entry atomic with the mutation. The
// store helpers append only closed action kinds and hashed non-secret detail.
type AuthMutationMeta struct {
	Audit            AuditMeta
	LedgerKind       string
	LedgerSubject    string
	LedgerDetailHash string
}

type authMutationContextKey struct{}

// WithAuthMutation attaches atomic audit/ledger metadata to a mutation context.
func WithAuthMutation(ctx context.Context, meta AuthMutationMeta) context.Context {
	return context.WithValue(ctx, authMutationContextKey{}, meta)
}

func appendAuthMutationTx(ctx context.Context, tx *sql.Tx, now int64) error {
	meta, ok := ctx.Value(authMutationContextKey{}).(AuthMutationMeta)
	if !ok {
		return nil
	}
	if meta.Audit.Action != "" {
		if err := AppendAuditTx(ctx, tx, meta.Audit, "ok"); err != nil {
			return err
		}
	}
	if meta.LedgerKind != "" {
		if meta.LedgerSubject == "" || meta.LedgerDetailHash == "" {
			return errors.New("store: incomplete auth ledger metadata")
		}
		if _, err := appendLedgerTx(ctx, tx, now, meta.LedgerKind, meta.LedgerSubject, meta.LedgerDetailHash); err != nil {
			return err
		}
	}
	return nil
}
