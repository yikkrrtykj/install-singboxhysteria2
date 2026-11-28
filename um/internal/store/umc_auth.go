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
	ErrAuthStale               = errors.New("store: authentication context is stale")
	ErrAuthSessionLimit        = errors.New("store: active authentication session limit reached")
)

type AuthUser struct {
	UserID             string
	Username           string
	PasswordHash       string
	Role               string
	Enabled            bool
	EventIDs           []string
	TOTPSecret         []byte
	TOTPKeyVersion     int
	TOTPEnrolledAt     *int64
	TOTPLastCounter    *int64
	TOTPFailedAttempts int64
	TOTPLockedUntil    *int64
	AuthEpoch          int64
	CreatedAt          int64
	UpdatedAt          int64
	DisabledAt         *int64
	LastLoginAt        *int64
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
	AuthEpoch         int64
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
	var locked sql.NullInt64
	if err := scanner.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.Role, &enabled,
		&secret, &keyVersion, &enrolled, &lastCounter, &u.TOTPFailedAttempts, &u.CreatedAt, &u.UpdatedAt, &disabled, &lastLogin, &locked, &u.AuthEpoch); err != nil {
		return AuthUser{}, err
	}
	u.Enabled = enabled != 0
	u.TOTPSecret = secret
	u.TOTPKeyVersion = int(keyVersion.Int64)
	u.TOTPEnrolledAt = nullInt64Pointer(enrolled)
	u.TOTPLastCounter = nullInt64Pointer(lastCounter)
	u.TOTPLockedUntil = nullInt64Pointer(locked)
	u.DisabledAt = nullInt64Pointer(disabled)
	u.LastLoginAt = nullInt64Pointer(lastLogin)
	return u, nil
}

const authUserColumns = `user_id,username,password_hash,role,enabled,totp_secret,totp_key_version,
	totp_enrolled_at,totp_last_counter,totp_failed_attempts,created_at,updated_at,disabled_at,last_login_at,totp_locked_until,auth_epoch`

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
	lockClear := ""
	if enabled {
		lockClear = ",totp_failed_attempts=0,totp_locked_until=NULL"
	}
	res, err := tx.ExecContext(ctx, `UPDATE umc_users SET enabled=?,disabled_at=?`+lockClear+`,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`,
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
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET role=?,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`, role, now, userID); err != nil {
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
	res, err := tx.ExecContext(ctx, `UPDATE umc_users SET password_hash=?,totp_failed_attempts=0,totp_locked_until=NULL,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`, passwordHash, now, userID)
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

// SetAuthUserTOTP stores a new encrypted secret, consumes no counter, resets
// TOTP failure/counter state, and revokes all sessions. Recovery-code generation
// is replaced separately by CompleteTOTPSetup or ReplaceRecoveryCodes.
func (s *Store) SetAuthUserTOTP(ctx context.Context, userID string, secret []byte, keyVersion int, now int64) error {
	if len(secret) == 0 || keyVersion < 1 {
		return invalidArgument("totp", "invalid sealed secret")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_secret=?,totp_key_version=?,totp_enrolled_at=?,totp_last_counter=NULL,totp_failed_attempts=0,totp_locked_until=NULL,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`,
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
	var last sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT totp_last_counter FROM umc_users WHERE user_id=?`, userID).Scan(&last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if last.Valid && counter <= last.Int64 {
		return ErrAuthTOTPReplayed
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_totp_counters(user_id,counter,used_at) VALUES(?,?,?)`,
		userID, counter, now); err != nil {
		if isUniqueViolation(err) {
			return ErrAuthTOTPReplayed
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_last_counter=?,totp_failed_attempts=0,totp_locked_until=NULL,updated_at=? WHERE user_id=?`,
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
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_secret=NULL,totp_enrolled_at=NULL,totp_last_counter=NULL,totp_failed_attempts=0,totp_locked_until=NULL,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`,
		now, userID); err != nil {
		return err
	}
	// A successful recovery invalidates the whole recovery generation and resets
	// the old TOTP time-step history; new one-time codes are generated only after
	// the mandated TOTP re-enrollment.
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userEpoch int64
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT auth_epoch,enabled FROM umc_users WHERE user_id=?`, sess.UserID).
		Scan(&userEpoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if enabled == 0 || sess.AuthEpoch != userEpoch {
		return ErrAuthStale
	}
	// Count only currently usable sessions. Pending/setup challenges have a
	// 10-minute TTL even though their absolute row expiry is 12h; otherwise a
	// password holder could open 32 abandoned TOTP challenges and lock the real
	// account out of new logins for up to 12h. Purge this user's expired
	// challenges first so abandoned rows cannot consume the cap.
	const pendingTTL = int64(600)
	pendingCutoff := sess.CreatedAt - pendingTTL
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM umc_sessions WHERE user_id=? AND revoked_at IS NULL AND state IN (?,?) AND created_at<?`,
		sess.UserID, AuthSessionTOTPPending, AuthSessionTOTPSetup, pendingCutoff); err != nil {
		return err
	}
	const usable = `revoked_at IS NULL AND absolute_expires_at>? AND ((state=? AND idle_expires_at>?) OR (state IN (?,?) AND created_at>=?))`
	var activeForUser, activeTotal int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM umc_sessions WHERE user_id=? AND `+usable,
		sess.UserID, sess.CreatedAt, AuthSessionActive, sess.CreatedAt, AuthSessionTOTPPending, AuthSessionTOTPSetup, pendingCutoff).
		Scan(&activeForUser); err != nil {
		return err
	}
	if activeForUser >= 32 {
		return ErrAuthSessionLimit
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM umc_sessions WHERE `+usable,
		sess.CreatedAt, AuthSessionActive, sess.CreatedAt, AuthSessionTOTPPending, AuthSessionTOTPSetup, pendingCutoff).
		Scan(&activeTotal); err != nil {
		return err
	}
	if activeTotal >= 10000 {
		return ErrAuthSessionLimit
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,auth_epoch)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.IDHash, sess.PublicID, sess.UserID, sess.State, sess.AccessSubject, sess.AccessIssuer, sess.CSRFHash,
		pending, pendingAt, sess.CreatedAt, sess.LastSeenAt, sess.IdleExpiresAt, sess.AbsoluteExpiresAt, sess.AuthEpoch); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, nowUnix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetSession(ctx context.Context, idHash string) (AuthSession, error) {
	var sess AuthSession
	var pending []byte
	var pendingAt, revoked sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,revoked_at,auth_epoch
		 FROM umc_sessions WHERE session_id_hash=?`, idHash).
		Scan(&sess.IDHash, &sess.PublicID, &sess.UserID, &sess.State, &sess.AccessSubject, &sess.AccessIssuer, &sess.CSRFHash,
			&pending, &pendingAt, &sess.CreatedAt, &sess.LastSeenAt, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &revoked, &sess.AuthEpoch)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE public_id=? AND revoked_at IS NULL`, now, publicID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeSession(ctx context.Context, idHash string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE session_id_hash=? AND revoked_at IS NULL`, now, idHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID string, now int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID)
	if err != nil {
		return 0, err
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RotateSession revokes the old session and creates the replacement atomically
// (session-fixation defense after password/TOTP/recovery authentication).
func (s *Store) RotateSession(ctx context.Context, oldHash string, next AuthSession, now int64) error {
	if next.PublicID == "" {
		return invalidArgument("session_public_id", "must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var oldUserID string
	var oldEpoch int64
	var oldRevoked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT user_id,auth_epoch,revoked_at FROM umc_sessions WHERE session_id_hash=?`, oldHash).
		Scan(&oldUserID, &oldEpoch, &oldRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthSessionUnknown
		}
		return err
	}
	if oldRevoked.Valid || oldUserID != next.UserID {
		return ErrAuthStale
	}
	var userEpoch int64
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT auth_epoch,enabled FROM umc_users WHERE user_id=?`, next.UserID).
		Scan(&userEpoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if enabled == 0 || oldEpoch != userEpoch || next.AuthEpoch != userEpoch {
		return ErrAuthStale
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE session_id_hash=? AND revoked_at IS NULL`, now, oldHash); err != nil {
		return err
	}
	var pending []byte
	var pendingAt any
	if len(next.PendingSecret) > 0 {
		pending = next.PendingSecret
	}
	if next.PendingCreatedAt != nil {
		pendingAt = *next.PendingCreatedAt
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,auth_epoch)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.IDHash, next.PublicID, next.UserID, next.State, next.AccessSubject, next.AccessIssuer, next.CSRFHash,
		pending, pendingAt, next.CreatedAt, next.LastSeenAt, next.IdleExpiresAt, next.AbsoluteExpiresAt, next.AuthEpoch); err != nil {
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
func (s *Store) CompleteTOTPLogin(ctx context.Context, userID string, expectedEpoch int64, counter int64, oldHash string, next AuthSession, now int64) error {
	if next.PublicID == "" {
		return invalidArgument("session_public_id", "must not be empty")
	}
	if next.AuthEpoch != expectedEpoch {
		return ErrAuthStale
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userEpoch int64
	var enabled int
	var lastCounter sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT auth_epoch,enabled,totp_last_counter FROM umc_users WHERE user_id=?`, userID).
		Scan(&userEpoch, &enabled, &lastCounter); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if enabled == 0 || userEpoch != expectedEpoch {
		return ErrAuthStale
	}
	var pendingUserID, state string
	var pendingEpoch int64
	var pendingRevoked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT user_id,state,auth_epoch,revoked_at FROM umc_sessions WHERE session_id_hash=?`, oldHash).
		Scan(&pendingUserID, &state, &pendingEpoch, &pendingRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthSessionUnknown
		}
		return err
	}
	if pendingRevoked.Valid || pendingUserID != userID || pendingEpoch != expectedEpoch || state != AuthSessionTOTPPending {
		return ErrAuthStale
	}
	// Persistent high-water survives bounded counter-row cleanup and resets only
	// when a new TOTP secret generation is installed.
	if lastCounter.Valid && counter <= lastCounter.Int64 {
		return ErrAuthTOTPReplayed
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_totp_counters(user_id,counter,used_at) VALUES(?,?,?)`,
		userID, counter, now); err != nil {
		if isUniqueViolation(err) {
			return ErrAuthTOTPReplayed
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_last_counter=?,last_login_at=?,totp_failed_attempts=0,totp_locked_until=NULL,updated_at=? WHERE user_id=?`,
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
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,auth_epoch)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.IDHash, next.PublicID, next.UserID, next.State, next.AccessSubject, next.AccessIssuer, next.CSRFHash,
		nil, nil, next.CreatedAt, next.LastSeenAt, next.IdleExpiresAt, next.AbsoluteExpiresAt, expectedEpoch); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]AuthSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,revoked_at,auth_epoch
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
			&sess.CSRFHash, &sess.CreatedAt, &sess.LastSeenAt, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &revoked, &sess.AuthEpoch); err != nil {
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
		 totp_last_counter=NULL,totp_failed_attempts=0,totp_locked_until=NULL,enabled=1,disabled_at=NULL,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`, passwordHash, now, userID)
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

// RecordTOTPFailure atomically increments the per-account TOTP failure count and
// returns the lockout deadline (0 when not locked). This is persistent so a
// process restart does not reset online guessing protection.
func (s *Store) RecordTOTPFailure(ctx context.Context, userID string, now, threshold, lockSeconds int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var attempts int64
	var locked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT totp_failed_attempts,totp_locked_until FROM umc_users WHERE user_id=?`, userID).
		Scan(&attempts, &locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrAuthUserUnknown
		}
		return 0, err
	}
	if locked.Valid && locked.Int64 <= now {
		// A previous lock has expired: start a fresh failure window so the next
		// typo cannot immediately re-lock the account forever.
		attempts = 0
		locked = sql.NullInt64{}
	}
	attempts++
	var until any
	if threshold > 0 && attempts >= threshold {
		v := now + lockSeconds
		until = v
		locked = sql.NullInt64{Int64: v, Valid: true}
	} else if locked.Valid {
		until = locked.Int64
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_users SET totp_failed_attempts=?,totp_locked_until=?,updated_at=? WHERE user_id=?`,
		attempts, until, now, userID); err != nil {
		return 0, err
	}
	if locked.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
			return 0, err
		}
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if locked.Valid {
		return locked.Int64, nil
	}
	return 0, nil
}

// ClearTOTPFailures resets the failure count after a successful TOTP.
func (s *Store) ClearTOTPFailures(ctx context.Context, userID string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE umc_users SET totp_failed_attempts=0,totp_locked_until=NULL,updated_at=? WHERE user_id=?`, now, userID)
	return err
}

// CompleteTOTPSetup atomically consumes the setup counter, stores the new
// encrypted TOTP secret, resets failure state, replaces the recovery-code
// generation, revokes all old sessions and inserts the authenticated session.
// No cookie is issued by the caller until this transaction commits.
func (s *Store) CompleteTOTPSetup(ctx context.Context, userID string, expectedEpoch int64, secret []byte, keyVersion int,
	counter int64, recoveryHashes []string, oldHash string, next AuthSession, now int64) error {
	if len(secret) == 0 || keyVersion < 1 || next.PublicID == "" {
		return invalidArgument("totp_setup", "invalid arguments")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userEpoch int64
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT auth_epoch,enabled FROM umc_users WHERE user_id=?`, userID).
		Scan(&userEpoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if enabled == 0 || userEpoch != expectedEpoch {
		return ErrAuthStale
	}
	// Only the currently pending setup session of the same credential epoch may
	// complete the enrollment. This serializes concurrent setup confirmations and
	// rejects a setup session whose account security state changed concurrently.
	var pendingUserID, pendingState string
	var pendingEpoch int64
	var pendingRevoked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT user_id,state,auth_epoch,revoked_at FROM umc_sessions WHERE session_id_hash=?`, oldHash).
		Scan(&pendingUserID, &pendingState, &pendingEpoch, &pendingRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthSessionUnknown
		}
		return err
	}
	if pendingRevoked.Valid || pendingUserID != userID || pendingEpoch != expectedEpoch || pendingState != AuthSessionTOTPSetup {
		return ErrAuthStale
	}
	res, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE session_id_hash=? AND state=? AND revoked_at IS NULL`,
		now, oldHash, AuthSessionTOTPSetup)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthSessionUnknown
	}
	// A new TOTP secret starts a fresh counter namespace; this happens inside the
	// serialized completion transaction, so it does not open a pre-completion
	// replay window for the old authenticator.
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_totp_counters WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO umc_totp_counters(user_id,counter,used_at) VALUES(?,?,?)`,
		userID, counter, now); err != nil {
		if isUniqueViolation(err) {
			return ErrAuthTOTPReplayed
		}
		return err
	}
	newEpoch := expectedEpoch + 1
	res, err = tx.ExecContext(ctx, `UPDATE umc_users SET totp_secret=?,totp_key_version=?,totp_enrolled_at=?,
		totp_last_counter=?,totp_failed_attempts=0,totp_locked_until=NULL,last_login_at=?,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`,
		secret, keyVersion, now, counter, now, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthUserUnknown
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM umc_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, hash := range recoveryHashes {
		if len(hash) != 64 {
			return invalidArgument("recovery_code", "invalid hash")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO umc_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)`,
			userID, hash, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,auth_epoch)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.IDHash, next.PublicID, next.UserID, next.State, next.AccessSubject, next.AccessIssuer, next.CSRFHash,
		nil, nil, next.CreatedAt, next.LastSeenAt, next.IdleExpiresAt, next.AbsoluteExpiresAt, newEpoch); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeRecoveryCodeAndStartSetup atomically consumes one recovery code,
// invalidates the recovery/TOTP generation, revokes all sessions, advances the
// credential epoch and inserts the restricted TOTP-setup session. If any step
// fails, the code is not consumed and no cookie is issued.
func (s *Store) ConsumeRecoveryCodeAndStartSetup(ctx context.Context, userID string, expectedEpoch int64,
	hash string, sealedSecret []byte, next AuthSession, now int64) error {
	if len(sealedSecret) == 0 || next.PublicID == "" || next.AuthEpoch != expectedEpoch+1 {
		return invalidArgument("recovery_setup", "invalid arguments")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var epoch int64
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT auth_epoch,enabled FROM umc_users WHERE user_id=?`, userID).
		Scan(&epoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthUserUnknown
		}
		return err
	}
	if enabled == 0 || epoch != expectedEpoch {
		return ErrAuthStale
	}
	res, err := tx.ExecContext(ctx, `UPDATE umc_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
		now, userID, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthRecoveryUsed
	}
	res, err = tx.ExecContext(ctx, `UPDATE umc_users SET totp_secret=NULL,totp_enrolled_at=NULL,totp_last_counter=NULL,
		totp_failed_attempts=0,totp_locked_until=NULL,auth_epoch=auth_epoch+1,updated_at=? WHERE user_id=?`, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAuthUserUnknown
	}
	for _, q := range []string{
		`DELETE FROM umc_recovery_codes WHERE user_id=?`,
		`DELETE FROM umc_totp_counters WHERE user_id=?`,
		`UPDATE umc_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`,
	} {
		var execErr error
		if strings.Contains(q, "revoked_at") {
			_, execErr = tx.ExecContext(ctx, q, now, userID)
		} else {
			_, execErr = tx.ExecContext(ctx, q, userID)
		}
		if execErr != nil {
			return execErr
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO umc_sessions(session_id_hash,public_id,user_id,state,access_subject,access_issuer,csrf_hash,pending_secret,pending_created_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,auth_epoch)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.IDHash, next.PublicID, next.UserID, next.State, next.AccessSubject, next.AccessIssuer, next.CSRFHash,
		sealedSecret, now, next.CreatedAt, next.LastSeenAt, next.IdleExpiresAt, next.AbsoluteExpiresAt, next.AuthEpoch); err != nil {
		return err
	}
	if err := appendAuthMutationTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

// Auth metadata and master-key consistency helpers. The sentinel stored in
// umc_meta is ciphertext produced with the master key; it never stores the key.
var ErrAuthMetaNotFound = errors.New("store: auth metadata not found")

func (s *Store) GetAuthMeta(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	if err := s.db.QueryRowContext(ctx, `SELECT meta_value FROM umc_meta WHERE meta_key=?`, key).Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuthMetaNotFound
		}
		return nil, err
	}
	return value, nil
}

func (s *Store) SetAuthMetaIfAbsent(ctx context.Context, key string, value []byte, now int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO umc_meta(meta_key,meta_value,updated_at) VALUES(?,?,?) ON CONFLICT(meta_key) DO NOTHING`,
		key, value, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

type AuthTOTPSecretRow struct {
	UserID     string
	Secret     []byte
	KeyVersion int
}

func (s *Store) ListEncryptedTOTPSecrets(ctx context.Context) ([]AuthTOTPSecretRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id,totp_secret,totp_key_version FROM umc_users WHERE totp_secret IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthTOTPSecretRow
	for rows.Next() {
		var r AuthTOTPSecretRow
		if err := rows.Scan(&r.UserID, &r.Secret, &r.KeyVersion); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CountAuthUsers(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM umc_users`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
