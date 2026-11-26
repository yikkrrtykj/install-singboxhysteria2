package store

// UM-B2 center data layer: enrollment identity lifecycle, persisted rotation
// state, per-node configuration, validated telemetry storage, the authenticated
// ingest transaction, and the policy-B retention/archive sweep.
//
// This file extends the B1 foundation without weakening its invariants:
//   - node_boot remains the only authoritative high-water and is never deleted;
//   - every protocol/security state change in this file happens inside the
//     caller's transaction (or a single transaction created here);
//   - payload bytes stored here have already been schema/platform/privacy
//     validated by the center layer; this layer still re-checks sizes/ordering.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
)

// Enrollment token failures are deliberately distinct so the HTTP layer can map
// them to token_invalid/token_expired/token_used/token_scope_mismatch without
// leaking details.
var (
	ErrTokenInvalid       = errors.New("store: enrollment token invalid")
	ErrTokenExpired       = errors.New("store: enrollment token expired")
	ErrTokenUsed          = errors.New("store: enrollment token already used")
	ErrTokenScopeMismatch = errors.New("store: enrollment token scope mismatch")
	ErrNodeRevoked        = errors.New("store: node revoked")
	ErrKeyRevoked         = errors.New("store: key revoked")
	ErrKeyUnknown         = errors.New("store: key unknown")
	ErrNodeUnknown        = errors.New("store: node unknown")
	ErrRotationInProgress = errors.New("store: rotation already in progress")
	ErrRotationExpired    = errors.New("store: rotation expired")
)

// Key states from the frozen rotation contract.
const (
	KeyActive      = "active"
	KeyProvisional = "provisional"
	KeyRevoked     = "revoked"
)

// Node states used by B2.
const (
	NodeActive  = "active"
	NodeRevoked = "revoked"
)

// RotationState values used by the persistent key_rotations table.
const (
	RotationAwaitingProof = "awaiting_proof"
	RotationConfirmed     = "confirmed"
	RotationAborted       = "aborted"
)

// DefaultConfigVersion is the first center-managed config version.
const DefaultConfigVersion = 1

// EnrollTokenInfo is the persisted single-use bootstrap token metadata.
type EnrollTokenInfo struct {
	TokenHash string
	EventID   string
	NodeClass string
	ExpiresAt int64
	UsedAt    *int64
	CreatedAt int64
}

// EnrolledIdentity is returned once enrollment has committed.
type EnrolledIdentity struct {
	NodeID         string
	EventID        string
	NodeClass      string
	KeyID          string
	ConfigVersion  int
	CadenceSeconds int
	DeviceSalt     string
}

// TokenHash returns the lowercase hex SHA-256 used as the persisted enroll token
// lookup key. The plaintext token is never stored.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewEnrollToken returns a random 32-byte base64url enrollment token and its
// persisted hash. The plaintext is shown once to the admin; the center stores
// only the hash.
func NewEnrollToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("store: generate enrollment token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, TokenHash(token), nil
}

// CreateEnrollToken stores a one-time token hash with explicit event/class scope.
func (s *Store) CreateEnrollToken(ctx context.Context, tokenHash, eventID, nodeClass string, expiresAt, now int64) error {
	if strings.TrimSpace(tokenHash) == "" {
		return invalidArgument("token_hash", "must not be empty")
	}
	if strings.TrimSpace(eventID) == "" {
		return invalidArgument("event_id", "must not be empty")
	}
	if nodeClass != NodeClassLinuxVPS && nodeClass != NodeClassWindowsTerminal {
		return invalidArgument("node_class", "must be linux_vps or windows_terminal")
	}
	if expiresAt <= now {
		return invalidArgument("expires_at", "must be in the future")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin enrollment token: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockCapacity(ctx, tx); err != nil {
		return err
	}
	if _, err := ensureEventActiveTx(ctx, tx, eventID, now); err != nil {
		return err
	}
	if err := checkNodeQuotaTx(ctx, tx, eventID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO enroll_tokens(token_hash,event_id,node_class,expires_at,used_at,created_at)
		 VALUES(?,?,?,?,NULL,?)`,
		tokenHash, eventID, nodeClass, expiresAt, now); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: token hash collision", ErrAlreadyExists)
		}
		return fmt.Errorf("store: create enrollment token: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "enroll_token_created", eventID, ledgerDetailHash(tokenHash+"|"+nodeClass)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit enrollment token: %w", err)
	}
	return nil
}

// Enroll consumes a one-time token and creates node+key+config in ONE transaction;
// the node is active immediately when the transaction commits.
func (s *Store) Enroll(ctx context.Context, tokenHash, nodeClass, hostOS, publicKey string, now int64) (EnrolledIdentity, error) {
	if strings.TrimSpace(tokenHash) == "" {
		return EnrolledIdentity{}, invalidArgument("token", "must not be empty")
	}
	if nodeClass != NodeClassLinuxVPS && nodeClass != NodeClassWindowsTerminal {
		return EnrolledIdentity{}, invalidArgument("node_class", "must be linux_vps or windows_terminal")
	}
	if !hostMatchesClass(nodeClass, hostOS) {
		return EnrolledIdentity{}, ErrTokenScopeMismatch
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(pubRaw) != 32 {
		return EnrolledIdentity{}, invalidArgument("public_key", "must be base64url 32 bytes")
	}
	nodeID, err := randomUUIDv4()
	if err != nil {
		return EnrolledIdentity{}, err
	}
	keyID, err := randomKeyID()
	if err != nil {
		return EnrolledIdentity{}, err
	}
	deviceSalt, err := randomSalt()
	if err != nil {
		return EnrolledIdentity{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockCapacity(ctx, tx); err != nil {
		return EnrolledIdentity{}, err
	}

	var tokenEvent, tokenClass string
	var expiresAt int64
	var usedAt sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT event_id,node_class,expires_at,used_at FROM enroll_tokens WHERE token_hash=?`, tokenHash).
		Scan(&tokenEvent, &tokenClass, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrolledIdentity{}, ErrTokenInvalid
	}
	if err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: read enrollment token: %w", err)
	}
	if usedAt.Valid {
		return EnrolledIdentity{}, ErrTokenUsed
	}
	if expiresAt <= now {
		return EnrolledIdentity{}, ErrTokenExpired
	}
	if tokenClass != nodeClass || tokenEvent == "" {
		return EnrolledIdentity{}, ErrTokenScopeMismatch
	}
	if _, err := ensureEventActiveTx(ctx, tx, tokenEvent, now); err != nil {
		return EnrolledIdentity{}, err
	}
	if err := checkNodeQuotaTx(ctx, tx, tokenEvent); err != nil {
		return EnrolledIdentity{}, err
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE enroll_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?`,
		now, tokenHash, now)
	if err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: consume enrollment token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: consume enrollment token: %w", err)
	}
	if affected != 1 {
		return EnrolledIdentity{}, ErrTokenUsed
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO nodes(node_id,event_id,node_class,state,created_at,last_seen_at)
		 VALUES(?,?,?,?,?,NULL)`, nodeID, tokenEvent, nodeClass, NodeActive, now); err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: create enrolled node: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO node_keys(key_id,node_id,public_key,state,created_at,activated_at,revoked_at)
		 VALUES(?,?,?,?,?,?,NULL)`, keyID, nodeID, publicKey, KeyActive, now, now); err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: create enrolled key: %w", err)
	}
	cfg, err := defaultNodeConfig(nodeID, tokenEvent, nodeClass, deviceSalt, now)
	if err != nil {
		return EnrolledIdentity{}, err
	}
	if err := insertNodeConfig(ctx, tx, cfg); err != nil {
		return EnrolledIdentity{}, err
	}
	if _, err := appendLedgerTx(ctx, tx, now, "node_enrolled", nodeID,
		ledgerDetailHash(tokenEvent+"|"+nodeClass+"|"+keyID)); err != nil {
		return EnrolledIdentity{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrolledIdentity{}, fmt.Errorf("store: commit enrollment: %w", err)
	}
	return EnrolledIdentity{
		NodeID: nodeID, EventID: tokenEvent, NodeClass: nodeClass, KeyID: keyID,
		ConfigVersion: cfg.ConfigVersion, CadenceSeconds: cfg.CadenceSeconds,
		DeviceSalt: cfg.DeviceSalt,
	}, nil
}

// TokenInfo returns a token's metadata for admin/diagnostic use. Missing tokens
// are ErrTokenInvalid.
func (s *Store) TokenInfo(ctx context.Context, tokenHash string) (EnrollTokenInfo, error) {
	var info EnrollTokenInfo
	var used sql.NullInt64
	var created sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,event_id,node_class,expires_at,used_at,created_at FROM enroll_tokens WHERE token_hash=?`, tokenHash).
		Scan(&info.TokenHash, &info.EventID, &info.NodeClass, &info.ExpiresAt, &used, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollTokenInfo{}, ErrTokenInvalid
	}
	if err != nil {
		return EnrollTokenInfo{}, fmt.Errorf("store: read enrollment token: %w", err)
	}
	if used.Valid {
		v := used.Int64
		info.UsedAt = &v
	}
	if created.Valid {
		info.CreatedAt = created.Int64
	}
	return info, nil
}

// NodeKey is a persisted identity key.
type NodeKey struct {
	KeyID       string
	NodeID      string
	PublicKey   string
	State       string
	CreatedAt   *int64
	ActivatedAt *int64
	RevokedAt   *int64
}

// NodeTx loads one node inside the caller's transaction.
func (t *Tx) NodeTx(ctx context.Context, nodeID string) (Node, error) {
	var node Node
	var lastSeen sql.NullInt64
	err := t.tx.QueryRowContext(ctx,
		`SELECT node_id,event_id,node_class,state,created_at,last_seen_at FROM nodes WHERE node_id=?`, nodeID).
		Scan(&node.NodeID, &node.EventID, &node.NodeClass, &node.State, &node.CreatedAt, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNodeUnknown
	}
	if err != nil {
		return Node{}, fmt.Errorf("store: read node: %w", err)
	}
	if lastSeen.Valid {
		v := lastSeen.Int64
		node.LastSeenAt = &v
	}
	return node, nil
}

// KeyTx loads one key inside the caller's transaction.
func (t *Tx) KeyTx(ctx context.Context, nodeID, keyID string) (NodeKey, error) {
	var key NodeKey
	var created, activated, revoked sql.NullInt64
	err := t.tx.QueryRowContext(ctx,
		`SELECT key_id,node_id,public_key,state,created_at,activated_at,revoked_at
		 FROM node_keys WHERE key_id=? AND node_id=?`, keyID, nodeID).
		Scan(&key.KeyID, &key.NodeID, &key.PublicKey, &key.State, &created, &activated, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeKey{}, ErrKeyUnknown
	}
	if err != nil {
		return NodeKey{}, fmt.Errorf("store: read node key: %w", err)
	}
	if created.Valid {
		v := created.Int64
		key.CreatedAt = &v
	}
	if activated.Valid {
		v := activated.Int64
		key.ActivatedAt = &v
	}
	if revoked.Valid {
		v := revoked.Int64
		key.RevokedAt = &v
	}
	return key, nil
}

// RotationRecord is the persisted rotation intent.
type RotationRecord struct {
	NodeID       string
	OldKeyID     string
	NewKeyID     string
	NewPublicKey string
	Nonce        string
	BodySHA256   string
	State        string
	ExpiresAt    int64
	CreatedAt    int64
	ConfirmedAt  *int64
	ResponseJSON string
}

// SetIngestHookForTest installs a test-only fault hook; production code must not
// call it.
func (s *Store) SetIngestHookForTest(hook func(string) error) { s.ingestHook = hook }

// GetKey loads one key outside an explicit transaction (used by the center to
// verify a signature before opening the authenticated ingest transaction; the
// key state is re-checked inside that transaction).
func (s *Store) GetKey(ctx context.Context, nodeID, keyID string) (NodeKey, error) {
	var key NodeKey
	var created, activated, revoked sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT key_id,node_id,public_key,state,created_at,activated_at,revoked_at
		 FROM node_keys WHERE key_id=? AND node_id=?`, keyID, nodeID).
		Scan(&key.KeyID, &key.NodeID, &key.PublicKey, &key.State, &created, &activated, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeKey{}, ErrKeyUnknown
	}
	if err != nil {
		return NodeKey{}, fmt.Errorf("store: read node key: %w", err)
	}
	if created.Valid {
		v := created.Int64
		key.CreatedAt = &v
	}
	if activated.Valid {
		v := activated.Int64
		key.ActivatedAt = &v
	}
	if revoked.Valid {
		v := revoked.Int64
		key.RevokedAt = &v
	}
	return key, nil
}

// RotationByNewKeyTx finds an awaiting rotation whose provisional key is keyID.
func (t *Tx) RotationByNewKeyTx(ctx context.Context, nodeID, keyID string) (RotationRecord, bool, error) {
	var r RotationRecord
	var expires, created, confirmed sql.NullInt64
	var newPub, response sql.NullString
	err := t.tx.QueryRowContext(ctx,
		`SELECT node_id,old_key_id,new_key_id,new_public_key,nonce,body_sha256,state,expires_at,created_at,confirmed_at,response_json
		 FROM key_rotations WHERE node_id=? AND new_key_id=? AND state=? ORDER BY created_at DESC LIMIT 1`,
		nodeID, keyID, RotationAwaitingProof).
		Scan(&r.NodeID, &r.OldKeyID, &r.NewKeyID, &newPub, &r.Nonce, &r.BodySHA256, &r.State, &expires, &created, &confirmed, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return RotationRecord{}, false, nil
	}
	if err != nil {
		return RotationRecord{}, false, fmt.Errorf("store: read pending rotation by key: %w", err)
	}
	r.NewPublicKey = newPub.String
	r.ResponseJSON = response.String
	if expires.Valid {
		r.ExpiresAt = expires.Int64
	}
	if created.Valid {
		r.CreatedAt = created.Int64
	}
	if confirmed.Valid {
		v := confirmed.Int64
		r.ConfirmedAt = &v
	}
	return r, true, nil
}

// PendingRotationTx returns the single awaiting_proof rotation for a node.
func (t *Tx) PendingRotationTx(ctx context.Context, nodeID string) (RotationRecord, bool, error) {
	var r RotationRecord
	var expires, created, confirmed sql.NullInt64
	var newPub, response sql.NullString
	err := t.tx.QueryRowContext(ctx,
		`SELECT node_id,old_key_id,new_key_id,new_public_key,nonce,body_sha256,state,expires_at,created_at,confirmed_at,response_json
		 FROM key_rotations WHERE node_id=? AND state=? ORDER BY created_at DESC LIMIT 1`,
		nodeID, RotationAwaitingProof).
		Scan(&r.NodeID, &r.OldKeyID, &r.NewKeyID, &newPub, &r.Nonce, &r.BodySHA256, &r.State, &expires, &created, &confirmed, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return RotationRecord{}, false, nil
	}
	if err != nil {
		return RotationRecord{}, false, fmt.Errorf("store: read pending rotation: %w", err)
	}
	r.NewPublicKey = newPub.String
	r.ResponseJSON = response.String
	if expires.Valid {
		r.ExpiresAt = expires.Int64
	}
	if created.Valid {
		r.CreatedAt = created.Int64
	}
	if confirmed.Valid {
		v := confirmed.Int64
		r.ConfirmedAt = &v
	}
	return r, true, nil
}

// AbortRotationTx immediately aborts one awaiting_proof rotation: only the
// provisional key is revoked; the old key remains active. Used for expired
// intents that must not block a new legal rotation until the hourly job.
func (t *Tx) AbortRotationTx(ctx context.Context, nodeID, nonce string, now int64) error {
	r, ok, err := t.RotationTx(ctx, nodeID, nonce)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if r.State != RotationAwaitingProof {
		return fmt.Errorf("%w: %s", ErrRotationState, r.State)
	}
	if _, err := t.tx.ExecContext(ctx,
		`UPDATE node_keys SET state=?, revoked_at=? WHERE node_id=? AND key_id=? AND state=?`,
		KeyRevoked, now, nodeID, r.NewKeyID, KeyProvisional); err != nil {
		return fmt.Errorf("store: abort provisional key: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		`UPDATE key_rotations SET state=? WHERE node_id=? AND nonce=?`,
		RotationAborted, nodeID, nonce); err != nil {
		return fmt.Errorf("store: abort rotation: %w", err)
	}
	if _, err := appendLedgerTx(ctx, t.tx, now, "rotation_aborted", nodeID, ledgerDetailHash(nonce+"|"+r.NewKeyID)); err != nil {
		return err
	}
	return nil
}

// AppendLedger appends a security-ledger entry inside the caller's transaction.
// It must be used instead of Store.AppendLedger while a transaction is open (the
// store has one SQLite writer connection).
func (t *Tx) AppendLedger(ctx context.Context, at int64, kind, subject, detailSHA string) error {
	_, err := appendLedgerTx(ctx, t.tx, at, kind, subject, detailSHA)
	return err
}

// RotationTx loads a rotation by (node, nonce).
func (t *Tx) RotationTx(ctx context.Context, nodeID, nonce string) (RotationRecord, bool, error) {
	var r RotationRecord
	var expires, created sql.NullInt64
	var confirmed sql.NullInt64
	var newPub, response sql.NullString
	err := t.tx.QueryRowContext(ctx,
		`SELECT node_id,old_key_id,new_key_id,new_public_key,nonce,body_sha256,state,expires_at,created_at,confirmed_at,response_json
		 FROM key_rotations WHERE node_id=? AND nonce=?`, nodeID, nonce).
		Scan(&r.NodeID, &r.OldKeyID, &r.NewKeyID, &newPub, &r.Nonce, &r.BodySHA256, &r.State, &expires, &created, &confirmed, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return RotationRecord{}, false, nil
	}
	if err != nil {
		return RotationRecord{}, false, fmt.Errorf("store: read rotation: %w", err)
	}
	r.NewPublicKey = newPub.String
	r.ResponseJSON = response.String
	if expires.Valid {
		r.ExpiresAt = expires.Int64
	}
	if created.Valid {
		r.CreatedAt = created.Int64
	}
	if confirmed.Valid {
		v := confirmed.Int64
		r.ConfirmedAt = &v
	}
	return r, true, nil
}

// CreateRotationTx persists a new awaiting_proof rotation and makes the new key
// provisional in the same transaction.
func (t *Tx) CreateRotationTx(ctx context.Context, r RotationRecord, newPublicKey string) error {
	keyID, err := randomKeyID()
	if err != nil {
		return err
	}
	r.NewKeyID = keyID
	r.NewPublicKey = newPublicKey
	r.State = RotationAwaitingProof
	if r.CreatedAt == 0 {
		r.CreatedAt = nowUnix()
	}
	if r.ExpiresAt == 0 {
		r.ExpiresAt = r.CreatedAt + 300
	}
	if _, err := t.tx.ExecContext(ctx,
		`INSERT INTO node_keys(key_id,node_id,public_key,state,created_at,activated_at,revoked_at)
		 VALUES(?,?,?,?,?,NULL,NULL)`, keyID, r.NodeID, newPublicKey, KeyProvisional, r.CreatedAt); err != nil {
		return fmt.Errorf("store: create provisional key: %w", err)
	}
	response := fmt.Sprintf(`{"v":1,"node_id":%q,"previous_key_id":%q,"new_key_id":%q,"config_version":1,"server_time":%d}`,
		r.NodeID, r.OldKeyID, keyID, r.CreatedAt)
	if _, err := t.tx.ExecContext(ctx,
		`INSERT INTO key_rotations(node_id,old_key_id,new_key_id,nonce,body_sha256,state,expires_at,created_at,new_public_key,response_json,confirmed_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,NULL)`,
		r.NodeID, r.OldKeyID, keyID, r.Nonce, r.BodySHA256, RotationAwaitingProof, r.ExpiresAt, r.CreatedAt, newPublicKey, response); err != nil {
		if isUniqueViolation(err) {
			return ErrRotationInProgress
		}
		return fmt.Errorf("store: create rotation: %w", err)
	}
	if _, err := appendLedgerTx(ctx, t.tx, r.CreatedAt, "rotation_started", r.NodeID, ledgerDetailHash(r.Nonce+"|"+keyID)); err != nil {
		return err
	}
	return nil
}

// ConfirmRotationTx activates the provisional key, revokes the old key, and marks
// the rotation confirmed in the caller's authenticated transaction.
func (t *Tx) ConfirmRotationTx(ctx context.Context, nodeID, nonce string, now int64) (RotationRecord, error) {
	r, ok, err := t.RotationTx(ctx, nodeID, nonce)
	if err != nil {
		return RotationRecord{}, err
	}
	if !ok {
		return RotationRecord{}, ErrKeyUnknown
	}
	if r.State != RotationAwaitingProof {
		// Never return a record that a caller could mistake for a successful
		// confirmation. Confirmed/aborted/unknown states are typed errors.
		return RotationRecord{}, fmt.Errorf("%w: %s", ErrRotationState, r.State)
	}
	if r.ExpiresAt > 0 && now > r.ExpiresAt {
		return RotationRecord{}, ErrRotationExpired
	}
	if _, err := t.tx.ExecContext(ctx,
		`UPDATE node_keys SET state=?, activated_at=? WHERE key_id=? AND node_id=?`,
		KeyActive, now, r.NewKeyID, nodeID); err != nil {
		return RotationRecord{}, fmt.Errorf("store: activate rotation key: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		`UPDATE node_keys SET state=?, revoked_at=? WHERE key_id=? AND node_id=?`,
		KeyRevoked, now, r.OldKeyID, nodeID); err != nil {
		return RotationRecord{}, fmt.Errorf("store: revoke old rotation key: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		`UPDATE key_rotations SET state=?, confirmed_at=? WHERE node_id=? AND nonce=?`,
		RotationConfirmed, now, nodeID, nonce); err != nil {
		return RotationRecord{}, fmt.Errorf("store: confirm rotation: %w", err)
	}
	r.State = RotationConfirmed
	r.ConfirmedAt = &now
	if _, err := appendLedgerTx(ctx, t.tx, now, "rotation_confirmed", nodeID, ledgerDetailHash(nonce+"|"+r.NewKeyID)); err != nil {
		return RotationRecord{}, err
	}
	return r, nil
}

// AbortExpiredRotations aborts awaiting_proof intents whose timer expired and
// revokes only the provisional key; the old key is never revoked by a timer.
func (s *Store) AbortExpiredRotations(ctx context.Context, now int64) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin rotation abort: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx,
		`SELECT node_id,new_key_id,nonce FROM key_rotations WHERE state=? AND expires_at<=?`,
		RotationAwaitingProof, now)
	if err != nil {
		return 0, fmt.Errorf("store: list expired rotations: %w", err)
	}
	var expired []struct{ node, key, nonce string }
	for rows.Next() {
		var e struct{ node, key, nonce string }
		if err := rows.Scan(&e.node, &e.key, &e.nonce); err != nil {
			rows.Close()
			return 0, err
		}
		expired = append(expired, e)
	}
	rows.Close()
	for _, e := range expired {
		if _, err := tx.ExecContext(ctx,
			`UPDATE node_keys SET state=?, revoked_at=? WHERE key_id=? AND node_id=?`,
			KeyRevoked, now, e.key, e.node); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE key_rotations SET state=? WHERE node_id=? AND nonce=?`,
			RotationAborted, e.node, e.nonce); err != nil {
			return 0, err
		}
		if _, err := appendLedgerTx(ctx, tx, now, "rotation_aborted", e.node,
			ledgerDetailHash(e.nonce)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit rotation abort: %w", err)
	}
	return len(expired), nil
}

// RevokeNode revokes a node and all its keys in one transaction; pending
// rotations are aborted. This is the admin action (management API is B4).
func (s *Store) RevokeNode(ctx context.Context, nodeID string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin revoke node: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE nodes SET state=?, retired_at=? WHERE node_id=?`, NodeRevoked, now, nodeID)
	if err != nil {
		return fmt.Errorf("store: revoke node: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return ErrNodeUnknown
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE node_keys SET state=?, revoked_at=? WHERE node_id=? AND state<>?`,
		KeyRevoked, now, nodeID, KeyRevoked); err != nil {
		return fmt.Errorf("store: revoke node keys: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE key_rotations SET state=? WHERE node_id=? AND state=?`,
		RotationAborted, nodeID, RotationAwaitingProof); err != nil {
		return fmt.Errorf("store: abort node rotations: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "node_revoked", nodeID, ledgerDetailHash("admin")); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeKey revokes a single key; the node identity remains.
func (s *Store) RevokeKey(ctx context.Context, nodeID, keyID string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin revoke key: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE node_keys SET state=?, revoked_at=? WHERE node_id=? AND key_id=? AND state<>?`,
		KeyRevoked, now, nodeID, keyID, KeyRevoked)
	if err != nil {
		return fmt.Errorf("store: revoke key: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return ErrKeyUnknown
	}
	// Revoke the other provisional key of any rotation involving this key: both
	// directions are invalid once either side is revoked.
	if _, err := tx.ExecContext(ctx,
		`UPDATE node_keys SET state=?, revoked_at=?
		 WHERE node_id=? AND state=? AND key_id IN (
		   SELECT new_key_id FROM key_rotations WHERE node_id=? AND old_key_id=?
		   UNION SELECT old_key_id FROM key_rotations WHERE node_id=? AND new_key_id=?
		 )`, KeyRevoked, now, nodeID, KeyProvisional, nodeID, keyID, nodeID, keyID); err != nil {
		return fmt.Errorf("store: revoke related provisional keys: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE key_rotations SET state=? WHERE node_id=? AND (old_key_id=? OR new_key_id=?) AND state=?`,
		RotationAborted, nodeID, keyID, keyID, RotationAwaitingProof); err != nil {
		return fmt.Errorf("store: abort key rotation: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "key_revoked", nodeID, ledgerDetailHash(keyID)); err != nil {
		return err
	}
	return tx.Commit()
}

// NodeConfig is the center-managed per-node configuration response source.
type NodeConfig struct {
	NodeID              string
	EventID             string
	ConfigVersion       int
	CadenceSeconds      int
	Sources             map[string]bool
	ExpectedInboundTags []InboundTag
	DeviceSalt          string
	UpdatedAt           int64
}

// InboundTag is one expected inbound allowlist entry.
type InboundTag struct {
	InboundTag string `json:"inbound_tag"`
	Kind       string `json:"kind"`
}

func defaultNodeConfig(nodeID, eventID, nodeClass, salt string, now int64) (NodeConfig, error) {
	sources := map[string]bool{
		"system": false, "services": false, "singbox_api": false,
		"mihomo_api": false, "terminal": false, "events": false,
	}
	tags := []InboundTag{}
	if nodeClass == NodeClassLinuxVPS {
		// Fail-closed defaults: no collection source enabled; a Linux node still
		// needs at least one expected inbound tag for future service telemetry.
		tags = []InboundTag{
			{InboundTag: "vless-in", Kind: "reality"},
			{InboundTag: "hy2-in", Kind: "hysteria2"},
		}
	}
	return NodeConfig{
		NodeID: nodeID, EventID: eventID, ConfigVersion: DefaultConfigVersion,
		CadenceSeconds: 60, Sources: sources, ExpectedInboundTags: tags,
		DeviceSalt: salt, UpdatedAt: now,
	}, nil
}

func insertNodeConfig(ctx context.Context, q execQuerier, cfg NodeConfig) error {
	src, err := json.Marshal(cfg.Sources)
	if err != nil {
		return fmt.Errorf("store: encode config sources: %w", err)
	}
	tags, err := json.Marshal(cfg.ExpectedInboundTags)
	if err != nil {
		return fmt.Errorf("store: encode expected inbound tags: %w", err)
	}
	if _, err := q.ExecContext(ctx,
		`INSERT INTO node_configs(node_id,event_id,config_version,cadence_seconds,sources_json,expected_inbound_tags_json,device_salt,updated_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		cfg.NodeID, cfg.EventID, cfg.ConfigVersion, cfg.CadenceSeconds, string(src), string(tags), cfg.DeviceSalt, cfg.UpdatedAt); err != nil {
		return fmt.Errorf("store: insert node config: %w", err)
	}
	return nil
}

// ConfigTx loads one node config inside the caller's transaction.
func (t *Tx) ConfigTx(ctx context.Context, nodeID string) (NodeConfig, error) {
	var cfg NodeConfig
	var src, tags string
	err := t.tx.QueryRowContext(ctx,
		`SELECT node_id,event_id,config_version,cadence_seconds,sources_json,expected_inbound_tags_json,device_salt,updated_at
		 FROM node_configs WHERE node_id=?`, nodeID).
		Scan(&cfg.NodeID, &cfg.EventID, &cfg.ConfigVersion, &cfg.CadenceSeconds, &src, &tags, &cfg.DeviceSalt, &cfg.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeConfig{}, ErrNotFound
	}
	if err != nil {
		return NodeConfig{}, fmt.Errorf("store: read node config: %w", err)
	}
	if err := json.Unmarshal([]byte(src), &cfg.Sources); err != nil {
		return NodeConfig{}, fmt.Errorf("store: decode config sources: %w", err)
	}
	if err := json.Unmarshal([]byte(tags), &cfg.ExpectedInboundTags); err != nil {
		return NodeConfig{}, fmt.Errorf("store: decode expected tags: %w", err)
	}
	return cfg, nil
}

// GetNodeConfig loads the config outside an explicit transaction.
func (s *Store) GetNodeConfig(ctx context.Context, nodeID string) (NodeConfig, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NodeConfig{}, err
	}
	defer func() { _ = tx.Rollback() }()
	return (&Tx{tx: tx}).ConfigTx(ctx, nodeID)
}

// UpdateNodeConfig applies an admin config update and increments config_version.
// The admin/config management API is B4; B2 exposes the store primitive and uses
// it for test setup.
func (s *Store) UpdateNodeConfig(ctx context.Context, nodeID string, sources map[string]bool, tags []InboundTag, cadence int, now int64) (NodeConfig, error) {
	if cadence < 30 || cadence > 300 {
		return NodeConfig{}, invalidArgument("cadence_seconds", "must be in [30,300]")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NodeConfig{}, err
	}
	defer func() { _ = tx.Rollback() }()
	t := &Tx{tx: tx}
	node, err := t.NodeTx(ctx, nodeID)
	if err != nil {
		return NodeConfig{}, err
	}
	cfg, err := t.ConfigTx(ctx, nodeID)
	if err != nil {
		return NodeConfig{}, err
	}
	if sources == nil {
		sources = cfg.Sources
	}
	if tags == nil {
		tags = cfg.ExpectedInboundTags
	}
	if err := validateConfigForClass(node.NodeClass, sources, tags, cadence, cfg.ConfigVersion+1); err != nil {
		return NodeConfig{}, err
	}
	cfg.Sources = sources
	cfg.ExpectedInboundTags = tags
	cfg.CadenceSeconds = cadence
	cfg.ConfigVersion++
	cfg.UpdatedAt = now
	src, _ := json.Marshal(cfg.Sources)
	tagsJSON, _ := json.Marshal(cfg.ExpectedInboundTags)
	if _, err := tx.ExecContext(ctx,
		`UPDATE node_configs SET config_version=?,cadence_seconds=?,sources_json=?,expected_inbound_tags_json=?,updated_at=? WHERE node_id=?`,
		cfg.ConfigVersion, cfg.CadenceSeconds, string(src), string(tagsJSON), now, nodeID); err != nil {
		return NodeConfig{}, fmt.Errorf("store: update node config: %w", err)
	}
	if _, err := appendLedgerTx(ctx, tx, now, "config_update", nodeID, ledgerDetailHash(fmt.Sprintf("v%d", cfg.ConfigVersion))); err != nil {
		return NodeConfig{}, err
	}
	if err := tx.Commit(); err != nil {
		return NodeConfig{}, err
	}
	return cfg, nil
}

// validateConfigForClass enforces the frozen class/source/tag/cadence rules before
// persistence, so a config that cannot produce a valid agent-config document is
// never stored.
func validateConfigForClass(nodeClass string, sources map[string]bool, tags []InboundTag, cadence, version int) error {
	if cadence < 30 || cadence > 300 {
		return invalidArgument("cadence_seconds", "must be in [30,300]")
	}
	if version < 1 {
		return invalidArgument("config_version", "must be positive")
	}
	if sources == nil {
		return invalidArgument("collect", "must not be nil")
	}
	allowed := map[string]bool{"system": true, "services": true, "singbox_api": true, "mihomo_api": true, "terminal": true, "events": true}
	if len(sources) != len(allowed) {
		return invalidArgument("collect", "must contain exactly the frozen source switches")
	}
	for k := range sources {
		if !allowed[k] {
			return invalidArgument("collect", "unknown source switch")
		}
	}
	switch nodeClass {
	case NodeClassLinuxVPS:
		if sources["terminal"] || len(tags) == 0 {
			return invalidArgument("collect", "linux_vps requires terminal=false and at least one expected inbound tag")
		}
	case NodeClassWindowsTerminal:
		if sources["services"] || sources["singbox_api"] || len(tags) != 0 {
			return invalidArgument("collect", "windows_terminal requires services/singbox_api=false and no expected inbound tags")
		}
	default:
		return invalidArgument("node_class", "unknown class")
	}
	for _, t := range tags {
		if t.InboundTag == "" || (t.Kind != "reality" && t.Kind != "hysteria2" && t.Kind != "other") {
			return invalidArgument("expected_inbound_tags", "invalid tag/kind")
		}
	}
	return nil
}

func hostMatchesClass(nodeClass, hostOS string) bool {
	switch nodeClass {
	case NodeClassLinuxVPS:
		return hostOS == "linux"
	case NodeClassWindowsTerminal:
		return hostOS == "windows"
	default:
		return false
	}
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("store: random bytes: %w", err)
	}
	return b, nil
}

func randomUUIDv4() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func randomKeyID() (string, error) {
	b, err := randomBytes(4)
	if err != nil {
		return "", err
	}
	return "key-" + hex.EncodeToString(b), nil
}

func randomSalt() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ledgerDetailHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// appendLedgerTx appends a security-ledger entry inside an existing transaction.
func appendLedgerTx(ctx context.Context, tx *sql.Tx, at int64, kind, subject, detailSHA string) (string, error) {
	prev := ledgerGenesisHash
	err := tx.QueryRowContext(ctx, `SELECT entry_hash FROM security_ledger ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read ledger head: %w", err)
	}
	hash := ledgerEntryHash(prev, at, kind, subject, detailSHA)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO security_ledger(at,kind,subject,detail_sha256,prev_hash,entry_hash) VALUES(?,?,?,?,?,?)`,
		at, kind, subject, detailSHA, prev, hash); err != nil {
		return "", fmt.Errorf("store: append ledger entry: %w", err)
	}
	return hash, nil
}

// ReportDisposition is the payload-level disposition returned after transport
// authentication/high-water handling.
type ReportDisposition string

const (
	DispositionAccepted     ReportDisposition = "accepted"
	DispositionDuplicate    ReportDisposition = "duplicate"
	DispositionStaleIgnored ReportDisposition = "stale_ignored"
)

// ApplyIngest runs one authenticated request inside a single transaction:
// precheck (node/key/rotation authorization), transport Evaluate, high-water
// persistence for accepted outcomes, then the payload callback. Unlike the B1
// helper, the callback also runs for a transport Duplicate so report/nonce
// idempotency can be resolved, and every error returns no committed Result.
func (s *Store) ApplyIngest(
	ctx context.Context,
	nodeID string,
	attempt protocol.Attempt,
	fingerprint string,
	precheck func(*Tx) error,
	apply func(*Tx) (ReportDisposition, error),
) (protocol.Result, ReportDisposition, error) {
	if strings.TrimSpace(nodeID) == "" {
		return protocol.Result{}, "", invalidArgument("node_id", "must not be empty")
	}
	if strings.TrimSpace(attempt.BootID) == "" {
		return protocol.Result{}, "", invalidArgument("boot_id", "must not be empty")
	}
	a := attempt
	if a.Fingerprint == "" {
		a.Fingerprint = fingerprint
	}
	if strings.TrimSpace(a.Fingerprint) == "" {
		return protocol.Result{}, "", invalidArgument("fingerprint", "must not be empty")
	}
	if _, err := numericToInt64("gen", a.Gen); err != nil {
		return protocol.Result{}, "", err
	}
	if _, err := numericToInt64("seq", a.Seq); err != nil {
		return protocol.Result{}, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Result{}, "", fmt.Errorf("store: begin ingest transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	t := &Tx{tx: tx}
	if precheck != nil {
		if err := precheck(t); err != nil {
			return protocol.Result{}, "", err
		}
	}
	current, _, err := loadBoot(ctx, tx, nodeID)
	if err != nil {
		return protocol.Result{}, "", err
	}
	history, err := loadSeqFingerprints(ctx, tx, nodeID, a.Gen, a.BootID)
	if err != nil {
		return protocol.Result{}, "", err
	}
	result, err := protocol.Evaluate(current, a, protocol.Options{SeqFingerprints: history})
	if err != nil {
		return protocol.Result{}, "", fmt.Errorf("store: evaluate ingest: %w", err)
	}
	switch result.Outcome {
	case protocol.Accepted:
		next := result.NextBoot
		if next.HighestGen == 0 {
			next = protocol.Boot{HighestGen: a.Gen, BootID: a.BootID, LastSeq: a.Seq}
		}
		if next.LastFingerprint == "" {
			next.LastFingerprint = a.Fingerprint
		}
		highestGen, err := numericToInt64("highest_gen", next.HighestGen)
		if err != nil {
			return protocol.Result{}, "", err
		}
		lastSeq, err := numericToInt64("last_seq", next.LastSeq)
		if err != nil {
			return protocol.Result{}, "", err
		}
		now := nowUnix()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_boot(node_id,highest_gen,boot_id,last_seq,last_fingerprint,updated_at)
			 VALUES(?,?,?,?,?,?)
			 ON CONFLICT(node_id) DO UPDATE SET
			   highest_gen=excluded.highest_gen, boot_id=excluded.boot_id,
			   last_seq=excluded.last_seq, last_fingerprint=excluded.last_fingerprint,
			   updated_at=excluded.updated_at`,
			nodeID, highestGen, next.BootID, lastSeq, nullString(next.LastFingerprint), now); err != nil {
			return protocol.Result{}, "", fmt.Errorf("store: advance ingest high-water: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO boot_registry(node_id,boot_gen,boot_id,first_seen_at,last_seen_at,last_seq,state)
			 VALUES(?,?,?,?,?,?,'active')
			 ON CONFLICT(node_id,boot_gen,boot_id) DO UPDATE SET
			   last_seen_at=excluded.last_seen_at, last_seq=excluded.last_seq, state='active'`,
			nodeID, a.Gen, a.BootID, now, now, func() int64 { v, _ := numericToInt64("seq", a.Seq); return v }()); err != nil {
			return protocol.Result{}, "", fmt.Errorf("store: record ingest boot registry: %w", err)
		}
		if err := recordSeq(ctx, tx, nodeID, a.Gen, a.BootID, a.Seq, a.Fingerprint, now); err != nil {
			return protocol.Result{}, "", err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET last_seen_at=? WHERE node_id=?`, now, nodeID); err != nil {
			return protocol.Result{}, "", fmt.Errorf("store: update node last seen: %w", err)
		}
		if result.AuditGap && current.HighestGen > 0 {
			if _, err := appendLedgerTx(ctx, tx, now, "boot_generation_gap", nodeID,
				ledgerDetailHash(fmt.Sprintf("%d->%d", current.HighestGen, a.Gen))); err != nil {
				return protocol.Result{}, "", err
			}
		}
	case protocol.Duplicate:
		// Already committed by the winning attempt; no high-water write.
	default:
		return protocol.Result{}, "", &TransportConflictError{Outcome: result.Outcome}
	}
	if s.ingestHook != nil {
		if err := s.ingestHook("after_highwater"); err != nil {
			return protocol.Result{}, "", fmt.Errorf("store: ingest fault injection: %w", err)
		}
	}
	var disposition ReportDisposition
	if apply != nil {
		disposition, err = apply(t)
		if err != nil {
			return protocol.Result{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return protocol.Result{}, "", fmt.Errorf("store: commit ingest transaction: %w", err)
	}
	committed = true
	return result, disposition, nil
}

// StoreSnapshotTx persists a validated snapshot and applies latest ordering by
// collected_at. The report dedupe row is the caller's responsibility; this method
// also guards the snapshot unique key/hash.
func (t *Tx) StoreSnapshotTx(ctx context.Context, rec SnapshotRecord) (ReportDisposition, error) {
	var existingHash string
	err := t.tx.QueryRowContext(ctx,
		`SELECT body_sha256 FROM snapshots WHERE node_id=? AND report_id=?`, rec.NodeID, rec.ReportID).Scan(&existingHash)
	if err == nil {
		if existingHash == rec.BodySHA256 {
			return DispositionDuplicate, nil
		}
		return "", fmt.Errorf("%w: report_id already stored with different snapshot hash", ErrConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read snapshot dedupe: %w", err)
	}
	var latestCollected sql.NullInt64
	err = t.tx.QueryRowContext(ctx, `SELECT collected_at FROM node_latest WHERE node_id=?`, rec.NodeID).Scan(&latestCollected)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read latest snapshot: %w", err)
	}
	disposition := DispositionAccepted
	if latestCollected.Valid && rec.CollectedAt <= latestCollected.Int64 {
		disposition = DispositionStaleIgnored
	}
	res, err := t.tx.ExecContext(ctx,
		`INSERT INTO snapshots(node_id,event_id,node_class,report_id,collected_at,received_at,body_sha256,payload_json)
		 VALUES(?,?,?,?,?,?,?,?)`,
		rec.NodeID, rec.EventID, rec.NodeClass, rec.ReportID, rec.CollectedAt, rec.ReceivedAt, rec.BodySHA256, rec.Payload)
	if err != nil {
		if isUniqueViolation(err) {
			return DispositionDuplicate, nil
		}
		return "", fmt.Errorf("store: insert snapshot: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", err
	}
	if disposition == DispositionAccepted {
		if _, err := t.tx.ExecContext(ctx,
			`INSERT INTO node_latest(node_id,snapshot_id,report_id,event_id,node_class,collected_at,updated_at)
			 VALUES(?,?,?,?,?,?,?)
			 ON CONFLICT(node_id) DO UPDATE SET snapshot_id=excluded.snapshot_id, report_id=excluded.report_id,
			   event_id=excluded.event_id, node_class=excluded.node_class, collected_at=excluded.collected_at, updated_at=excluded.updated_at`,
			rec.NodeID, id, rec.ReportID, rec.EventID, rec.NodeClass, rec.CollectedAt, rec.ReceivedAt); err != nil {
			return "", fmt.Errorf("store: update latest snapshot: %w", err)
		}
	}
	return disposition, nil
}

// SnapshotRecord is validated snapshot storage input.
type SnapshotRecord struct {
	NodeID, EventID, NodeClass, ReportID string
	CollectedAt, ReceivedAt              int64
	BodySHA256                           string
	Payload                              []byte
}

// GetLatestSnapshot returns the latest applied snapshot row.
func (s *Store) GetLatestSnapshot(ctx context.Context, nodeID string) (SnapshotRecord, error) {
	var rec SnapshotRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT n.node_id,n.event_id,n.node_class,n.report_id,n.collected_at,n.received_at,n.body_sha256,n.payload_json
		 FROM node_latest l JOIN snapshots n ON n.id=l.snapshot_id WHERE l.node_id=?`, nodeID).
		Scan(&rec.NodeID, &rec.EventID, &rec.NodeClass, &rec.ReportID, &rec.CollectedAt, &rec.ReceivedAt, &rec.BodySHA256, &rec.Payload)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotRecord{}, ErrNotFound
	}
	if err != nil {
		return SnapshotRecord{}, fmt.Errorf("store: read latest snapshot: %w", err)
	}
	return rec, nil
}

// StoreMetricsTx persists a validated metrics report.
func (t *Tx) StoreMetricsTx(ctx context.Context, rec ReportRecord) (ReportDisposition, error) {
	var existing string
	err := t.tx.QueryRowContext(ctx, `SELECT body_sha256 FROM report_metrics WHERE node_id=? AND report_id=?`, rec.NodeID, rec.ReportID).Scan(&existing)
	if err == nil {
		if existing == rec.BodySHA256 {
			return DispositionDuplicate, nil
		}
		return "", fmt.Errorf("%w: report_id already stored with different metrics hash", ErrConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if _, err := t.tx.ExecContext(ctx,
		`INSERT INTO report_metrics(node_id,event_id,report_id,collected_at,received_at,body_sha256,payload_json)
		 VALUES(?,?,?,?,?,?,?)`, rec.NodeID, rec.EventID, rec.ReportID, rec.CollectedAt, rec.ReceivedAt, rec.BodySHA256, rec.Payload); err != nil {
		return "", fmt.Errorf("store: insert metrics report: %w", err)
	}
	return DispositionAccepted, nil
}

// StoreEventsTx persists a validated events report. The caller supplies the
// per-event rows (already validated against the closed event schema).
func (t *Tx) StoreEventsTx(ctx context.Context, rec ReportRecord, events []EventRecord) (ReportDisposition, error) {
	var existing string
	err := t.tx.QueryRowContext(ctx, `SELECT body_sha256 FROM report_event_reports WHERE node_id=? AND report_id=?`, rec.NodeID, rec.ReportID).Scan(&existing)
	if err == nil {
		if existing == rec.BodySHA256 {
			return DispositionDuplicate, nil
		}
		return "", fmt.Errorf("%w: report_id already stored with different events hash", ErrConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read events report dedupe: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		`INSERT INTO report_event_reports(node_id,event_id,report_id,collected_at,received_at,body_sha256,payload_json)
		 VALUES(?,?,?,?,?,?,?)`, rec.NodeID, rec.EventID, rec.ReportID, rec.CollectedAt, rec.ReceivedAt, rec.BodySHA256, rec.Payload); err != nil {
		return "", fmt.Errorf("store: insert events report: %w", err)
	}
	for _, e := range events {
		severity := e.Severity
		if severity == "" {
			severity = "info"
		}
		if _, err := t.tx.ExecContext(ctx,
			`INSERT INTO report_events(node_id,event_id,report_id,collected_at,received_at,event_id_json,event_at,kind,severity,details_json)
			 VALUES(?,?,?,?,?,?,?,?,?,?)`,
			rec.NodeID, rec.EventID, rec.ReportID, rec.CollectedAt, rec.ReceivedAt, e.EventID, e.At, e.Kind, severity, e.DetailsJSON); err != nil {
			return "", fmt.Errorf("store: insert event row: %w", err)
		}
	}
	return DispositionAccepted, nil
}

// ReportRecord is validated report storage input shared by metrics/events.
type ReportRecord struct {
	NodeID, EventID, ReportID string
	CollectedAt, ReceivedAt   int64
	BodySHA256                string
	Payload                   []byte
}

// EventRecord is one validated event row.
type EventRecord struct {
	EventID     string
	At          int64
	Kind        string
	Severity    string
	DetailsJSON string
}

// RunRetentionB2 executes the B2 policy-B sweep: bounded seq/boot pruning,
// nonce/report windows, 30-day active data + 30-day archive, and a recorded run.
// node_boot is never deleted by retention.
func (s *Store) RunRetentionB2(ctx context.Context, now int64) (map[string]int64, error) {
	return s.RunRetentionB2PolicyB(ctx, now)
}

// CapacityStats reports bounded row counts/size used by B2 capacity tests.
type CapacityStats struct {
	Nodes, Snapshots, Metrics, Events, Archive, SeqDedupe, BootRegistry, ReportDedupe, NonceDedupe int64
}

func (s *Store) CapacityStats(ctx context.Context) (CapacityStats, error) {
	var c CapacityStats
	queries := []struct {
		dst *int64
		q   string
	}{
		{&c.Nodes, `SELECT COUNT(*) FROM nodes`},
		{&c.Snapshots, `SELECT COUNT(*) FROM snapshots`},
		{&c.Metrics, `SELECT COUNT(*) FROM report_metrics`},
		{&c.Events, `SELECT COUNT(*) FROM report_events`},
		{&c.Archive, `SELECT COUNT(*) FROM event_catalog WHERE state='archived' AND data_purged_at IS NULL`},
		{&c.SeqDedupe, `SELECT COUNT(*) FROM seq_dedupe`},
		{&c.BootRegistry, `SELECT COUNT(*) FROM boot_registry`},
		{&c.ReportDedupe, `SELECT COUNT(*) FROM report_dedupe`},
		{&c.NonceDedupe, `SELECT COUNT(*) FROM nonce_dedupe`},
	}
	for _, q := range queries {
		if err := s.db.QueryRowContext(ctx, q.q).Scan(q.dst); err != nil {
			return CapacityStats{}, err
		}
	}
	return c, nil
}

var _ = time.Now // retained for future clock injection in B2 handlers
