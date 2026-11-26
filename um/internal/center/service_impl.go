package center

// Real UM-B2 service layer: strict auth/freshness/signature verification, the
// authenticated single-transaction ingest path, enrollment/rotation/config, and
// validated telemetry persistence. The HTTP boundary only frames/decodes and
// passes already-parsed fields here.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/contract"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/protocol"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

const maxClockSkewSeconds = 300
const maxPayloadAgeSeconds = 7 * 24 * 60 * 60

// ServiceConfig configures the real service implementation.
type ServiceConfig struct {
	Store      *store.Store
	Schemas    *schema.Set
	Now        func() time.Time
	ServerSPKI string // optional base64url SHA-256 SPKI pin
}

// ServiceImpl is the real Center Service.
type ServiceImpl struct {
	store   *store.Store
	schemas *schema.Set
	now     func() time.Time
	spki    string
}

// NewService constructs the real service. It requires an already-open store and
// a startup-validated contract schema set (explicit trusted deployment path).
func NewService(cfg ServiceConfig) (*ServiceImpl, error) {
	if cfg.Store == nil {
		return nil, errors.New("center: service store is required")
	}
	if cfg.Schemas == nil {
		return nil, errors.New("center: startup-loaded contract schema set is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &ServiceImpl{store: cfg.Store, schemas: cfg.Schemas, now: cfg.Now, spki: cfg.ServerSPKI}, nil
}

func nowSeconds(t time.Time) int64 { return t.Unix() }

func bodySHA(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func apiErr(status int, code string, retry bool) error {
	return NewAPIError(status, code, retry)
}

// mapServiceError maps store/protocol/contract errors onto the closed HTTP error
// vocabulary. The original error text is never exposed to the client.
func mapServiceError(err error) error {
	if err == nil {
		return nil
	}
	var api *APIError
	if errors.As(err, &api) {
		return api
	}
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		return apiErr(401, "token_invalid", false)
	case errors.Is(err, store.ErrTokenExpired):
		return apiErr(401, "token_expired", false)
	case errors.Is(err, store.ErrTokenUsed):
		return apiErr(401, "token_used", false)
	case errors.Is(err, store.ErrTokenScopeMismatch):
		return apiErr(401, "token_scope_mismatch", false)
	case errors.Is(err, store.ErrNodeRevoked), errors.Is(err, store.ErrKeyRevoked):
		return apiErr(401, "revoked_key", false)
	case errors.Is(err, store.ErrNodeUnknown), errors.Is(err, store.ErrKeyUnknown):
		return apiErr(401, "unknown_node", false)
	case errors.Is(err, store.ErrRotationInProgress):
		return apiErr(409, "rotation_in_progress", false)
	case errors.Is(err, store.ErrRotationExpired):
		return apiErr(409, "rotation_expired", false)
	case errors.Is(err, store.ErrNotFound):
		return apiErr(404, "endpoint_not_found", false)
	case contract.IsPlatformMismatch(err):
		return apiErr(400, "platform_mismatch", false)
	case contract.IsInvalidRequest(err):
		return apiErr(400, "invalid_request", false)
	case store.IsTransportConflict(err):
		if outcome, ok := store.TransportConflictOutcome(err); ok {
			switch outcome {
			case protocol.StaleBootGeneration:
				return apiErr(409, "stale_boot_generation", false)
			case protocol.BootIdentityConflict:
				return apiErr(409, "boot_identity_conflict", false)
			case protocol.SequenceConflict:
				return apiErr(409, "sequence_conflict", false)
			}
		}
		return apiErr(409, "sequence_conflict", false)
	case errors.Is(err, store.ErrConflict):
		return apiErr(409, "report_conflict", false)
	case errors.Is(err, store.ErrInvalidArgument):
		return apiErr(400, "invalid_request", false)
	}
	return apiErr(503, "storage_unavailable", true)
}

func (s *ServiceImpl) serverTime() int64 { return nowSeconds(s.now()) }

func (s *ServiceImpl) verifySignature(fields wire.Fields, body []byte, signature, publicKeyB64 string) error {
	pub, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != 32 {
		return apiErr(401, "bad_signature", false)
	}
	if err := wire.VerifyWithError(fields, body, signature, pub); err != nil {
		return apiErr(401, "bad_signature", false)
	}
	return nil
}

func (s *ServiceImpl) checkFreshness(now int64, sentAtValue string) (int64, error) {
	sentAt, err := wire.ParseCanonicalDecimal(wire.HeaderSentAt, sentAtValue, 0, math.MaxInt64)
	if err != nil {
		return 0, apiErr(400, "invalid_header", false)
	}
	delta := now - int64(sentAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > maxClockSkewSeconds {
		return 0, apiErr(401, "stale_timestamp", true)
	}
	return int64(sentAt), nil
}

// authzKeyTx re-checks node/key state inside the authenticated ingest
// transaction. A provisional key can be accepted only as a rotation proof; the
// confirmation revokes the old key atomically in the same transaction.
func (s *ServiceImpl) authzKeyTx(ctx context.Context, tx *store.Tx, nodeID, keyID string, now int64) error {
	node, err := tx.NodeTx(ctx, nodeID)
	if err != nil {
		return mapServiceError(err)
	}
	if node.State != store.NodeActive {
		return apiErr(401, "revoked_key", false)
	}
	key, err := tx.KeyTx(ctx, nodeID, keyID)
	if err != nil {
		return mapServiceError(err)
	}
	switch key.State {
	case store.KeyActive:
		return nil
	case store.KeyProvisional:
		rec, ok, err := tx.RotationByNewKeyTx(ctx, nodeID, keyID)
		if err != nil {
			return mapServiceError(err)
		}
		if !ok {
			return apiErr(401, "revoked_key", false)
		}
		if rec.ExpiresAt > 0 && now > rec.ExpiresAt {
			return apiErr(409, "rotation_expired", false)
		}
		if _, err := tx.ConfirmRotationTx(ctx, nodeID, rec.Nonce, now); err != nil {
			return mapServiceError(err)
		}
		return nil
	case store.KeyRevoked:
		return apiErr(401, "revoked_key", false)
	default:
		return apiErr(401, "unauthorized", false)
	}
}

// Enroll consumes a scoped one-time bootstrap token and commits node+key+config
// atomically, after verifying the bootstrap signature. The token is not consumed
// if the signature/body/scope checks fail before the transaction.
func (s *ServiceImpl) Enroll(ctx context.Context, req EnrollRequest) (EnrollResult, error) {
	now := req.Now
	if now == 0 {
		now = s.serverTime()
	}
	if req.Fields.Endpoint != wire.Enroll {
		return EnrollResult{}, apiErr(400, "invalid_request", false)
	}
	if err := req.Fields.Validate(); err != nil {
		return EnrollResult{}, apiErr(400, "invalid_header", false)
	}
	var body struct {
		NodeClass string `json:"node_class"`
		Host      struct {
			OS string `json:"os"`
		} `json:"host"`
	}
	if err := s.schemas.Validate("enroll-request.schema.json", req.Body); err != nil {
		return EnrollResult{}, apiErr(400, "invalid_request", false)
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return EnrollResult{}, apiErr(400, "invalid_request", false)
	}
	if err := s.verifySignature(req.Fields, req.Body, req.Signature, req.Fields.PublicKey); err != nil {
		return EnrollResult{}, err
	}
	id, err := s.store.Enroll(ctx, store.TokenHash(req.Token), body.NodeClass, body.Host.OS, req.Fields.PublicKey, now)
	if err != nil {
		return EnrollResult{}, mapServiceError(err)
	}
	return EnrollResult{
		NodeID: id.NodeID, EventID: id.EventID, NodeClass: id.NodeClass,
		KeyID: id.KeyID, DeviceSalt: id.DeviceSalt, ConfigVersion: id.ConfigVersion,
		CadenceSeconds: id.CadenceSeconds, ServerTime: now, CenterSPKISHA256: s.spki,
	}, nil
}

func (s *ServiceImpl) loadNodeAndKey(ctx context.Context, nodeID, keyID string) (store.Node, store.NodeKey, error) {
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return store.Node{}, store.NodeKey{}, mapServiceError(err)
	}
	key, err := s.store.GetKey(ctx, nodeID, keyID)
	if err != nil {
		return store.Node{}, store.NodeKey{}, mapServiceError(err)
	}
	if key.State == store.KeyRevoked || node.State != store.NodeActive {
		return store.Node{}, store.NodeKey{}, apiErr(401, "revoked_key", false)
	}
	return node, key, nil
}

func (s *ServiceImpl) nodeConfig(ctx context.Context, nodeID string) (store.NodeConfig, error) {
	cfg, err := s.store.GetNodeConfig(ctx, nodeID)
	if err != nil {
		return store.NodeConfig{}, mapServiceError(err)
	}
	return cfg, nil
}

// Report authenticates one report attempt and commits high-water, nonce/report
// dedupe, and validated telemetry in one transaction.
func (s *ServiceImpl) Report(ctx context.Context, req ReportRequest) (ReportResult, error) {
	now := req.Now
	if now == 0 {
		now = s.serverTime()
	}
	if req.Fields.Endpoint != wire.Report {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	if err := req.Fields.Validate(); err != nil {
		return ReportResult{}, apiErr(400, "invalid_header", false)
	}
	sentAt, err := s.checkFreshness(now, req.Fields.SentAt)
	if err != nil {
		return ReportResult{}, err
	}
	var env struct {
		V           int    `json:"v"`
		Type        string `json:"type"`
		ReportID    string `json:"report_id"`
		CollectedAt int64  `json:"collected_at"`
	}
	if err := json.Unmarshal(req.Body, &env); err != nil {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	if env.Type != req.ReportType || env.ReportID != req.ReportID || env.CollectedAt != req.CollectedAt {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	if env.CollectedAt > sentAt+60 {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	if env.CollectedAt < now-maxPayloadAgeSeconds {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	node, key, err := s.loadNodeAndKey(ctx, req.Fields.NodeID, req.Fields.KeyID)
	if err != nil {
		return ReportResult{}, err
	}
	if err := s.verifySignature(req.Fields, req.Body, req.Signature, key.PublicKey); err != nil {
		return ReportResult{}, err
	}
	cfg, err := s.nodeConfig(ctx, node.NodeID)
	if err != nil {
		return ReportResult{}, err
	}
	opts := contract.ValidateOptions{TerminalConfigured: cfg.Sources["terminal"] || cfg.Sources["mihomo_api"]}
	if err := contract.ValidateReportBodyWithSchemaSet(s.schemas, node.NodeClass, req.ReportType, req.Body, opts); err != nil {
		return ReportResult{}, mapServiceError(err)
	}
	if req.ReportType == "snapshot" {
		if err := enforceExpectedInboundTags(node.NodeClass, req.Body, cfg.ExpectedInboundTags); err != nil {
			return ReportResult{}, err
		}
	}
	if req.Fingerprint == "" {
		fp, ferr := wire.Fingerprint(req.Fields, req.Body)
		if ferr != nil {
			return ReportResult{}, apiErr(400, "invalid_header", false)
		}
		req.Fingerprint = fp
	}
	bodyHash := bodySHA(req.Body)
	var disposition store.ReportDisposition
	attempt := protocol.Attempt{
		Gen: req.FieldsBootGen(), BootID: req.Fields.BootID, Seq: req.FieldsSeq(),
		Fingerprint: req.Fingerprint,
	}
	result, _, err := s.store.ApplyIngest(ctx, node.NodeID, attempt, req.Fingerprint,
		func(tx *store.Tx) error { return s.authzKeyTx(ctx, tx, node.NodeID, req.Fields.KeyID, now) },
		func(tx *store.Tx) (store.ReportDisposition, error) {
			nonceStatus, err := tx.CheckOrInsertNonce(ctx, node.NodeID, req.Fields.Nonce, req.Fingerprint, now)
			if err != nil {
				return "", mapServiceError(err)
			}
			if nonceStatus == store.NonceReuse {
				return "", apiErr(409, "nonce_reuse", false)
			}
			reportStatus, err := tx.CheckOrInsertReport(ctx, node.NodeID, env.ReportID, bodyHash, now)
			if err != nil {
				return "", mapServiceError(err)
			}
			if reportStatus == store.ReportConflict {
				return "", apiErr(409, "report_conflict", false)
			}
			if reportStatus == store.ReportDuplicate {
				disposition = store.DispositionDuplicate
				return disposition, nil
			}
			switch env.Type {
			case "snapshot":
				d, err := tx.StoreSnapshotTx(ctx, store.SnapshotRecord{
					NodeID: node.NodeID, EventID: node.EventID, NodeClass: node.NodeClass,
					ReportID: env.ReportID, CollectedAt: env.CollectedAt, ReceivedAt: now,
					BodySHA256: bodyHash, Payload: req.Body,
				})
				if err != nil {
					return "", mapServiceError(err)
				}
				disposition = d
			case "metrics":
				d, err := tx.StoreMetricsTx(ctx, store.ReportRecord{
					NodeID: node.NodeID, EventID: node.EventID, ReportID: env.ReportID,
					CollectedAt: env.CollectedAt, ReceivedAt: now, BodySHA256: bodyHash, Payload: req.Body,
				})
				if err != nil {
					return "", mapServiceError(err)
				}
				disposition = d
			case "events":
				var eventsEnv struct {
					Events []struct {
						EventID string          `json:"event_id"`
						At      int64           `json:"at"`
						Kind    string          `json:"kind"`
						Detail  json.RawMessage `json:"detail"`
					} `json:"events"`
				}
				if err := json.Unmarshal(req.Body, &eventsEnv); err != nil {
					return "", apiErr(400, "invalid_request", false)
				}
				records := make([]store.EventRecord, 0, len(eventsEnv.Events))
				for _, e := range eventsEnv.Events {
					records = append(records, store.EventRecord{EventID: e.EventID, At: e.At, Kind: e.Kind, DetailsJSON: string(e.Detail)})
				}
				d, err := tx.StoreEventsTx(ctx, store.ReportRecord{
					NodeID: node.NodeID, EventID: node.EventID, ReportID: env.ReportID,
					CollectedAt: env.CollectedAt, ReceivedAt: now, BodySHA256: bodyHash, Payload: req.Body,
				}, records)
				if err != nil {
					return "", mapServiceError(err)
				}
				disposition = d
			default:
				return "", apiErr(400, "invalid_request", false)
			}
			return disposition, nil
		})
	if err != nil {
		return ReportResult{}, mapServiceError(err)
	}
	_ = result
	ackResult := "accepted"
	switch disposition {
	case store.DispositionDuplicate:
		ackResult = "duplicate"
	case store.DispositionStaleIgnored:
		ackResult = "stale_ignored"
	}
	var nextSeq *uint64
	if boot, berr := s.store.GetBoot(ctx, node.NodeID); berr == nil {
		if boot.LastSeq < wire.MaxNumeric {
			v := boot.LastSeq + 1
			nextSeq = &v
		}
	}
	return ReportResult{
		ReportID: env.ReportID, Result: ackResult, NextSeq: nextSeq,
		ConfigVersion: cfg.ConfigVersion, ServerTime: now,
	}, nil
}

// Rotate implements the persisted rotation-intent state machine with full
// transport/high-water validation on every attempt (including replays).
func (s *ServiceImpl) Rotate(ctx context.Context, req RotateRequest) (RotateResult, error) {
	now := req.Now
	if now == 0 {
		now = s.serverTime()
	}
	if req.Fields.Endpoint != wire.Rotate {
		return RotateResult{}, apiErr(400, "invalid_request", false)
	}
	if err := req.Fields.Validate(); err != nil {
		return RotateResult{}, apiErr(400, "invalid_header", false)
	}
	if _, err := s.checkFreshness(now, req.Fields.SentAt); err != nil {
		return RotateResult{}, err
	}
	if err := s.schemas.Validate("rotate-request.schema.json", req.Body); err != nil {
		return RotateResult{}, apiErr(400, "invalid_request", false)
	}
	var body struct {
		V         int    `json:"v"`
		NewPubkey string `json:"new_pubkey"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return RotateResult{}, apiErr(400, "invalid_request", false)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(body.NewPubkey); err != nil || len(raw) != 32 {
		return RotateResult{}, apiErr(400, "invalid_request", false)
	}
	node, key, err := s.loadNodeAndKey(ctx, req.Fields.NodeID, req.Fields.KeyID)
	if err != nil {
		return RotateResult{}, err
	}
	if key.State != store.KeyActive {
		return RotateResult{}, apiErr(401, "revoked_key", false)
	}
	if err := s.verifySignature(req.Fields, req.Body, req.Signature, key.PublicKey); err != nil {
		return RotateResult{}, err
	}
	bodyHash := bodySHA(req.Body)
	rotateFP := rotateFingerprint(node.NodeID, req.Fields.Nonce, req.Fields.KeyID, bodyHash)
	if req.Fingerprint == "" {
		req.Fingerprint = rotateFP
	}
	attempt := protocol.Attempt{Gen: req.FieldsBootGen(), BootID: req.Fields.BootID, Seq: req.FieldsSeq(), Fingerprint: req.FieldsFingerprint()}
	var responseBody []byte
	var previousKeyID, newKeyID string
	_, _, err = s.store.ApplyIngest(ctx, node.NodeID, attempt, req.FieldsFingerprint(),
		func(tx *store.Tx) error {
			return s.authzKeyTx(ctx, tx, node.NodeID, req.Fields.KeyID, now)
		},
		func(tx *store.Tx) (store.ReportDisposition, error) {
			nonceStatus, err := tx.CheckOrInsertNonce(ctx, node.NodeID, req.Fields.Nonce, rotateFP, now)
			if err != nil {
				return "", mapServiceError(err)
			}
			if nonceStatus == store.NonceReuse {
				return "", apiErr(409, "nonce_reuse", false)
			}
			if existing, ok, err := tx.RotationTx(ctx, node.NodeID, req.Fields.Nonce); err != nil {
				return "", mapServiceError(err)
			} else if ok {
				if existing.OldKeyID != req.Fields.KeyID || existing.BodySHA256 != bodyHash {
					return "", apiErr(409, "nonce_reuse", false)
				}
				switch existing.State {
				case store.RotationAwaitingProof:
					if existing.ExpiresAt > 0 && now > existing.ExpiresAt {
						return "", apiErr(409, "rotation_expired", false)
					}
				case store.RotationConfirmed:
					// Idempotent replay of the already committed response.
				case store.RotationAborted:
					return "", apiErr(409, "rotation_expired", false)
				default:
					return "", apiErr(401, "unauthorized", false)
				}
				responseBody = []byte(existing.ResponseJSON)
				previousKeyID, newKeyID = existing.OldKeyID, existing.NewKeyID
				return store.DispositionDuplicate, nil
			}
			if pending, ok, err := tx.PendingRotationTx(ctx, node.NodeID); err != nil {
				return "", mapServiceError(err)
			} else if ok && pending.Nonce != req.Fields.Nonce {
				return "", apiErr(409, "rotation_in_progress", false)
			}
			rec := store.RotationRecord{
				NodeID: node.NodeID, OldKeyID: req.Fields.KeyID, Nonce: req.Fields.Nonce,
				BodySHA256: bodyHash, ExpiresAt: now + 300, CreatedAt: now,
			}
			if err := tx.CreateRotationTx(ctx, rec, body.NewPubkey); err != nil {
				return "", mapServiceError(err)
			}
			created, ok, err := tx.RotationTx(ctx, node.NodeID, req.Fields.Nonce)
			if err != nil || !ok {
				return "", apiErr(503, "storage_unavailable", true)
			}
			responseBody = []byte(created.ResponseJSON)
			previousKeyID, newKeyID = created.OldKeyID, created.NewKeyID
			return store.DispositionAccepted, nil
		})
	if err != nil {
		return RotateResult{}, mapServiceError(err)
	}
	cfg, err := s.nodeConfig(ctx, node.NodeID)
	if err != nil {
		return RotateResult{}, err
	}
	return RotateResult{Response: responseBody, PreviousKeyID: previousKeyID, NewKeyID: newKeyID,
		ConfigVersion: cfg.ConfigVersion, ServerTime: now}, nil
}

// Config pulls the complete center-managed agent config after full auth.
func (s *ServiceImpl) Config(ctx context.Context, req ConfigRequest) (ConfigResult, error) {
	now := req.Now
	if now == 0 {
		now = s.serverTime()
	}
	if req.Fields.Endpoint != wire.Config {
		return ConfigResult{}, apiErr(400, "invalid_request", false)
	}
	if err := req.Fields.Validate(); err != nil {
		return ConfigResult{}, apiErr(400, "invalid_header", false)
	}
	if _, err := s.checkFreshness(now, req.Fields.SentAt); err != nil {
		return ConfigResult{}, err
	}
	if string(req.Body) != "{}" {
		return ConfigResult{}, apiErr(400, "invalid_request", false)
	}
	node, key, err := s.loadNodeAndKey(ctx, req.Fields.NodeID, req.Fields.KeyID)
	if err != nil {
		return ConfigResult{}, err
	}
	if err := s.verifySignature(req.Fields, req.Body, req.Signature, key.PublicKey); err != nil {
		return ConfigResult{}, err
	}
	fp := req.Fingerprint
	if fp == "" {
		fp, err = wire.Fingerprint(req.Fields, req.Body)
		if err != nil {
			return ConfigResult{}, apiErr(400, "invalid_header", false)
		}
	}
	var cfg store.NodeConfig
	attempt := protocol.Attempt{Gen: req.FieldsBootGen(), BootID: req.Fields.BootID, Seq: req.FieldsSeq(), Fingerprint: fp}
	_, _, err = s.store.ApplyIngest(ctx, node.NodeID, attempt, fp,
		func(tx *store.Tx) error { return s.authzKeyTx(ctx, tx, node.NodeID, req.Fields.KeyID, now) },
		func(tx *store.Tx) (store.ReportDisposition, error) {
			status, err := tx.CheckOrInsertNonce(ctx, node.NodeID, req.Fields.Nonce, fp, now)
			if err != nil {
				return "", mapServiceError(err)
			}
			if status == store.NonceReuse {
				return "", apiErr(409, "nonce_reuse", false)
			}
			c, err := tx.ConfigTx(ctx, node.NodeID)
			if err != nil {
				return "", mapServiceError(err)
			}
			cfg = c
			return store.DispositionAccepted, nil
		})
	if err != nil {
		return ConfigResult{}, mapServiceError(err)
	}
	if err := validateClassConfigForClass(node.NodeClass, cfg); err != nil {
		return ConfigResult{}, err
	}
	doc := map[string]any{
		"v": 1, "node_id": node.NodeID, "event_id": node.EventID, "node_class": node.NodeClass,
		"config_version": cfg.ConfigVersion, "cadence_seconds": cfg.CadenceSeconds,
		"collect": cfg.Sources, "device_salt": cfg.DeviceSalt, "server_time": now,
		"expected_inbound_tags": cfg.ExpectedInboundTags,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return ConfigResult{}, apiErr(503, "storage_unavailable", true)
	}
	if err := s.schemas.Validate("agent-config.schema.json", body); err != nil {
		// A config-generation bug must fail closed, not emit an invalid config.
		return ConfigResult{}, apiErr(503, "storage_unavailable", true)
	}
	return ConfigResult{Body: body, ConfigVersion: cfg.ConfigVersion, ServerTime: now}, nil
}

// enforceExpectedInboundTags binds a Linux snapshot's protocol/traffic inbound
// tags to the center-managed allowlist for that node/event. Unknown tags are
// rejected at the boundary rather than stored/displayed.
func enforceExpectedInboundTags(nodeClass string, body []byte, expected []store.InboundTag) error {
	if nodeClass != store.NodeClassLinuxVPS {
		return nil
	}
	allowed := make(map[string]string, len(expected))
	for _, t := range expected {
		allowed[t.InboundTag] = t.Kind
	}
	var snap struct {
		Protocols []struct {
			Kind       string `json:"kind"`
			InboundTag string `json:"inbound_tag"`
		} `json:"protocols"`
		Traffic []struct {
			InboundTag string `json:"inbound_tag"`
		} `json:"traffic"`
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		return apiErr(400, "invalid_request", false)
	}
	for _, p := range snap.Protocols {
		kind, ok := allowed[p.InboundTag]
		if !ok || kind != p.Kind {
			return apiErr(400, "invalid_request", false)
		}
	}
	for _, tr := range snap.Traffic {
		if _, ok := allowed[tr.InboundTag]; !ok {
			return apiErr(400, "invalid_request", false)
		}
	}
	return nil
}

func validateClassConfigForClass(nodeClass string, cfg store.NodeConfig) error {
	if cfg.Sources == nil {
		return apiErr(503, "storage_unavailable", true)
	}
	if nodeClass == store.NodeClassLinuxVPS {
		if cfg.Sources["terminal"] || len(cfg.ExpectedInboundTags) == 0 {
			return apiErr(503, "storage_unavailable", true)
		}
		return nil
	}
	if nodeClass == store.NodeClassWindowsTerminal {
		if cfg.Sources["services"] || cfg.Sources["singbox_api"] || len(cfg.ExpectedInboundTags) != 0 {
			return apiErr(503, "storage_unavailable", true)
		}
		return nil
	}
	return apiErr(503, "storage_unavailable", true)
}

// rotateFingerprint binds a rotation intent to (node, nonce, old key, body hash)
// and deliberately excludes refreshed sent_at/seq/boot_gen so an intent retry is
// idempotent while still being fully transport-validated.
func rotateFingerprint(nodeID, nonce, oldKeyID, bodyHash string) string {
	sum := sha256.Sum256([]byte("um-rotate-intent-v1\n" + nodeID + "\n" + nonce + "\n" + oldKeyID + "\n" + bodyHash))
	return hex.EncodeToString(sum[:])
}

// Small typed helpers keep the request structs strict without exposing unsigned
// conversions to the store.
func (r ReportRequest) FieldsBootGen() uint64 {
	v, _ := wire.ParseCanonicalDecimal(wire.HeaderBootGen, r.Fields.BootGen, 1, wire.MaxNumeric)
	return v
}
func (r ReportRequest) FieldsSeq() uint64 {
	v, _ := wire.ParseCanonicalDecimal(wire.HeaderSeq, r.Fields.Sequence, 1, wire.MaxNumeric)
	return v
}
func (r RotateRequest) FieldsBootGen() uint64 {
	v, _ := wire.ParseCanonicalDecimal(wire.HeaderBootGen, r.Fields.BootGen, 1, wire.MaxNumeric)
	return v
}
func (r RotateRequest) FieldsSeq() uint64 {
	v, _ := wire.ParseCanonicalDecimal(wire.HeaderSeq, r.Fields.Sequence, 1, wire.MaxNumeric)
	return v
}
func (r RotateRequest) FieldsFingerprint() string {
	fp, _ := wire.Fingerprint(r.Fields, r.Body)
	return fp
}
func (r ConfigRequest) FieldsBootGen() uint64 {
	v, _ := wire.ParseCanonicalDecimal(wire.HeaderBootGen, r.Fields.BootGen, 1, wire.MaxNumeric)
	return v
}
func (r ConfigRequest) FieldsSeq() uint64 {
	v, _ := wire.ParseCanonicalDecimal(wire.HeaderSeq, r.Fields.Sequence, 1, wire.MaxNumeric)
	return v
}

var _ = strconv.Itoa
var _ = strings.TrimSpace
