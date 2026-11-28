package center

// Real UM-B2 service layer: strict auth/freshness/signature verification, the
// authenticated single-transaction ingest path, enrollment/rotation/config, and
// validated telemetry persistence. The HTTP boundary only frames/decodes and
// passes already-parsed fields here.

import (
	"bytes"
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
	case errors.Is(err, store.ErrTokenInvalid), errors.Is(err, store.ErrTokenRevoked):
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
	case errors.Is(err, store.ErrRotationState):
		return apiErr(409, "nonce_reuse", false)
	case errors.Is(err, store.ErrEventArchived), errors.Is(err, store.ErrEventPurged), errors.Is(err, store.ErrEventUnknown):
		return apiErr(409, "identity_mismatch", false)
	case errors.Is(err, store.ErrQuotaExceeded), errors.Is(err, store.ErrArchiveQuota):
		// The frozen v1 error vocabulary has no quota_exceeded token; B2 maps this
		// capacity failure onto storage_unavailable and documents the clarification
		// proposal in um/docs/um-b2-contract-clarifications.md. No new wire code is
		// invented.
		return apiErr(503, "storage_unavailable", true)
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
func (s *ServiceImpl) authzKeyTx(ctx context.Context, tx *store.Tx, nodeID, keyID string, now int64, allowProvisional bool) error {
	node, err := tx.NodeTx(ctx, nodeID)
	if err != nil {
		return mapServiceError(err)
	}
	if node.State != store.NodeActive {
		return apiErr(401, "revoked_key", false)
	}
	event, err := tx.EventActiveTx(ctx, node.EventID)
	if err != nil {
		return mapServiceError(err)
	}
	_ = event
	key, err := tx.KeyTx(ctx, nodeID, keyID)
	if err != nil {
		return mapServiceError(err)
	}
	switch key.State {
	case store.KeyActive:
		return nil
	case store.KeyProvisional:
		if !allowProvisional {
			return apiErr(401, "revoked_key", false)
		}
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
	if _, err := s.checkFreshness(now, req.Fields.SentAt); err != nil {
		return EnrollResult{}, err
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
	// Predictable enrollment-response schema violations are refused before the
	// store commits node/key/config; the boundary still byte-validates the result.
	if s.spki != "" {
		raw, err := base64.RawURLEncoding.DecodeString(s.spki)
		if err != nil || len(raw) != 32 {
			return EnrollResult{}, apiErr(503, "storage_unavailable", true)
		}
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

// rejectionAuditKind maps a rolled-back API rejection to the security-ledger
// kind used consistently by Report/Config/Rotate.
func rejectionAuditKind(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.Code {
		case "nonce_reuse":
			return "nonce_reuse"
		case "report_conflict":
			return "report_conflict"
		}
	}
	return ""
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
		Agent       struct {
			Version string `json:"version"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(req.Body, &env); err != nil {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	if env.Type != req.ReportType || env.ReportID != req.ReportID || env.CollectedAt != req.CollectedAt {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	if env.CollectedAt > sentAt+60 || env.CollectedAt < now-maxPayloadAgeSeconds {
		return ReportResult{}, apiErr(400, "invalid_request", false)
	}
	node, key, err := s.loadNodeAndKey(ctx, req.Fields.NodeID, req.Fields.KeyID)
	if err != nil {
		return ReportResult{}, err
	}
	if err := s.verifySignature(req.Fields, req.Body, req.Signature, key.PublicKey); err != nil {
		return ReportResult{}, err
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
	var (
		currentCfg    store.NodeConfig
		trafficRecord *store.TrafficObservationRecord
	)
	validationRejected := false
	auditKind := ""
	attempt := protocol.Attempt{
		Gen: req.FieldsBootGen(), BootID: req.Fields.BootID, Seq: req.FieldsSeq(),
		Fingerprint: req.Fingerprint,
	}
	result, _, err := s.store.ApplyIngest(ctx, node.NodeID, attempt, req.Fingerprint,
		func(tx *store.Tx) error {
			if err := s.authzKeyTx(ctx, tx, node.NodeID, req.Fields.KeyID, now, true); err != nil {
				return err
			}
			// The configuration used for payload/source validation must be the one
			// read in this same transaction, not an earlier snapshot.
			c, err := tx.ConfigAtTx(ctx, node.NodeID, env.CollectedAt)
			if err != nil {
				return mapServiceError(err)
			}
			if err := validateClassConfigForClass(node.NodeClass, c); err != nil {
				return err
			}
			cur, err := tx.ConfigTx(ctx, node.NodeID)
			if err != nil {
				return mapServiceError(err)
			}
			if err := validateClassConfigForClass(node.NodeClass, cur); err != nil {
				return err
			}
			currentCfg = cur
			opts := contract.ValidateOptions{
				TerminalConfigured:      c.Sources["terminal"] || c.Sources["mihomo_api"],
				MonitorExportConfigured: c.Sources["monitor_export"],
			}
			if err := contract.ValidateReportBodyWithSchemaSet(s.schemas, node.NodeClass, req.ReportType, req.Body, opts); err != nil {
				validationRejected = true
				return mapServiceError(err)
			}
			if err := validateReportSources(node.NodeClass, req.ReportType, req.Body, c.Sources); err != nil {
				validationRejected = true
				return err
			}
			var revisionProbe struct {
				ContractRevision *int `json:"contract_revision"`
			}
			_ = json.Unmarshal(req.Body, &revisionProbe)
			if revisionProbe.ContractRevision != nil && *revisionProbe.ContractRevision == contract.ContractRevision7 {
				// CFG-REV7 defense in depth: only a rev-7-capable signed agent may
				// submit a rev-7 body, even if an operator/bug enabled the source for
				// an older node. The config gate is the primary control; this check
				// keeps a misconfigured/rollback race from storing rev-7 data that the
				// center never advertised to that agent build.
				var agentDoc struct {
					Agent struct {
						Version string `json:"version"`
					} `json:"agent"`
				}
				if json.Unmarshal(req.Body, &agentDoc) != nil || !agentVersionAtLeast(agentDoc.Agent.Version, MinMonitorExportAgentVersion) {
					validationRejected = true
					return apiErr(400, "invalid_request", false)
				}
			}
			if req.ReportType == "snapshot" {
				if err := enforceExpectedInboundTags(node.NodeClass, req.Body, c.ExpectedInboundTags); err != nil {
					validationRejected = true
					return err
				}
				// The rev-7 traffic observation is normalized once, inside the
				// authenticated transaction that decided the effective config, and
				// stored in the same snapshot ingest transaction below.
				rec, terr := normalizeTrafficObservation(env.CollectedAt, req.Body, now)
				if terr != nil {
					validationRejected = true
					return mapServiceError(terr)
				}
				trafficRecord = rec
			}
			if err := validateMetricEventTagBindings(node.NodeClass, req.ReportType, req.Body, c.ExpectedInboundTags); err != nil {
				validationRejected = true
				return err
			}
			nonceStatus, err := tx.CheckOrInsertNonce(ctx, node.NodeID, req.Fields.Nonce, req.Fingerprint, now)
			if err != nil {
				return mapServiceError(err)
			}
			if nonceStatus == store.NonceReuse {
				auditKind = "nonce_reuse"
				return apiErr(409, "nonce_reuse", false)
			}
			return nil
		},
		func(tx *store.Tx) (store.ReportDisposition, error) {
			if existingKind, existingHash, exists, err := tx.ExistingReportKindHash(ctx, node.NodeID, env.ReportID); err != nil {
				return "", mapServiceError(err)
			} else if exists && (existingKind != "dedupe" && existingKind != env.Type || existingHash != bodyHash) {
				// The 8-day dedupe row may have expired while the 30-day telemetry
				// still exists; report type/body identity must remain immutable.
				auditKind = "report_conflict"
				return "", apiErr(409, "report_conflict", false)
			}
			reportStatus, err := tx.CheckOrInsertReport(ctx, node.NodeID, env.ReportID, bodyHash, now)
			if err != nil {
				return "", mapServiceError(err)
			}
			if reportStatus == store.ReportConflict {
				auditKind = "report_conflict"
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
					BodySHA256: bodyHash, Payload: req.Body, TrafficObservation: trafficRecord,
					AgentVersion: env.Agent.Version,
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
						EventID  string          `json:"event_id"`
						At       int64           `json:"at"`
						Kind     string          `json:"kind"`
						Severity string          `json:"severity"`
						Detail   json.RawMessage `json:"detail"`
					} `json:"events"`
				}
				if err := json.Unmarshal(req.Body, &eventsEnv); err != nil {
					return "", apiErr(400, "invalid_request", false)
				}
				records := make([]store.ReportEventRecord, 0, len(eventsEnv.Events))
				for _, e := range eventsEnv.Events {
					records = append(records, store.ReportEventRecord{EventID: e.EventID, At: e.At, Kind: e.Kind, Severity: e.Severity, DetailsJSON: string(e.Detail)})
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
		if validationRejected && auditKind == "" {
			auditKind = "report_rejected"
		}
		if auditKind != "" {
			// The rejection rolled back the ingest transaction; record the audit in
			// its own transaction. An audit failure is not silently ignored: the
			// caller gets a retryable storage error instead of a claimed audit.
			if _, aerr := s.store.AppendLedger(ctx, now, auditKind, node.NodeID, bodyHash); aerr != nil {
				return ReportResult{}, apiErr(503, "storage_unavailable", true)
			}
		}
		return ReportResult{}, mapServiceError(err)
	}
	ackResult := "accepted"
	switch disposition {
	case store.DispositionDuplicate:
		ackResult = "duplicate"
	case store.DispositionStaleIgnored:
		ackResult = "stale_ignored"
	}
	var nextSeq *uint64
	if result.NextSeq != nil {
		v := *result.NextSeq
		nextSeq = &v
	}
	return ReportResult{
		ReportID: env.ReportID, Result: ackResult, NextSeq: nextSeq,
		ConfigVersion: currentCfg.ConfigVersion, ServerTime: now,
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
	// Expired awaiting_proof intents are aborted immediately (only the
	// provisional key is revoked; the old key remains active). They must not block
	// a new legal rotation until the hourly maintenance job.
	if _, err := s.store.AbortExpiredRotations(ctx, now); err != nil {
		return RotateResult{}, apiErr(503, "storage_unavailable", true)
	}
	if req.Fingerprint == "" {
		req.Fingerprint = rotateFP
	}
	attempt := protocol.Attempt{Gen: req.FieldsBootGen(), BootID: req.Fields.BootID, Seq: req.FieldsSeq(), Fingerprint: req.FieldsFingerprint()}
	var responseBody []byte
	var previousKeyID, newKeyID string
	_, _, err = s.store.ApplyIngest(ctx, node.NodeID, attempt, req.FieldsFingerprint(),
		func(tx *store.Tx) error {
			return s.authzKeyTx(ctx, tx, node.NodeID, req.Fields.KeyID, now, false)
		},
		func(tx *store.Tx) (store.ReportDisposition, error) {
			// Frozen §7 order: boot/sequence validation happened in Evaluate;
			// nonce intent match is step 6. A nonce failure rolls back high-water.
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
				if err := s.schemas.Validate("rotate-response.schema.json", responseBody); err != nil {
					return "", apiErr(503, "storage_unavailable", true)
				}
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
			if err := s.schemas.Validate("rotate-response.schema.json", responseBody); err != nil {
				return "", apiErr(503, "storage_unavailable", true)
			}
			previousKeyID, newKeyID = created.OldKeyID, created.NewKeyID
			return store.DispositionAccepted, nil
		})
	if err != nil {
		if kind := rejectionAuditKind(err); kind != "" {
			if _, aerr := s.store.AppendLedger(ctx, now, kind, node.NodeID, bodyHash); aerr != nil {
				return RotateResult{}, apiErr(503, "storage_unavailable", true)
			}
		}
		return RotateResult{}, mapServiceError(err)
	}
	// No post-commit config reread: the boundary writes the persisted rotate
	// response bytes verbatim when Response is non-empty.
	return RotateResult{Response: responseBody, PreviousKeyID: previousKeyID, NewKeyID: newKeyID,
		ConfigVersion: 0, ServerTime: now}, nil
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
	var responseBody []byte
	var configVersion int
	bodyHash := bodySHA(req.Body)
	attempt := protocol.Attempt{Gen: req.FieldsBootGen(), BootID: req.Fields.BootID, Seq: req.FieldsSeq(), Fingerprint: fp}
	_, _, err = s.store.ApplyIngest(ctx, node.NodeID, attempt, fp,
		func(tx *store.Tx) error {
			if err := s.authzKeyTx(ctx, tx, node.NodeID, req.Fields.KeyID, now, false); err != nil {
				return err
			}
			// Nonce ordering is before transport/high-water evaluation.
			status, err := tx.CheckOrInsertNonce(ctx, node.NodeID, req.Fields.Nonce, fp, now)
			if err != nil {
				return mapServiceError(err)
			}
			if status == store.NonceReuse {
				return apiErr(409, "nonce_reuse", false)
			}
			cfg, err := tx.ConfigTx(ctx, node.NodeID)
			if err != nil {
				return mapServiceError(err)
			}
			if err := validateClassConfigForClass(node.NodeClass, cfg); err != nil {
				return err
			}
			// OD-LT-14 revision-7 agent-config selection. The optional
			// collect.monitor_export switch may only be emitted when ALL hold:
			//   - the node is linux_vps;
			//   - the operator/admin source switch is enabled in the stored config;
			//   - the deployed contract set carries the rev-7 agent-config schema;
			//   - the node's latest authenticated snapshot agent.version is at
			//     least MinMonitorExportAgentVersion.
			// Otherwise the key is omitted entirely (rev-5/rev-6 strict decoders
			// require exactly the six frozen keys; the rev-7 schema makes
			// monitor_export OPTIONAL so six keys are valid for a rev-7 agent too).
			// The stored source switch stays true so enabling before a rev-7 agent
			// reports takes effect after its next authenticated snapshot.
			reportedVersion, err := tx.LastAgentVersionTx(ctx, node.NodeID)
			if err != nil {
				return mapServiceError(err)
			}
			includeMonitorExport := node.NodeClass == store.NodeClassLinuxVPS &&
				cfg.Sources["monitor_export"] &&
				s.schemas.Has(contract.AgentConfigRev7SchemaFile) &&
				agentVersionAtLeast(reportedVersion, MinMonitorExportAgentVersion)
			collect := cloneBoolMap(cfg.Sources)
			if includeMonitorExport {
				collect["monitor_export"] = true
			} else {
				delete(collect, "monitor_export")
			}
			doc := map[string]any{
				"v": 1, "node_id": node.NodeID, "event_id": node.EventID, "node_class": node.NodeClass,
				"config_version": cfg.ConfigVersion, "cadence_seconds": cfg.CadenceSeconds,
				"collect": collect, "device_salt": cfg.DeviceSalt, "server_time": now,
				"expected_inbound_tags": cfg.ExpectedInboundTags,
			}
			body, err := json.Marshal(doc)
			if err != nil {
				return apiErr(503, "storage_unavailable", true)
			}
			agentConfigSchema := "agent-config.schema.json"
			if includeMonitorExport {
				agentConfigSchema = contract.AgentConfigRev7SchemaFile
			}
			if err := s.schemas.Validate(agentConfigSchema, body); err != nil {
				// Validate the complete response BEFORE the high-water commit.
				return apiErr(503, "storage_unavailable", true)
			}
			responseBody = body
			configVersion = cfg.ConfigVersion
			return nil
		},
		func(tx *store.Tx) (store.ReportDisposition, error) { return store.DispositionAccepted, nil })
	if err != nil {
		if kind := rejectionAuditKind(err); kind != "" {
			if _, aerr := s.store.AppendLedger(ctx, now, kind, node.NodeID, bodyHash); aerr != nil {
				return ConfigResult{}, apiErr(503, "storage_unavailable", true)
			}
		}
		return ConfigResult{}, mapServiceError(err)
	}
	return ConfigResult{Body: responseBody, ConfigVersion: configVersion, ServerTime: now}, nil
}

// normalizeTrafficObservation extracts the optional rev-7 traffic observation
// from an already contract-validated snapshot body into the normalized storage
// projection. It stores only allowlisted fields, never the raw export JSON. A
// rev-5 body has no observation and normalizes to nil.
func normalizeTrafficObservation(collectedAt int64, body []byte, receivedAt int64) (*store.TrafficObservationRecord, error) {
	var doc struct {
		TrafficObservation json.RawMessage `json:"traffic_observation"`
	}
	raw := bytes.TrimSpace(body)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, apiErr(400, "invalid_request", false)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, apiErr(400, "invalid_request", false)
	}
	if len(doc.TrafficObservation) == 0 || bytes.Equal(bytes.TrimSpace(doc.TrafficObservation), []byte("null")) {
		return nil, nil
	}
	observation, err := contract.ValidateTrafficObservation(collectedAt, doc.TrafficObservation)
	if err != nil {
		return nil, err
	}
	record := &store.TrafficObservationRecord{
		Source: observation.Source, SourceEpoch: observation.SourceEpoch,
		Sequence: observation.Sequence, ObservedAt: observation.ObservedAt,
		CollectedAt: collectedAt, ReceivedAt: receivedAt,
		Availability: observation.Availability, Freshness: observation.Freshness,
		ActiveConnections: cloneInt64Pointer(observation.ActiveConnections),
		RateWindowSeconds: cloneFloat64Pointer(observation.RateWindowSeconds),
		CounterScope:      observation.CounterScope, Exactness: observation.Exactness,
		BytesEstimate: int64(len(doc.TrafficObservation)) + int64(len(observation.Inbounds))*128,
		Inbounds:      make([]store.TrafficInboundRecord, 0, len(observation.Inbounds)),
	}
	for _, inbound := range observation.Inbounds {
		record.Inbounds = append(record.Inbounds, store.TrafficInboundRecord{
			InboundTag: inbound.InboundTag, Kind: inbound.Kind, ObservedAt: inbound.ObservedAt,
			Availability: inbound.Availability, Quality: inbound.Quality,
			UplinkObservedLowerBoundBytes:   cloneInt64Pointer(inbound.UplinkObservedLowerBoundBytes),
			DownlinkObservedLowerBoundBytes: cloneInt64Pointer(inbound.DownlinkObservedLowerBoundBytes),
			UplinkObservedRateBps:           cloneFloat64Pointer(inbound.UplinkObservedRateBps),
			DownlinkObservedRateBps:         cloneFloat64Pointer(inbound.DownlinkObservedRateBps),
			ActiveConnections:               inbound.ActiveConnections,
		})
	}
	return record, nil
}

func cloneInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneFloat64Pointer(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

// enforceExpectedInboundTags binds a Linux snapshot's protocol/traffic inbound
// tags to the center-managed allowlist for that node/event. Unknown tags are
// rejected at the boundary rather than stored/displayed. Revision 7 additionally
// binds the traffic_observation inbounds: every tag must be in the allowlist with
// the configured kind, and an "ok" observation must cover every expected tag so
// an agent cannot claim full observation while omitting a configured inbound.
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
		TrafficObservation *struct {
			Availability string `json:"availability"`
			Inbounds     []struct {
				InboundTag string `json:"inbound_tag"`
				Kind       string `json:"kind"`
			} `json:"inbounds"`
		} `json:"traffic_observation"`
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
	if snap.TrafficObservation != nil {
		seen := make(map[string]bool, len(snap.TrafficObservation.Inbounds))
		for _, inbound := range snap.TrafficObservation.Inbounds {
			kind, ok := allowed[inbound.InboundTag]
			if !ok || kind != inbound.Kind || seen[inbound.InboundTag] {
				return apiErr(400, "invalid_request", false)
			}
			seen[inbound.InboundTag] = true
		}
		if snap.TrafficObservation.Availability == "ok" && len(seen) != len(allowed) {
			return apiErr(400, "invalid_request", false)
		}
	}
	return nil
}

func validateClassConfigForClass(nodeClass string, cfg store.NodeConfig) error {
	if cfg.Sources == nil || (len(cfg.Sources) != 6 && len(cfg.Sources) != 7) {
		return apiErr(503, "storage_unavailable", true)
	}
	if cfg.CadenceSeconds < 30 || cfg.CadenceSeconds > 300 || cfg.ConfigVersion < 1 {
		return apiErr(503, "storage_unavailable", true)
	}
	switch nodeClass {
	case store.NodeClassLinuxVPS:
		if cfg.Sources["terminal"] || cfg.Sources["mihomo_api"] || len(cfg.ExpectedInboundTags) == 0 {
			return apiErr(503, "storage_unavailable", true)
		}
	case store.NodeClassWindowsTerminal:
		if cfg.Sources["services"] || cfg.Sources["singbox_api"] || cfg.Sources["monitor_export"] || len(cfg.ExpectedInboundTags) != 0 {
			return apiErr(503, "storage_unavailable", true)
		}
	default:
		return apiErr(503, "storage_unavailable", true)
	}
	return nil
}

// cloneBoolMap returns a defensive copy of a source-switch map.
func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	return out
}

// validateReportSources enforces the center-managed source switches while keeping
// legal old spool data (collected at/before the config update) and honest
// unavailable/null/empty states acceptable after a switch is disabled.
func validateReportSources(nodeClass, reportType string, body []byte, sources map[string]bool) error {
	var availability map[string]string
	switch reportType {
	case "snapshot":
		var doc struct {
			Availability map[string]string          `json:"availability"`
			System       map[string]json.RawMessage `json:"system"`
			Services     []json.RawMessage          `json:"services"`
			Protocols    []json.RawMessage          `json:"protocols"`
			Traffic      []json.RawMessage          `json:"traffic"`
			Clients      json.RawMessage            `json:"clients"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return apiErr(400, "invalid_request", false)
		}
		availability = doc.Availability
		check := func(source, key string) error {
			if sources[source] {
				return nil
			}
			if availability[key] != "unavailable" {
				return apiErr(400, "invalid_request", false)
			}
			return nil
		}
		if err := check("system", "system"); err != nil {
			return err
		}
		if err := check("services", "services"); err != nil {
			return err
		}
		if err := check("singbox_api", "protocols"); err != nil {
			return err
		}
		if err := check("singbox_api", "traffic"); err != nil {
			return err
		}
		if err := check("singbox_api", "clients"); err != nil {
			return err
		}
		if nodeClass == store.NodeClassWindowsTerminal {
			var term struct {
				Terminal *struct {
					Selection struct {
						Availability string `json:"availability"`
					} `json:"selection"`
					ActiveConnections struct {
						Availability string `json:"availability"`
					} `json:"active_connections"`
				} `json:"terminal"`
			}
			if err := json.Unmarshal(body, &term); err != nil {
				return apiErr(400, "invalid_request", false)
			}
			if term.Terminal == nil {
				// No terminal observation object: legal (the frozen snapshot
				// schema allows honest absence). This is the default Windows
				// config case with all terminal sources disabled.
				return nil
			}
			if !sources["terminal"] && !sources["mihomo_api"] {
				// Any real terminal/controller observation requires at least one
				// corresponding source authorization.
				return apiErr(400, "invalid_request", false)
			}
			// selection and active_connections are independently authorized:
			// selection is a terminal-source observation; active_connections is
			// real Controller data and requires mihomo_api. A disabled source must
			// report honest unavailable/null, never "ok" observation data.
			if !sources["terminal"] && term.Terminal.Selection.Availability != "unavailable" {
				return apiErr(400, "invalid_request", false)
			}
			if !sources["mihomo_api"] && term.Terminal.ActiveConnections.Availability != "unavailable" {
				return apiErr(400, "invalid_request", false)
			}
		}
	case "metrics":
		var doc struct {
			Availability map[string]string `json:"availability"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return apiErr(400, "invalid_request", false)
		}
		// Metrics do not carry per-source tags; historical samples are accepted when
		// collected before the config update. For current samples, disabling a source
		// requires the documented unavailable state rather than fabricated data.
		for source, key := range map[string]string{"system": "system", "services": "services", "singbox_api": "protocols"} {
			if !sources[source] && doc.Availability[key] != "unavailable" {
				return apiErr(400, "invalid_request", false)
			}
		}
	case "events":
		// Generic agent/diagnostic events remain legal when event collection is
		// disabled; service/protocol/terminal-specific events need their source.
		var doc struct {
			Events []struct {
				Kind string `json:"kind"`
			} `json:"events"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return apiErr(400, "invalid_request", false)
		}
		for _, e := range doc.Events {
			switch e.Kind {
			case "service_restart", "service_failure":
				if !sources["services"] {
					return apiErr(400, "invalid_request", false)
				}
			case "protocol_outage", "protocol_recovery":
				if !sources["singbox_api"] {
					return apiErr(400, "invalid_request", false)
				}
			case "terminal_route_changed", "terminal_source_unavailable":
				if !sources["terminal"] {
					return apiErr(400, "invalid_request", false)
				}
			}
		}
	}
	return nil
}

// validateMetricEventTagBindings enforces center expected_inbound_tags on event
// detail objects that carry an inbound_tag (metrics have no inbound fields).
func validateMetricEventTagBindings(nodeClass, reportType string, body []byte, tags []store.InboundTag) error {
	if reportType != "events" || nodeClass != store.NodeClassLinuxVPS {
		return nil
	}
	allowed := make(map[string]string, len(tags))
	for _, t := range tags {
		allowed[t.InboundTag] = t.Kind
	}
	var doc struct {
		Events []struct {
			Detail map[string]json.RawMessage `json:"detail"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return apiErr(400, "invalid_request", false)
	}
	for _, e := range doc.Events {
		rawTag, ok := e.Detail["inbound_tag"]
		if !ok {
			continue
		}
		var tag string
		if err := json.Unmarshal(rawTag, &tag); err != nil {
			return apiErr(400, "invalid_request", false)
		}
		kind, ok := allowed[tag]
		if !ok {
			return apiErr(400, "invalid_request", false)
		}
		if rawKind, ok := e.Detail["kind"]; ok {
			var k string
			if err := json.Unmarshal(rawKind, &k); err != nil || k != kind {
				return apiErr(400, "invalid_request", false)
			}
		}
	}
	return nil
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
