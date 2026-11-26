// Package protocol implements the pure revision-5 UM recovery, ordering and
// rotation-intent decisions.
//
// It is deliberately free of I/O, persistence and ambient clocks: every
// function is a pure decision over state supplied by the caller (for rotation
// retries the caller also supplies the current time). The caller owns the
// transaction:
//
//   - For Evaluate, a Result with HighWaterCommitted set must be persisted
//     atomically together with the request's side effects, and the ACK may only
//     be sent after that commit. A rejected outcome must not change any state.
//   - For EvaluateRotateRetry the same holds gated by RotateVerdict.ReplayAllowed:
//     the persisted rotate response, the transport high-water and the
//     nonce/dedupe state commit together, and any failed transport or intent
//     check commits nothing.
//
// The frozen contract is docs/um/um-a/04-node-protocol-v1.md §5–§7.
package protocol

import (
	"fmt"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// Boot is the persisted authoritative transport high-water of one node: the
// highest accepted boot generation, the boot id that owns that generation, and
// the last accepted attempt of that generation. The enrollment state is the
// zero value (HighestGen 0, LastSeq 0); the first accepted request of the first
// generation then sets the baseline, and its seq may be greater than 1.
type Boot struct {
	HighestGen      uint64
	BootID          string
	LastSeq         uint64
	LastFingerprint string
}

// Attempt is one transport attempt as described by the signed headers and the
// request fingerprint. BootID and Fingerprint are opaque to this package; the
// caller has already authenticated them and computed the fingerprint.
type Attempt struct {
	Gen         uint64
	BootID      string
	Seq         uint64
	Fingerprint string
}

// Outcome is the frozen rev-5 transport classification of one attempt.
type Outcome string

const (
	// Accepted advances the transport high-water; the caller must commit
	// NextBoot (and NextSeq in the ACK) atomically with the request effects.
	Accepted Outcome = "accepted"
	// Duplicate is the idempotent retry of an already committed attempt (lost
	// ACK); the caller must not write data again and must not advance the
	// high-water, only return NextSeq.
	Duplicate Outcome = "duplicate"
	// StaleBootGeneration rejects a retired generation.
	StaleBootGeneration Outcome = "stale_boot_generation"
	// BootIdentityConflict rejects a same-generation boot id mismatch or a
	// generation jump above wire.MaxBootGap.
	BootIdentityConflict Outcome = "boot_identity_conflict"
	// SequenceConflict rejects a reused sequence number whose fingerprint does
	// not match the committed one.
	SequenceConflict Outcome = "sequence_conflict"
)

// Options carries decision inputs that are not part of the two core structs.
type Options struct {
	// SeqFingerprints is the exact-retry history for seq values below
	// Boot.LastSeq, keyed by sequence number and holding the committed
	// fingerprint of that attempt. It lets a delayed duplicate of an already
	// superseded attempt be recognised; a missing or different entry is a
	// SequenceConflict.
	SeqFingerprints map[uint64]string
}

// Result is the transport decision. NextBoot is the boot state after the
// decision: it equals cur for every rejected outcome, so persisting it is a
// no-op. NextSeq is the ACK next_seq value; it is nil for every outcome except
// Accepted and Duplicate, and for those it is nil only when the generation is
// numerically exhausted. HighWaterCommitted reports whether the caller must
// persist NextBoot (and the seq dedupe entry) in the same transaction as the
// request's side effects.
type Result struct {
	Outcome            Outcome
	Gap                uint64
	AuditGap           bool
	NextBoot           Boot
	NextSeq            *uint64
	HighWaterCommitted bool
}

// ValidationError is a typed, non-echoing input validation error. Field names
// the rejected input ("gen", "seq", "highest_gen" or "last_seq") and Detail
// describes the violated precondition without echoing the offending value, so
// callers may log it safely.
type ValidationError struct {
	Field  string
	Detail string
}

func (e *ValidationError) Error() string {
	return "protocol: invalid " + e.Field + ": " + e.Detail
}

// Evaluate classifies one transport attempt against the persisted boot
// high-water and returns the state transition the caller must commit.
//
// Frozen rev-5 rules:
//
//   - Attempt.Gen and Attempt.Seq must be in [1, wire.MaxNumeric]; zero or
//     out-of-range values are validation errors and no decision is made.
//   - gen < HighestGen: StaleBootGeneration. A retired generation is never
//     re-activated, even if an old report_id would look known.
//   - gen == HighestGen: the boot id must equal Boot.BootID, otherwise
//     BootIdentityConflict. With a matching boot id:
//     seq > LastSeq is Accepted and advances the high-water;
//     seq == LastSeq with the same fingerprint is a Duplicate (the previous
//     attempt committed but its ACK was lost), with a different fingerprint it
//     is a SequenceConflict;
//     seq < LastSeq is a Duplicate only when Options.SeqFingerprints holds the
//     exact committed fingerprint for that seq, and a SequenceConflict
//     otherwise.
//   - gen > HighestGen: gap := gen - HighestGen. A gap greater than
//     wire.MaxBootGap is a BootIdentityConflict with no state change. A bounded
//     gap is Accepted as the first contact of the new generation, even when its
//     first seq is greater than 1: the new boot state replaces the high-water
//     and gap > 1 is recorded as an audited generation gap.
//
// NextBoot is always the state after the decision. Only Accepted sets
// HighWaterCommitted; a Duplicate was already committed by the attempt that won
// the race, and rejected outcomes change nothing.
func Evaluate(cur Boot, a Attempt, opts Options) (Result, error) {
	if err := validateAttempt(a); err != nil {
		return Result{}, err
	}
	if err := validateBoot(cur); err != nil {
		return Result{}, err
	}

	if a.Gen < cur.HighestGen {
		return Result{Outcome: StaleBootGeneration, NextBoot: cur}, nil
	}
	if a.Gen == cur.HighestGen {
		return evaluateSameGeneration(cur, a, opts), nil
	}
	return evaluateNewGeneration(cur, a), nil
}

// AckNextSeq returns the ACK next_seq for a committed last sequence: lastSeq+1,
// or nil when the generation is numerically exhausted (lastSeq is already at
// wire.MaxNumeric), in which case the agent must not reuse a seq and must start
// a new generation.
func AckNextSeq(lastSeq uint64) *uint64 {
	if lastSeq >= wire.MaxNumeric {
		return nil
	}
	next := lastSeq + 1
	return &next
}

// evaluateSameGeneration applies the gen == HighestGen branch of Evaluate.
func evaluateSameGeneration(cur Boot, a Attempt, opts Options) Result {
	if a.BootID != cur.BootID {
		return Result{Outcome: BootIdentityConflict, NextBoot: cur}
	}
	switch {
	case a.Seq > cur.LastSeq:
		next := cur
		next.LastSeq = a.Seq
		next.LastFingerprint = a.Fingerprint
		return Result{
			Outcome:            Accepted,
			NextBoot:           next,
			NextSeq:            AckNextSeq(next.LastSeq),
			HighWaterCommitted: true,
		}
	case a.Seq == cur.LastSeq:
		if a.Fingerprint == cur.LastFingerprint {
			return duplicate(cur)
		}
		return Result{Outcome: SequenceConflict, NextBoot: cur}
	default:
		// A delayed attempt that was already superseded: only the exact
		// committed fingerprint for that seq is an idempotent retry.
		if fp, ok := opts.SeqFingerprints[a.Seq]; ok && fp == a.Fingerprint {
			return duplicate(cur)
		}
		return Result{Outcome: SequenceConflict, NextBoot: cur}
	}
}

// evaluateNewGeneration applies the gen > HighestGen branch of Evaluate.
func evaluateNewGeneration(cur Boot, a Attempt) Result {
	gap := a.Gen - cur.HighestGen
	if gap > wire.MaxBootGap {
		return Result{Outcome: BootIdentityConflict, NextBoot: cur}
	}
	next := Boot{
		HighestGen:      a.Gen,
		BootID:          a.BootID,
		LastSeq:         a.Seq,
		LastFingerprint: a.Fingerprint,
	}
	return Result{
		Outcome:            Accepted,
		Gap:                gap,
		AuditGap:           gap > 1,
		NextBoot:           next,
		NextSeq:            AckNextSeq(next.LastSeq),
		HighWaterCommitted: true,
	}
}

// duplicate is the no-change Duplicate result: the high-water was committed by
// the attempt that won the race, so the caller only echoes the current ACK.
func duplicate(cur Boot) Result {
	return Result{
		Outcome:  Duplicate,
		NextBoot: cur,
		NextSeq:  AckNextSeq(cur.LastSeq),
	}
}

func validateAttempt(a Attempt) error {
	if a.Gen == 0 || a.Gen > wire.MaxNumeric {
		return invalidRange("gen")
	}
	if a.Seq == 0 || a.Seq > wire.MaxNumeric {
		return invalidRange("seq")
	}
	return nil
}

func validateBoot(cur Boot) error {
	if cur.HighestGen > wire.MaxNumeric {
		return &ValidationError{
			Field:  "highest_gen",
			Detail: fmt.Sprintf("must not exceed %d", wire.MaxNumeric),
		}
	}
	if cur.LastSeq > wire.MaxNumeric {
		return &ValidationError{
			Field:  "last_seq",
			Detail: fmt.Sprintf("must not exceed %d", wire.MaxNumeric),
		}
	}
	return nil
}

func invalidRange(field string) error {
	return &ValidationError{
		Field:  field,
		Detail: fmt.Sprintf("must be in [1, %d]", wire.MaxNumeric),
	}
}

// RotationState is the persisted state of one rotation intent. The set is
// closed: any other persisted value is corruption and is reported as a
// ValidationError, never silently folded into another outcome.
type RotationState string

const (
	// RotationAwaitingProof is an intent whose rotate response was persisted
	// but whose proof has not been confirmed yet; it is replayable until
	// ExpiresAtUnix.
	RotationAwaitingProof RotationState = "awaiting_proof"
	// RotationConfirmed is an intent whose proof was confirmed (the new key is
	// active and the old key is revoked). An old-key retry must never be
	// re-authorized from this pure state machine; the caller must run
	// authentication and key/revocation state checks first.
	RotationConfirmed RotationState = "confirmed"
	// RotationAborted is an intent that was aborted before confirmation; a
	// retry maps to the rotation_expired cause and is never nonce_reuse.
	RotationAborted RotationState = "aborted"
	// RotationAdminRevoked is an intent whose new key was revoked by an
	// administrator; a retry maps to the revoked/rotation_expired cause.
	RotationAdminRevoked RotationState = "admin_revoked"
)

// RotateIntent is the persisted rotation record that a rotate retry replays.
// The nonce is a persisted intent key; NodeID, Nonce, OldKeyID and BodySHA256
// are matched as a set, and unchanged transport fields (sent_at, seq, boot_gen)
// are refreshed by the agent and fully revalidated by Evaluate.
type RotateIntent struct {
	NodeID        string
	Nonce         string
	OldKeyID      string
	BodySHA256    string
	State         RotationState
	ExpiresAtUnix int64
}

// RotateVerdict is the rotate-retry decision. Transport carries the always-run
// Evaluate result. IntentMatched reports that the persisted intent matched the
// request identity; Confirmed, Aborted and AdminRevoked report the matched
// intent's non-replayable state-class for the caller's mapping; Expired and
// NonceReuse expose the frozen 409 rotation_expired / nonce_reuse causes.
// ReplayAllowed is the single gate for replaying the persisted rotate response
// and committing Transport: it is true only for a matched, unexpired
// awaiting_proof intent.
type RotateVerdict struct {
	Transport     Result
	IntentMatched bool
	Confirmed     bool
	Aborted       bool
	AdminRevoked  bool
	ReplayAllowed bool
	Expired       bool
	NonceReuse    bool
}

// EvaluateRotateRetry decides whether a rotate request may replay its persisted
// response, applying the rev-5 rule that a rotation-intent replay never bypasses
// transport validation.
//
// This is a pure ordering/decision helper for use AFTER the caller has
// authenticated the request. It is NOT a complete identity or authentication
// API: request signatures, the node's key history, old-key state and
// revocation state are all caller-owned and are not verified here. A caller
// must never use a successful verdict to skip any signature, key-state or
// revocation check.
//
// The transport decision is computed first and is never skipped: a stale
// generation, a same-generation boot id mismatch, a gap above wire.MaxBootGap or
// a sequence conflict denies the replay regardless of how well the intent
// matches. Only when the transport outcome is Accepted or Duplicate is the
// persisted rotation intent consulted:
//
//   - the intent identity (node_id, nonce, old_key_id, body_sha256) must match
//     the request exactly; any mismatch is NonceReuse (a nonce is bound to
//     exactly one rotation intent), IntentMatched is false and the replay is
//     denied;
//   - a matched awaiting_proof intent whose ExpiresAtUnix is strictly before
//     nowUnix is Expired and denies the replay (the rotation_expired path); the
//     expiry timestamp is a second-level bound, so equality is not expired,
//     and a matched, unexpired awaiting_proof intent is the only state that
//     allows the replay;
//   - a matched aborted intent denies the replay with Aborted and Expired set
//     (the caller maps it to rotation_expired); it is never NonceReuse;
//   - a matched confirmed intent denies the replay with Confirmed set, before
//     and after its expiry timestamp: the old key is revoked and this pure
//     state machine did not verify key/revocation state, so it must not
//     re-authorize an old-key request;
//   - a matched admin_revoked intent denies the replay with AdminRevoked set;
//     the caller maps it to the revoked/rotation_expired cause;
//   - any other persisted state is corrupt: a typed ValidationError with field
//     "rotation_state" is returned instead of silently classifying it.
//
// The transport high-water is represented only by Transport. The caller commits
// it, the replayed rotate response and the nonce/dedupe state in one
// transaction, and only when ReplayAllowed is true. When ReplayAllowed is false
// nothing may be committed, even if Transport.HighWaterCommitted is set.
func EvaluateRotateRetry(cur Boot, a Attempt, intent RotateIntent, nodeID, nonce, oldKeyID, bodySHA256 string, nowUnix int64, opts Options) (RotateVerdict, error) {
	transport, err := Evaluate(cur, a, opts)
	if err != nil {
		return RotateVerdict{}, err
	}
	verdict := RotateVerdict{Transport: transport}
	if transport.Outcome != Accepted && transport.Outcome != Duplicate {
		return verdict, nil
	}

	if intent.NodeID != nodeID ||
		intent.Nonce != nonce ||
		intent.OldKeyID != oldKeyID ||
		intent.BodySHA256 != bodySHA256 {
		verdict.NonceReuse = true
		return verdict, nil
	}
	verdict.IntentMatched = true

	switch intent.State {
	case RotationAwaitingProof:
		if intent.ExpiresAtUnix < nowUnix {
			verdict.Expired = true
			return verdict, nil
		}
		verdict.ReplayAllowed = true
	case RotationConfirmed:
		verdict.Confirmed = true
	case RotationAborted:
		verdict.Aborted = true
		verdict.Expired = true
	case RotationAdminRevoked:
		verdict.AdminRevoked = true
	default:
		return RotateVerdict{}, &ValidationError{
			Field:  "rotation_state",
			Detail: "must be one of awaiting_proof, confirmed, aborted or admin_revoked",
		}
	}
	return verdict, nil
}
