package protocol

import (
	"errors"
	"fmt"
	"testing"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/wire"
)

// Boot ids and fingerprints are opaque transport identity strings at this
// layer; internal/wire owns their grammar and authentication.
const (
	bootA = "boot-a"
	bootB = "boot-b"

	fp1   = "fp-1"
	fp2   = "fp-2"
	fp3   = "fp-3"
	fp4   = "fp-4"
	fp5   = "fp-5"
	fpMax = "fp-max"
	fpBad = "fp-forged"
)

func seqPtr(v uint64) *uint64 { return &v }

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name         string
		cur          Boot
		attempt      Attempt
		opts         Options
		want         Result
		wantErrField string
	}{
		{
			name:    "enrollment first contact gen 1 seq 1 accepted",
			cur:     Boot{},
			attempt: Attempt{Gen: 1, BootID: bootA, Seq: 1, Fingerprint: fp1},
			want: Result{
				Outcome:            Accepted,
				Gap:                1,
				NextBoot:           Boot{HighestGen: 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
				NextSeq:            seqPtr(2),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "normal restart gen+1 seq 1 accepted",
			cur:     Boot{HighestGen: 1, BootID: bootA, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 2, BootID: bootB, Seq: 1, Fingerprint: fp5},
			want: Result{
				Outcome:            Accepted,
				Gap:                1,
				NextBoot:           Boot{HighestGen: 2, BootID: bootB, LastSeq: 1, LastFingerprint: fp5},
				NextSeq:            seqPtr(2),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "new generation first contact seq>1 accepted and sets last seq",
			cur:     Boot{HighestGen: 1, BootID: bootA, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 2, BootID: bootB, Seq: 9, Fingerprint: fp2},
			want: Result{
				Outcome:            Accepted,
				Gap:                1,
				NextBoot:           Boot{HighestGen: 2, BootID: bootB, LastSeq: 9, LastFingerprint: fp2},
				NextSeq:            seqPtr(10),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "enrollment first contact seq>1 accepted with audited gap",
			cur:     Boot{},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 7, Fingerprint: fp4},
			want: Result{
				Outcome:            Accepted,
				Gap:                2,
				AuditGap:           true,
				NextBoot:           Boot{HighestGen: 2, BootID: bootA, LastSeq: 7, LastFingerprint: fp4},
				NextSeq:            seqPtr(8),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "generation gap 2 accepted and audited",
			cur:     Boot{HighestGen: 3, BootID: bootA, LastSeq: 2, LastFingerprint: fp2},
			attempt: Attempt{Gen: 5, BootID: bootB, Seq: 1, Fingerprint: fp3},
			want: Result{
				Outcome:            Accepted,
				Gap:                2,
				AuditGap:           true,
				NextBoot:           Boot{HighestGen: 5, BootID: bootB, LastSeq: 1, LastFingerprint: fp3},
				NextSeq:            seqPtr(2),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "generation gap 65535 boundary accepted and audited",
			cur:     Boot{HighestGen: 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
			attempt: Attempt{Gen: 1 + wire.MaxBootGap, BootID: bootB, Seq: 1, Fingerprint: fp2},
			want: Result{
				Outcome:            Accepted,
				Gap:                wire.MaxBootGap,
				AuditGap:           true,
				NextBoot:           Boot{HighestGen: 1 + wire.MaxBootGap, BootID: bootB, LastSeq: 1, LastFingerprint: fp2},
				NextSeq:            seqPtr(2),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "generation gap 65536 rejected as boot identity conflict",
			cur:     Boot{HighestGen: 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
			attempt: Attempt{Gen: 1 + wire.MaxBootGap + 1, BootID: bootB, Seq: 1, Fingerprint: fp2},
			want: Result{
				Outcome:  BootIdentityConflict,
				NextBoot: Boot{HighestGen: 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
			},
		},
		{
			name:    "same generation different boot id conflict",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			attempt: Attempt{Gen: 2, BootID: bootB, Seq: 4, Fingerprint: fp4},
			want: Result{
				Outcome:  BootIdentityConflict,
				NextBoot: Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			},
		},
		{
			name:    "stale generation never reactivated",
			cur:     Boot{HighestGen: 5, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			attempt: Attempt{Gen: 4, BootID: bootA, Seq: 9, Fingerprint: fp2},
			want: Result{
				Outcome:  StaleBootGeneration,
				NextBoot: Boot{HighestGen: 5, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			},
		},
		{
			name:    "stale generation is rejected even with exact known seq fingerprint",
			cur:     Boot{HighestGen: 5, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 4, BootID: bootA, Seq: 3, Fingerprint: fp3},
			opts:    Options{SeqFingerprints: map[uint64]string{3: fp3}},
			want: Result{
				Outcome:  StaleBootGeneration,
				NextBoot: Boot{HighestGen: 5, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			},
		},
		{
			name:    "same generation seq advances accepted",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 4, Fingerprint: fp4},
			want: Result{
				Outcome:            Accepted,
				NextBoot:           Boot{HighestGen: 2, BootID: bootA, LastSeq: 4, LastFingerprint: fp4},
				NextSeq:            seqPtr(5),
				HighWaterCommitted: true,
			},
		},
		{
			name:    "same generation same seq same fingerprint duplicate",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 3, Fingerprint: fp3},
			want: Result{
				Outcome:  Duplicate,
				NextBoot: Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
				NextSeq:  seqPtr(4),
			},
		},
		{
			name:    "same generation same seq different fingerprint conflict",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 3, Fingerprint: fpBad},
			want: Result{
				Outcome:  SequenceConflict,
				NextBoot: Boot{HighestGen: 2, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			},
		},
		{
			name:    "lower seq exact known fingerprint duplicate",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 2, Fingerprint: fp2},
			opts:    Options{SeqFingerprints: map[uint64]string{2: fp2}},
			want: Result{
				Outcome:  Duplicate,
				NextBoot: Boot{HighestGen: 2, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
				NextSeq:  seqPtr(6),
			},
		},
		{
			name:    "lower seq unknown fingerprint conflict",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 2, Fingerprint: fpBad},
			opts:    Options{SeqFingerprints: map[uint64]string{2: fp2}},
			want: Result{
				Outcome:  SequenceConflict,
				NextBoot: Boot{HighestGen: 2, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			},
		},
		{
			name:    "lower seq missing fingerprint history conflict",
			cur:     Boot{HighestGen: 2, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 2, BootID: bootA, Seq: 2, Fingerprint: fp2},
			want: Result{
				Outcome:  SequenceConflict,
				NextBoot: Boot{HighestGen: 2, BootID: bootA, LastSeq: 5, LastFingerprint: fp5},
			},
		},
		{
			name:    "numeric max seq accepted with exhausted next seq",
			cur:     Boot{HighestGen: 3, BootID: bootA, LastSeq: 10, LastFingerprint: fp1},
			attempt: Attempt{Gen: 3, BootID: bootA, Seq: wire.MaxNumeric, Fingerprint: fpMax},
			want: Result{
				Outcome:            Accepted,
				NextBoot:           Boot{HighestGen: 3, BootID: bootA, LastSeq: wire.MaxNumeric, LastFingerprint: fpMax},
				HighWaterCommitted: true,
			},
		},
		{
			name:    "numeric max seq duplicate has exhausted next seq",
			cur:     Boot{HighestGen: 3, BootID: bootA, LastSeq: wire.MaxNumeric, LastFingerprint: fpMax},
			attempt: Attempt{Gen: 3, BootID: bootA, Seq: wire.MaxNumeric, Fingerprint: fpMax},
			want: Result{
				Outcome:  Duplicate,
				NextBoot: Boot{HighestGen: 3, BootID: bootA, LastSeq: wire.MaxNumeric, LastFingerprint: fpMax},
			},
		},
		{
			name:    "numeric max generation accepted at gap 1",
			cur:     Boot{HighestGen: wire.MaxNumeric - 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
			attempt: Attempt{Gen: wire.MaxNumeric, BootID: bootB, Seq: 1, Fingerprint: fp2},
			want: Result{
				Outcome:            Accepted,
				Gap:                1,
				NextBoot:           Boot{HighestGen: wire.MaxNumeric, BootID: bootB, LastSeq: 1, LastFingerprint: fp2},
				NextSeq:            seqPtr(2),
				HighWaterCommitted: true,
			},
		},
		{
			name:         "gen zero is a validation error",
			attempt:      Attempt{Gen: 0, BootID: bootA, Seq: 1, Fingerprint: fp1},
			wantErrField: "gen",
		},
		{
			name:         "gen above numeric max is a validation error",
			attempt:      Attempt{Gen: wire.MaxNumeric + 1, BootID: bootA, Seq: 1, Fingerprint: fp1},
			wantErrField: "gen",
		},
		{
			name:         "seq zero is a validation error",
			attempt:      Attempt{Gen: 1, BootID: bootA, Seq: 0, Fingerprint: fp1},
			wantErrField: "seq",
		},
		{
			name:         "seq above numeric max is a validation error",
			attempt:      Attempt{Gen: 1, BootID: bootA, Seq: wire.MaxNumeric + 1, Fingerprint: fp1},
			wantErrField: "seq",
		},
		{
			name:         "corrupt current highest for gen is a validation error",
			cur:          Boot{HighestGen: wire.MaxNumeric + 1},
			attempt:      Attempt{Gen: 1, BootID: bootA, Seq: 1, Fingerprint: fp1},
			wantErrField: "highest_gen",
		},
		{
			name:         "corrupt current last seq is a validation error",
			cur:          Boot{HighestGen: 1, LastSeq: wire.MaxNumeric + 1},
			attempt:      Attempt{Gen: 1, BootID: bootA, Seq: 1, Fingerprint: fp1},
			wantErrField: "last_seq",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.cur, tc.attempt, tc.opts)
			if tc.wantErrField != "" {
				checkValidationError(t, err, tc.wantErrField)
				if got != (Result{}) {
					t.Fatalf("Result on validation error = %+v, want zero Result", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Evaluate() unexpected error: %v", err)
			}
			checkResult(t, got, tc.want)
		})
	}
}

func TestAckNextSeq(t *testing.T) {
	tests := []struct {
		name    string
		lastSeq uint64
		wantNil bool
		want    uint64
	}{
		{name: "zero", lastSeq: 0, wantNil: false, want: 1},
		{name: "normal", lastSeq: 41, wantNil: false, want: 42},
		{name: "below numeric max", lastSeq: wire.MaxNumeric - 1, wantNil: false, want: wire.MaxNumeric},
		{name: "at numeric max generation exhausted", lastSeq: wire.MaxNumeric, wantNil: true},
		{name: "above numeric max generation exhausted", lastSeq: wire.MaxNumeric + 1, wantNil: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AckNextSeq(tc.lastSeq)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("AckNextSeq(%d) = %d, want nil", tc.lastSeq, *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("AckNextSeq(%d) = nil, want %d", tc.lastSeq, tc.want)
			}
			if *got != tc.want {
				t.Fatalf("AckNextSeq(%d) = %d, want %d", tc.lastSeq, *got, tc.want)
			}
		})
	}
}

const (
	rotNodeID   = "00000000-0000-4000-8000-000000000001"
	rotNonce    = "nonce-rotation-1"
	rotOldKeyID = "key-0123abcd"
	rotBodyHash = "body-sha256"
)

type rotateArgs struct {
	nodeID     string
	nonce      string
	oldKeyID   string
	bodySHA256 string
}

func matchedRotateArgs() rotateArgs {
	return rotateArgs{nodeID: rotNodeID, nonce: rotNonce, oldKeyID: rotOldKeyID, bodySHA256: rotBodyHash}
}

func awaitingProofIntent(expiresAtUnix int64) RotateIntent {
	return RotateIntent{
		NodeID:        rotNodeID,
		Nonce:         rotNonce,
		OldKeyID:      rotOldKeyID,
		BodySHA256:    rotBodyHash,
		State:         RotationAwaitingProof,
		ExpiresAtUnix: expiresAtUnix,
	}
}

func confirmedIntent(expiresAtUnix int64) RotateIntent {
	intent := awaitingProofIntent(expiresAtUnix)
	intent.State = RotationConfirmed
	return intent
}

func abortedIntent(expiresAtUnix int64) RotateIntent {
	intent := awaitingProofIntent(expiresAtUnix)
	intent.State = RotationAborted
	return intent
}

func adminRevokedIntent(expiresAtUnix int64) RotateIntent {
	intent := awaitingProofIntent(expiresAtUnix)
	intent.State = RotationAdminRevoked
	return intent
}

func TestEvaluateRotateRetry(t *testing.T) {
	// A matched awaiting_proof rotation that is not yet expired.
	matchingIntent := awaitingProofIntent(2000)

	tests := []struct {
		name         string
		cur          Boot
		attempt      Attempt
		intent       RotateIntent
		args         rotateArgs
		nowUnix      int64
		opts         Options
		want         RotateVerdict
		wantErrField string
	}{
		{
			name:    "matched awaiting proof across generation gap replays and commits high-water",
			cur:     Boot{HighestGen: 1, BootID: bootA, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 1, Fingerprint: fp5},
			intent:  matchingIntent,
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					Gap:                2,
					AuditGap:           true,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 1, LastFingerprint: fp5},
					NextSeq:            seqPtr(2),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				ReplayAllowed: true,
			},
		},
		{
			name:    "matched duplicate replays without high-water commit",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  matchingIntent,
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:  Duplicate,
					NextBoot: Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:  seqPtr(6),
				},
				IntentMatched: true,
				ReplayAllowed: true,
			},
		},
		{
			name:    "matched confirmed intent denies replay after its expiry timestamp",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  confirmedIntent(900),
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				Confirmed:     true,
			},
		},
		{
			name:    "matched confirmed intent denies replay before its expiry timestamp",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  confirmedIntent(2000),
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				Confirmed:     true,
			},
		},
		{
			name:    "matched admin revoked intent denies replay",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  adminRevokedIntent(2000),
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				AdminRevoked:  true,
			},
		},
		{
			name:    "stale generation denies replay even if intent matches",
			cur:     Boot{HighestGen: 5, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
			attempt: Attempt{Gen: 4, BootID: bootA, Seq: 4, Fingerprint: fp4},
			intent:  matchingIntent,
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:  StaleBootGeneration,
					NextBoot: Boot{HighestGen: 5, BootID: bootA, LastSeq: 3, LastFingerprint: fp3},
				},
			},
		},
		{
			name:    "sequence conflict denies replay even if intent matches",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 2, Fingerprint: fpBad},
			intent:  matchingIntent,
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			opts:    Options{SeqFingerprints: map[uint64]string{2: fp2}},
			want: RotateVerdict{
				Transport: Result{
					Outcome:  SequenceConflict,
					NextBoot: Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
				},
			},
		},
		{
			name:    "boot identity conflict denies replay even if intent matches",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
			attempt: Attempt{Gen: 3, BootID: bootA, Seq: 6, Fingerprint: fp4},
			intent:  matchingIntent,
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:  BootIdentityConflict,
					NextBoot: Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
				},
			},
		},
		{
			name:    "generation gap above max denies replay even if intent matches",
			cur:     Boot{HighestGen: 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
			attempt: Attempt{Gen: 1 + wire.MaxBootGap + 1, BootID: bootB, Seq: 1, Fingerprint: fp2},
			intent:  matchingIntent,
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:  BootIdentityConflict,
					NextBoot: Boot{HighestGen: 1, BootID: bootA, LastSeq: 1, LastFingerprint: fp1},
				},
			},
		},
		{
			name:    "node id mismatch is nonce reuse",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  matchingIntent,
			args:    rotateArgs{nodeID: "00000000-0000-4000-8000-000000000002", nonce: rotNonce, oldKeyID: rotOldKeyID, bodySHA256: rotBodyHash},
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				NonceReuse: true,
			},
		},
		{
			name:    "nonce mismatch is nonce reuse",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  matchingIntent,
			args:    rotateArgs{nodeID: rotNodeID, nonce: "nonce-other", oldKeyID: rotOldKeyID, bodySHA256: rotBodyHash},
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				NonceReuse: true,
			},
		},
		{
			name:    "old key id mismatch is nonce reuse",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  matchingIntent,
			args:    rotateArgs{nodeID: rotNodeID, nonce: rotNonce, oldKeyID: "key-deadbeef", bodySHA256: rotBodyHash},
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				NonceReuse: true,
			},
		},
		{
			name:    "body sha256 mismatch is nonce reuse",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  matchingIntent,
			args:    rotateArgs{nodeID: rotNodeID, nonce: rotNonce, oldKeyID: rotOldKeyID, bodySHA256: "body-other"},
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				NonceReuse: true,
			},
		},
		{
			name:    "matched aborted intent maps to rotation_expired and is never nonce reuse",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  abortedIntent(2000),
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				Aborted:       true,
				Expired:       true,
			},
		},
		{
			name:    "expired awaiting proof intent denies replay",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  awaitingProofIntent(999),
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				Expired:       true,
			},
		},
		{
			name:    "expiry boundary equal is not expired",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent:  awaitingProofIntent(1000),
			args:    matchedRotateArgs(),
			nowUnix: 1000,
			want: RotateVerdict{
				Transport: Result{
					Outcome:            Accepted,
					NextBoot:           Boot{HighestGen: 3, BootID: bootB, LastSeq: 5, LastFingerprint: fp5},
					NextSeq:            seqPtr(6),
					HighWaterCommitted: true,
				},
				IntentMatched: true,
				ReplayAllowed: true,
			},
		},
		{
			name:    "unknown rotation state is a validation error",
			cur:     Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt: Attempt{Gen: 3, BootID: bootB, Seq: 5, Fingerprint: fp5},
			intent: func() RotateIntent {
				intent := awaitingProofIntent(2000)
				intent.State = RotationState("corrupted_state")
				return intent
			}(),
			args:         matchedRotateArgs(),
			nowUnix:      1000,
			wantErrField: "rotation_state",
		},
		{
			name:         "invalid attempt propagates validation error",
			cur:          Boot{HighestGen: 3, BootID: bootB, LastSeq: 4, LastFingerprint: fp4},
			attempt:      Attempt{Gen: 3, BootID: bootB, Seq: 0, Fingerprint: fp5},
			intent:       matchingIntent,
			args:         matchedRotateArgs(),
			nowUnix:      1000,
			wantErrField: "seq",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateRotateRetry(
				tc.cur, tc.attempt, tc.intent,
				tc.args.nodeID, tc.args.nonce, tc.args.oldKeyID, tc.args.bodySHA256,
				tc.nowUnix, tc.opts,
			)
			if tc.wantErrField != "" {
				checkValidationError(t, err, tc.wantErrField)
				if got != (RotateVerdict{}) {
					t.Fatalf("RotateVerdict on validation error = %+v, want zero verdict", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("EvaluateRotateRetry() unexpected error: %v", err)
			}
			checkRotateVerdict(t, got, tc.want)
		})
	}
}

func checkResult(t *testing.T, got, want Result) {
	t.Helper()
	if got.Outcome != want.Outcome {
		t.Errorf("Outcome = %q, want %q", got.Outcome, want.Outcome)
	}
	if got.Gap != want.Gap {
		t.Errorf("Gap = %d, want %d", got.Gap, want.Gap)
	}
	if got.AuditGap != want.AuditGap {
		t.Errorf("AuditGap = %t, want %t", got.AuditGap, want.AuditGap)
	}
	if got.NextBoot != want.NextBoot {
		t.Errorf("NextBoot = %+v, want %+v", got.NextBoot, want.NextBoot)
	}
	if got.HighWaterCommitted != want.HighWaterCommitted {
		t.Errorf("HighWaterCommitted = %t, want %t", got.HighWaterCommitted, want.HighWaterCommitted)
	}
	switch {
	case got.NextSeq == nil && want.NextSeq == nil:
	case got.NextSeq == nil || want.NextSeq == nil:
		t.Errorf("NextSeq = %s, want %s", nextSeqString(got.NextSeq), nextSeqString(want.NextSeq))
	case *got.NextSeq != *want.NextSeq:
		t.Errorf("NextSeq = %d, want %d", *got.NextSeq, *want.NextSeq)
	}
}

func checkRotateVerdict(t *testing.T, got, want RotateVerdict) {
	t.Helper()
	checkResult(t, got.Transport, want.Transport)
	if got.IntentMatched != want.IntentMatched {
		t.Errorf("IntentMatched = %t, want %t", got.IntentMatched, want.IntentMatched)
	}
	if got.Confirmed != want.Confirmed {
		t.Errorf("Confirmed = %t, want %t", got.Confirmed, want.Confirmed)
	}
	if got.Aborted != want.Aborted {
		t.Errorf("Aborted = %t, want %t", got.Aborted, want.Aborted)
	}
	if got.AdminRevoked != want.AdminRevoked {
		t.Errorf("AdminRevoked = %t, want %t", got.AdminRevoked, want.AdminRevoked)
	}
	if got.ReplayAllowed != want.ReplayAllowed {
		t.Errorf("ReplayAllowed = %t, want %t", got.ReplayAllowed, want.ReplayAllowed)
	}
	if got.Expired != want.Expired {
		t.Errorf("Expired = %t, want %t", got.Expired, want.Expired)
	}
	if got.NonceReuse != want.NonceReuse {
		t.Errorf("NonceReuse = %t, want %t", got.NonceReuse, want.NonceReuse)
	}
}

func checkValidationError(t *testing.T, err error, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error = %v (%T), want *ValidationError", err, err)
	}
	if ve.Field != wantField {
		t.Errorf("ValidationError.Field = %q, want %q", ve.Field, wantField)
	}
	if ve.Detail == "" || ve.Error() == "" {
		t.Errorf("validation error is not descriptive: %#v", ve)
	}
}

func nextSeqString(p *uint64) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprintf("%d", *p)
}
