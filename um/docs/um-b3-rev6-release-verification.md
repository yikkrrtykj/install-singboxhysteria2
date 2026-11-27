# UM-B3 rev-6 contract release verification

- Date: 2026-11-27/28 (Europe/Istanbul)
- Tracking Issue: #127 (OPEN)
- B3 PR: #131 (Draft; no merge authorization)
- Contract release PR: #132 (MERGED)

## Rev-6 publication record

| Item | Value |
| --- | --- |
| Release PR | #132 (`docs(um-127): rev-6 contract release — power-loss generation overlay/fixture`) |
| Release head | `1fc7b052d1d67787c7777550fa21de5ccaf6572f` (tree `1057b027b9d6d0e5b805bf93704ba1e568188fd8`) |
| Base | `54efc81c0f2b72f61e4b70e7aaad1e0d4e41e411` |
| Merge commit | `a5ee4d8b0d11f15595c14db03d1f6df47de34868` |
| Merge parents | `54efc81c0f2b72f61e4b70e7aaad1e0d4e41e411`, `1fc7b052d1d67787c7777550fa21de5ccaf6572f` |
| Merge tree | `1057b027b9d6d0e5b805bf93704ba1e568188fd8` (identical to release head tree) |
| Merge type | normal Merge Commit; no squash/rebase/force-push |
| Owner decision | `docs/um/um-127/10-owner-decisions-rev6.md` (2026-11-27, limited scope) |
| Independent review | PASS/ACCEPT on `1fc7b052`; recorded on PR #132 |
| Exact-head PR checks | 25/25 PASS |
| Main CI | **25/25 PASS** on the exact merge commit after recording the known external `windows-exe` process-tree flake and a successful rerun |
| Status | **REV-6 PUBLISHED / FROZEN / VERIFIED** |

The rev-5 normative file, 10 schemas, signed vectors, negative vectors and the
REC fixture were byte-unchanged by the release; rev-6 is an additive normative
overlay plus fixture. The merge-commit CI includes the repository's required
checks. The rerun is recorded as an external harness flake, not a code/test
weakening; the same exact merge commit is green.

## Normative artifacts

- `docs/um/um-a/04-node-protocol-v1.rev6.md` — normative rev-6 overlay.
- `docs/um/contracts/v1/power-loss-generation.rev6.json` — formal executable
  fixture (AMEND-REC-27-A..F).
- `docs/um/um-127/10-owner-decisions-rev6.md` — OD-P3/OD-P7/Linux sing-box/
  power-loss Owner decisions and limits.

## B3 synchronization

PR #131 was synchronized by a normal merge of `origin/main` into
`codex/um-b3-agents` (no rebase/force-push), creating merge commit
`3259b51d719bde059f40cc2b7dd01f5f1175bb0f` (tree
`c3dacc31d0a3f9f61f305993d2f2aa3bd52baa0a`). The rev-6 overlay/fixture are now
the normative basis for B3 restart/power-loss acceptance. The final B3 HEAD,
exact CI and lab run are appended below when verified.

## Executable rev-6 REC results

- AMEND-REC-27-A: real same-runtime exact retry through center HTTP/SQLite and
  persisted agent spool → `duplicate`, high-water unchanged, no second copy.
- AMEND-REC-27-B: real persisted agent plus process-level crash/restart harness
  → new generation/boot, same report_id/body, first new-generation report
  `duplicate`, new high-water committed atomically, no second stored copy.
- AMEND-REC-27-C: real late retired-generation request → `stale_boot_generation`,
  no state change.
- AMEND-REC-27-D: real `um-agent status` against persisted state → command exit 0,
  state tree hash and generation/seq unchanged; `InspectState` creates no
  spool/quarantine.
- AMEND-REC-27-E: real same-generation/different-boot request →
  `boot_identity_conflict`, no state change.
- AMEND-REC-27-F: real consecutive offline restarts within `MAX_BOOT_GAP` →
  accepted new-generation contact, high-water committed, gap audit chain valid.

## Remaining limits

- Linux `singbox_api` remains disabled/unavailable; v1.14.5 authorization audit
  FAIL stands. Reality/Hysteria2 real traffic collection is not a PASS.
- R1 is isolated-lab authorized; production enablement HOLD.
- OD-P7 production account/credential policy remains Owner/deployment scope.
- PR #131 remains Draft; no merge authorization is granted by this release.
