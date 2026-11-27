# UM-B3 sing-box service.api authorization and traffic audit

- Status: **investigation complete; source DISABLED.** This document is
  evidence for the P1-10 server-side authorization gate and must not be read as
  a production approval.
- Tested release: **sing-box 1.14.5** (`go1.27.4 windows/amd64`,
  revision `a6844a780ba173e189a018d0ac62df67cd50b8e9` at the time of the
  isolated lab), in a disposable synthetic configuration only.
- Protocol source: `SagerNet/sing-box` v1.14.5
  `daemon/started_service.proto` (raw URL below). The repository has no
  vendored proto; the client pins the v1.14 field numbers used by the
  `StartedService/SubscribeConnections` stream.

## 1. Credential capability

The `service.api` listener authenticates with a single service secret. That
secret authorizes the whole `StartedService` gRPC service, which includes
mutating/control RPCs, for example:

- `ClearLogs`
- `SetClashMode`
- `SelectOutbound`
- `SetGroupExpand`
- `CloseConnection`
- `CloseAllConnections`
- `StartNetworkQualityTest`
- `StartSTUNTest`
- `SetTailscaleExitNode`
- `TailscaleLogout`
- `MarkTaildropInboxRead`
- `DeleteTaildropFile`
- `CancelTaildropReceiving`
- `SubmitOpenConnectAuthResponse` / `SubmitOpenVPNChallengeResponse`

The read-only stream we use (`SubscribeConnections`) is only one method of a
write-capable service. **The credential is therefore not a read-only
authorization**, even if the agent never calls a mutating method. The B3 agent
uses exactly the subscription stream and performs no write RPC, but that is an
implementation property, not an authorization proof.

Source: <https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.5/daemon/started_service.proto>

## 2. Traffic semantics

- `SubscribeConnections` delivers `NEW`/`UPDATE`/`CLOSED` events. A `Connection`
  carries active `uplink`/`downlink` and per-connection `uplinkTotal`/
  `downlinkTotal`.
- The API has **no per-inbound daemon-lifetime counter**. The aggregate
  `SubscribeStatus` stream has daemon-level `uplinkTotal`/`downlinkTotal`, but
  the frozen UM traffic projection is per authorized inbound/protocol; an
  aggregate cannot be attributed to the expected inbound tags.
- The B3 accumulator can report a probe-observed cumulative **lower bound**
  (active authoritative counters plus finalized closed/abandoned lifecycles
  banked once, with reset replay accounting), but it cannot prove exactness.
  `TotalsExact=false` is exposed internally; the frozen traffic schema has no
  lower-bound/exactness representation.
- Therefore B3 reports `traffic=unavailable` with an empty traffic array for
  both official service.api and the legacy Clash compatibility path. It does
  not place active-connection bytes or a lower bound into `uplink_total_bytes`/
  `downlink_total_bytes`.
- Protocol state/active-connection counts derived from the connection stream
  remain usable as explicit observations when the source is authorized.

## 3. Version/matrix status

| Release | Isolated service.api stream tested | Notes |
| --- | --- | --- |
| 1.14.5 | yes, active `mixed` connection and real center/SQLite snapshot | field numbers and stream path verified |
| other 1.14.x | not tested | source disabled; no compatibility claim |
| earlier/later major/minor | not tested | no compatibility claim |

The reproducible lab harness is `um/deploy/lab/singbox-serviceapi-lab.sh`
(Windows PowerShell variant may be added by the lab workflow); it uses the
official release binary, a synthetic loopback API, and a local echo target.

## 4. Authorization conclusion / decision

- **P1-10 authorization audit: FAIL / cannot be proven** for the tested
  release: the one credential is write-capable.
- `collect.singbox_api` stays **disabled/unavailable by default** and no
  credential is accepted or wired from environment variables, a center switch
  or a local credential path in this release. The legacy environment variables
  are inert and covered by a regression test.
- The implemented client is retained for isolated lab and future contract work
  only; it is not enabled by center config or environment.
- No production sing-box configuration, permission or credential was changed.
- R2/R1 Windows work does not authorize the Linux sing-box source.
