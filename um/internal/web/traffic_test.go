package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

const (
	trafficEventA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	trafficEventB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	trafficNodeA  = "11111111-1111-4111-8111-111111111111"
	trafficNodeB  = "22222222-2222-4222-8222-222222222222"
)

// seedTrafficPoint inserts one normalized observation for a node/event series via
// the store test seed helper (the Web package cannot run the machine ingest).
func seedTrafficPoint(t *testing.T, tw *testWeb, eventID, nodeID, reportID, tag, kind string, observedAt, sequence int64, epochSeed string) {
	t.Helper()
	uplink := int64(1000 + observedAt%1000)
	downlink := int64(2000 + observedAt%1000)
	var rate *float64
	if tag == "vless-in" {
		value := 12.5
		rate = &value
	}
	active := int64(1)
	window := 60.0
	observation := &store.TrafficObservationRecord{
		Source: "monitor_readonly_export", SourceEpoch: strings.Repeat(epochSeed, 16), Sequence: sequence,
		ObservedAt: observedAt, CollectedAt: observedAt + 1, ReceivedAt: observedAt + 2,
		Availability: "ok", Freshness: "fresh", ActiveConnections: &active, RateWindowSeconds: &window,
		CounterScope: "observation_epoch", Exactness: "lower_bound", BytesEstimate: 512,
		Inbounds: []store.TrafficInboundRecord{{
			InboundTag: tag, Kind: kind, ObservedAt: observedAt, Availability: "ok", Quality: "lower_bound",
			UplinkObservedLowerBoundBytes: &uplink, DownlinkObservedLowerBoundBytes: &downlink,
			UplinkObservedRateBps: rate, ActiveConnections: 1,
		}},
	}
	if err := tw.store.SeedTrafficObservationForTest(context.Background(), store.SnapshotRecord{
		NodeID: nodeID, EventID: eventID, ReportID: reportID, CollectedAt: observedAt + 1,
		ReceivedAt: observedAt + 2, BodySHA256: "sha-" + reportID,
		Payload: []byte("{}"), TrafficObservation: observation,
	}); err != nil {
		t.Fatalf("seed traffic point %q: %v", reportID, err)
	}
}

func seedTrafficEvents(t *testing.T, tw *testWeb) int64 {
	t.Helper()
	now := time.Now()
	for _, eventID := range []string{trafficEventA, trafficEventB} {
		if _, err := tw.store.CreateEvent(context.Background(), eventID, eventID, now.Unix()); err != nil {
			t.Fatalf("create event %q: %v", eventID, err)
		}
	}
	observed := now.Unix()
	seedTrafficPoint(t, tw, trafficEventA, trafficNodeA, "a-first", "vless-in", "reality", observed-120, 1, "ab")
	seedTrafficPoint(t, tw, trafficEventA, trafficNodeA, "a-second", "vless-in", "reality", observed-60, 2, "ab")
	seedTrafficPoint(t, tw, trafficEventB, trafficNodeB, "b-only", "hy2-in", "hysteria2", observed-90, 1, "cd")
	return observed
}

// trafficUserLogin bootstraps/creates an account with the given role/scopes and
// completes the password+TOTP login, returning the active CSRF token.
func trafficUserLogin(t *testing.T, tw *testWeb, username, role string, scopes []string) string {
	t.Helper()
	now := time.Now()
	hash, err := umcauth.HashPassword(tw.password, umcauth.DefaultPasswordParams())
	if err != nil {
		t.Fatal(err)
	}
	var user store.AuthUser
	if role == store.AuthRolePlatformAdmin {
		user, err = tw.store.BootstrapAuthUser(context.Background(), username, hash, now.Unix())
		if err != nil {
			t.Fatalf("bootstrap platform admin: %v", err)
		}
	} else {
		if _, err := tw.store.BootstrapAuthUser(context.Background(), "owner", hash, now.Unix()); err != nil {
			t.Fatalf("bootstrap owner: %v", err)
		}
		user, err = tw.store.CreateAuthUser(context.Background(), store.AuthUserInput{
			Username: username, PasswordHash: hash, Role: role, EventIDs: scopes, Now: now.Unix(),
		})
		if err != nil {
			t.Fatalf("create %s: %v", role, err)
		}
	}
	secret, err := umcauth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := umcauth.Seal(tw.master, []byte(secret), []byte("umc-totp:"+user.UserID+":v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.store.SetAuthUserTOTP(context.Background(), user.UserID, sealed, 1, now.Unix()); err != nil {
		t.Fatalf("set TOTP: %v", err)
	}
	pre := tw.startContext(t)
	status, raw := tw.request(t, http.MethodPost, "/auth/login", pre,
		map[string]any{"username": username, "password": tw.password}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("login %s status=%d body=%s", username, status, raw)
	}
	pending, _ := decodeMap(t, raw)["csrf_token"].(string)
	code, err := umcauth.TOTPCode(secret, *tw.clock)
	if err != nil {
		t.Fatal(err)
	}
	status, raw = tw.request(t, http.MethodPost, "/auth/totp", pending, map[string]any{"code": code}, tw.jwt)
	if status != http.StatusOK {
		t.Fatalf("TOTP %s status=%d body=%s", username, status, raw)
	}
	csrf, _ := decodeMap(t, raw)["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("active CSRF missing for %s: %s", username, raw)
	}
	return csrf
}

func getTraffic(t *testing.T, tw *testWeb, path string) (int, []byte) {
	t.Helper()
	return tw.request(t, http.MethodGet, path, "", nil, tw.jwt)
}

func trafficPoints(t *testing.T, raw []byte) ([]map[string]any, bool) {
	t.Helper()
	var response struct {
		Points    []map[string]any `json:"points"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode traffic response %s: %v", raw, err)
	}
	return response.Points, response.Truncated
}

func TestTrafficAPIRequiresAccessAndSession(t *testing.T) {
	tw := newTestWeb(t)
	seedTrafficEvents(t, tw)
	status, raw := tw.request(t, http.MethodGet, "/web/api/traffic/latest", "", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated traffic status=%d body=%s", status, raw)
	}
	// A valid Access assertion alone (no local session) is not enough.
	status, raw = getTraffic(t, tw, "/web/api/traffic/latest")
	if status != http.StatusUnauthorized {
		t.Fatalf("sessionless traffic status=%d body=%s", status, raw)
	}
	// No local bearer/loopback bypass exists on this route.
	req, _ := http.NewRequest(http.MethodGet, tw.server.URL+"/web/api/traffic/latest", nil)
	req.Header.Set("Authorization", "Bearer local-admin-bypass")
	resp, err := tw.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer-only traffic status=%d", resp.StatusCode)
	}
}

func TestTrafficAPIRoleScoping(t *testing.T) {
	cases := []struct {
		role    string
		scopes  []string
		wantB   bool
		wantAll int
	}{
		{role: store.AuthRoleViewer, scopes: []string{trafficEventA}, wantAll: 1},
		{role: store.AuthRoleEventAdmin, scopes: []string{trafficEventA}, wantAll: 1},
		{role: store.AuthRolePlatformAdmin, wantB: true, wantAll: 2},
	}
	for _, tcCase := range cases {
		t.Run(tcCase.role, func(t *testing.T) {
			tw := newTestWeb(t)
			seedTrafficEvents(t, tw)
			trafficUserLogin(t, tw, "traffic-"+tcCase.role, tcCase.role, tcCase.scopes)

			status, raw := getTraffic(t, tw, "/web/api/traffic/latest")
			if status != http.StatusOK {
				t.Fatalf("latest status=%d body=%s", status, raw)
			}
			points, _ := trafficPoints(t, raw)
			if len(points) != tcCase.wantAll {
				t.Fatalf("latest visible series=%d, want %d: %s", len(points), tcCase.wantAll, raw)
			}
			for _, point := range points {
				if !tcCase.wantB && point["event_id"] != trafficEventA {
					t.Fatalf("unassigned event leaked: %v", point)
				}
			}

			// Explicit out-of-scope event is a consistent 403.
			status, raw = getTraffic(t, tw, "/web/api/traffic/latest?event_id="+trafficEventB)
			if tcCase.wantB {
				if status != http.StatusOK {
					t.Fatalf("platform event B status=%d body=%s", status, raw)
				}
			} else if status != http.StatusForbidden {
				t.Fatalf("out-of-scope event status=%d body=%s, want 403", status, raw)
			}
			// Scoped history: the allowed event works, the other is denied.
			status, raw = getTraffic(t, tw, fmt.Sprintf("/web/api/traffic/history?event_id=%s&from=%d&to=%d",
				trafficEventA, time.Now().Unix()-600, time.Now().Unix()+60))
			if status != http.StatusOK || !strings.Contains(string(raw), trafficEventA) {
				t.Fatalf("scoped history status=%d body=%s", status, raw)
			}
			status, _ = getTraffic(t, tw, fmt.Sprintf("/web/api/traffic/history?event_id=%s&from=%d&to=%d",
				trafficEventB, time.Now().Unix()-600, time.Now().Unix()+60))
			if !tcCase.wantB && status != http.StatusForbidden {
				t.Fatalf("out-of-scope history status=%d, want 403", status)
			}
		})
	}
}

func TestTrafficAPIValidationBounds(t *testing.T) {
	tw := newTestWeb(t)
	now := seedTrafficEvents(t, tw)
	trafficUserLogin(t, tw, "traffic-admin", store.AuthRolePlatformAdmin, nil)
	bad := []string{
		"/web/api/traffic/latest?limit=2001",
		"/web/api/traffic/latest?limit=0",
		"/web/api/traffic/latest?event_id=not-a-uuid",
		"/web/api/traffic/latest?node_id=not-a-uuid",
		"/web/api/traffic/latest?kind=vless",
		"/web/api/traffic/latest?inbound_tag=bad tag",
		"/web/api/traffic/latest?unknown_parameter=1",
		"/web/api/traffic/latest?from=-1",
		fmt.Sprintf("/web/api/traffic/history?from=%d", now-600),
		fmt.Sprintf("/web/api/traffic/history?from=%d&to=%d", now-40*24*60*60, now),
		fmt.Sprintf("/web/api/traffic/history?from=%d&to=%d&step_seconds=99999", now-600, now),
	}
	for _, path := range bad {
		status, raw := getTraffic(t, tw, path)
		if status != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", path, status, raw)
		}
	}
	status, _ := tw.request(t, http.MethodPost, "/web/api/traffic/latest", "", nil, tw.jwt)
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("POST traffic status=%d, want 405", status)
	}
	status, _ = getTraffic(t, tw, "/web/api/traffic/bogus")
	if status != http.StatusNotFound {
		t.Fatalf("unknown traffic route status=%d, want 404", status)
	}
}

func TestTrafficAPILatestHistoryPayload(t *testing.T) {
	tw := newTestWeb(t)
	now := seedTrafficEvents(t, tw)
	trafficUserLogin(t, tw, "traffic-admin", store.AuthRolePlatformAdmin, nil)

	status, raw := getTraffic(t, tw, "/web/api/traffic/latest?event_id="+trafficEventA)
	if status != http.StatusOK {
		t.Fatalf("latest status=%d body=%s", status, raw)
	}
	points, _ := trafficPoints(t, raw)
	if len(points) != 1 {
		t.Fatalf("latest series = %d, want 1", len(points))
	}
	var latestBody map[string]any
	if err := json.Unmarshal(raw, &latestBody); err != nil {
		t.Fatal(err)
	}
	observations, _ := latestBody["observations"].([]any)
	if len(observations) != 1 {
		t.Fatalf("latest observation states = %d, want 1", len(observations))
	}
	latest := points[0]
	if latest["observed_at"] != float64(now-60) || latest["quality"] != "lower_bound" ||
		latest["freshness"] != "fresh" || latest["source_epoch"] != strings.Repeat("ab", 16) ||
		latest["uplink_observed_lower_bound_bytes"] == nil {
		t.Fatalf("unexpected latest point: %v", latest)
	}

	status, raw = getTraffic(t, tw, fmt.Sprintf("/web/api/traffic/history?event_id=%s&from=%d&to=%d",
		trafficEventA, now-200, now-10))
	if status != http.StatusOK {
		t.Fatalf("history status=%d body=%s", status, raw)
	}
	points, truncated := trafficPoints(t, raw)
	if truncated || len(points) != 2 {
		t.Fatalf("history rows=%d truncated=%v", len(points), truncated)
	}
	if points[0]["observed_at"] != float64(now-120) || points[1]["observed_at"] != float64(now-60) {
		t.Fatalf("history order = %v/%v", points[0]["observed_at"], points[1]["observed_at"])
	}
	if points[0]["gap_before_seconds"] != nil {
		t.Fatalf("first history row gap = %v", points[0]["gap_before_seconds"])
	}
	if points[1]["gap_before_seconds"] != float64(60) {
		t.Fatalf("second history row gap = %v, want 60", points[1]["gap_before_seconds"])
	}
	// Truncation metadata without a full count.
	status, raw = getTraffic(t, tw, fmt.Sprintf("/web/api/traffic/history?event_id=%s&from=%d&to=%d&limit=1",
		trafficEventA, now-200, now-10))
	if status != http.StatusOK {
		t.Fatalf("truncated history status=%d body=%s", status, raw)
	}
	if points, truncated = trafficPoints(t, raw); !truncated || len(points) != 1 {
		t.Fatalf("truncated history rows=%d truncated=%v", len(points), truncated)
	}
}
