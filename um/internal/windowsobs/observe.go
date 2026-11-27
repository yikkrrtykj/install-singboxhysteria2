// Package windowsobs projects local Mihomo snapshots onto the frozen Windows
// terminal route tokens.
//
// This is an experimental, read-only observation component: every request is a
// loopback HTTP GET against the local Mihomo/Clash Verge Rev external
// controller. Holding a controller credential is a controller-write-capable
// credential used by a read-only client (the R1 residual risk); it is never
// enabled implicitly by this package and requires a separate centre/operator
// authorization plus local secret injection by the caller. The R2 truly
// read-only source is a later design decision and only needs to implement the
// same observation shape (see the windowsagent collector interface).
//
// The package owns the only route/role enum used by the node agent: the six
// frozen tokens a_reality, a_hy2, b_reality, b_hy2, direct and unknown. Local
// proxy/group names are operator-local binding inputs; they are never part of
// the snapshot wire shape that the centre validates.
package windowsobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Role is one route token of the frozen Windows terminal six-token vocabulary
// (report-snapshot.schema.json $defs.route_token). This is the only route enum
// in the node agent: there are no aliases and no A/B collapse.
type Role string

const (
	// AReality is the A path over Reality (centre aggregation A).
	AReality Role = "a_reality"
	// AHY2 is the A path over Hysteria2 (centre aggregation A).
	AHY2 Role = "a_hy2"
	// BReality is the B path over Reality (centre aggregation B).
	BReality Role = "b_reality"
	// BHY2 is the B path over Hysteria2 (centre aggregation B).
	BHY2 Role = "b_hy2"
	// Direct is the explicit operator-local direct binding token. It is emitted
	// only when the operator-local profile explicitly maps a local name to
	// Direct; the built-in DIRECT/REJECT proxy names are never inferred, and an
	// unmapped path is never reported as direct.
	Direct Role = "direct"
	// UnknownRoute is the fallback token for an observed but unmapped or
	// ambiguous path. It is not a valid binding target.
	UnknownRoute Role = "unknown"
)

// Tokens returns the six frozen route tokens in contract order.
func Tokens() []Role {
	return []Role{AReality, AHY2, BReality, BHY2, Direct, UnknownRoute}
}

// Sample states reported by one local source read. A sample that could not be
// taken is never reported as observed and an observed empty set is never
// reported as unavailable.
const (
	// StateObserved means the source answered and the value was parsed.
	StateObserved = "observed"
	// StateUnknown means the source answered but its value could not be
	// interpreted or the local group/route binding could not be resolved.
	StateUnknown = "unknown"
	// StateUnavailable means no usable answer was obtained (transport error or
	// an unusable controller response).
	StateUnavailable = "unavailable"
)

// Source failure reasons. The values are the frozen terminal reason_code
// vocabulary so the Windows collector can surface them verbatim; they never
// contain raw proxy names, IPs, URLs, connection identities or exception text.
const (
	// ReasonControllerUnreachable means the controller could not be used:
	// transport failure, timeout, redirect refusal or a non-200 answer that is
	// not an authentication failure.
	ReasonControllerUnreachable = "controller_unreachable"
	// ReasonControllerAuth means the controller rejected the request with 401 or
	// 403. The credential itself is never included in the reason.
	ReasonControllerAuth = "controller_auth"
	// ReasonMalformedResponse means the controller answered but the body was
	// oversized, not JSON, or not the expected object shape.
	ReasonMalformedResponse = "malformed_response"
	// ReasonRouteUnbound means a syntactically valid answer was obtained but the
	// watched group/leaf/path does not resolve to exactly one bound role. It is
	// the honest fallback in place of guessing direct.
	ReasonRouteUnbound = "route_unbound"
)

const (
	maxBody         = 4 << 20
	maxSelectionHop = 16
	snapshotVersion = 1
)

// Profile is the operator-local observation configuration. Controller, group
// and route names are local operator data: they are never uploaded and never
// appear in the projected Snapshot.
type Profile struct {
	Controller string          `json:"controller"`
	Group      string          `json:"group"`
	Routes     map[Role]string `json:"routes"`
}

// Selection is the independently sampled selected-route observation.
type Selection struct {
	State     string `json:"state"`
	Role      Role   `json:"role,omitempty"`
	Reason    string `json:"reason,omitempty"`
	SampledAt int64  `json:"sampled_at,omitempty"`
}

// Active is the independently sampled open-connection aggregate. Counts holds
// one entry per bound non-unknown role, Unknown counts connections that pass
// through the watched group but do not resolve to exactly one bound role.
type Active struct {
	State     string       `json:"state"`
	Counts    map[Role]int `json:"counts,omitempty"`
	Unknown   *int         `json:"unknown,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	SampledAt int64        `json:"sampled_at,omitempty"`
}

// Snapshot is one projection result. Selection and Active are sampled by
// independent requests; ObservedAt is the completion time of the projection.
type Snapshot struct {
	Version    int       `json:"version"`
	ObservedAt time.Time `json:"observed_at"`
	Selection  Selection `json:"selection"`
	Active     Active    `json:"active_connections"`
}

// Observer is a read-only loopback controller client. It performs only
// GET /proxies and GET /connections; it never mutates controller state.
type Observer struct {
	base   *url.URL
	group  string
	roles  map[string]Role
	secret string
	client *http.Client
}

// New validates the operator-local profile and creates a read-only observer.
//
// Routes maps local proxy names to the five bindable tokens (a_reality, a_hy2,
// b_reality, b_hy2, direct). UnknownRoute is the automatic fallback and is
// rejected as a binding target. A path is classified as direct only when the
// operator explicitly bound a local name to Direct.
func New(profile Profile, secret string) (*Observer, error) {
	base, err := url.Parse(profile.Controller)
	if err != nil || base.Scheme != "http" || base.User != nil ||
		base.Path != "" || base.RawPath != "" || base.ForceQuery ||
		base.RawQuery != "" || strings.Contains(profile.Controller, "#") {
		return nil, errors.New("controller must be an HTTP loopback IP and port")
	}
	host, err := netip.ParseAddr(base.Hostname())
	port, portErr := strconv.ParseUint(base.Port(), 10, 16)
	if err != nil || !host.IsLoopback() || host.Zone() != "" || portErr != nil || port == 0 {
		return nil, errors.New("controller must be an HTTP loopback IP and port")
	}
	if profile.Group == "" || len(profile.Routes) == 0 {
		return nil, errors.New("a watched group and at least one route are required")
	}
	roles := make(map[string]Role, len(profile.Routes))
	for role, name := range profile.Routes {
		switch role {
		case AReality, AHY2, BReality, BHY2, Direct:
		case UnknownRoute:
			return nil, errors.New("unknown is the fallback token and cannot be bound to a local route")
		default:
			return nil, errors.New("invalid route role")
		}
		if name == "" || name == profile.Group || roles[name] != "" {
			return nil, errors.New("route names must be distinct and different from the watched group")
		}
		roles[name] = role
	}
	if strings.ContainsAny(secret, "\r\n") {
		return nil, errors.New("invalid controller credential format")
	}

	return &Observer{
		base: base, group: profile.Group, roles: roles, secret: secret,
		client: &http.Client{
			Transport: &http.Transport{DisableCompression: true},
			Timeout:   3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Collect samples selection and active connections independently and returns
// both in one projection value. The two source reads remain independent: one
// can be observed while the other is unavailable/unknown.
func (o *Observer) Collect(ctx context.Context) Snapshot {
	selection := o.ObserveSelection(ctx)
	active := o.ObserveActive(ctx)
	return Snapshot{
		Version:    snapshotVersion,
		ObservedAt: time.Now().UTC(),
		Selection:  selection,
		Active:     active,
	}
}

// ObserveSelection samples only the selected route (GET /proxies).
func (o *Observer) ObserveSelection(ctx context.Context) Selection {
	var proxies struct {
		Proxies map[string]*proxy `json:"proxies"`
	}
	state, reason := o.get(ctx, "/proxies", &proxies)
	sampledAt := time.Now().UTC().Unix()
	if state != StateObserved {
		return Selection{State: state, Reason: reason, SampledAt: sampledAt}
	}
	selection := o.selected(proxies.Proxies)
	selection.SampledAt = sampledAt
	return selection
}

// ObserveActive samples only the open-connection aggregate (GET /connections).
func (o *Observer) ObserveActive(ctx context.Context) Active {
	var response struct {
		Connections json.RawMessage `json:"connections"`
	}
	state, reason := o.get(ctx, "/connections", &response)
	sampledAt := time.Now().UTC().Unix()
	if state != StateObserved {
		return Active{State: state, Reason: reason, SampledAt: sampledAt}
	}
	active := o.active(response.Connections)
	active.SampledAt = sampledAt
	return active
}

// get performs one bounded, non-redirecting, GET-only controller request. It
// classifies transport and body failures without exposing any raw value.
func (o *Observer) get(ctx context.Context, path string, out any) (string, string) {
	endpoint := o.base.JoinPath(path)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return StateUnknown, ReasonMalformedResponse
	}
	request.Header.Set("Accept", "application/json")
	if o.secret != "" {
		request.Header.Set("Authorization", "Bearer "+o.secret)
	}
	response, err := o.client.Do(request)
	if err != nil {
		return StateUnavailable, ReasonControllerUnreachable
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return StateUnavailable, ReasonControllerAuth
	case http.StatusOK:
	default:
		return StateUnavailable, ReasonControllerUnreachable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return StateUnavailable, ReasonControllerUnreachable
	}
	if len(body) > maxBody || json.Unmarshal(body, out) != nil {
		return StateUnknown, ReasonMalformedResponse
	}
	return StateObserved, ""
}

type proxy struct {
	Now string   `json:"now"`
	All []string `json:"all"`
}

// selected resolves the watched group's current selection down to exactly one
// operator-bound route token. It never guesses: an unresolvable, cyclic,
// missing or depth-bounded path is reported as StateUnknown/route_unbound, and
// the built-in DIRECT name is only recognised if the operator bound it.
func (o *Observer) selected(proxies map[string]*proxy) Selection {
	next := o.group
	visited := make(map[string]bool, maxSelectionHop)
	for len(visited) < maxSelectionHop && !visited[next] {
		entry, exists := proxies[next]
		if !exists || entry == nil {
			break
		}
		if role := o.roles[next]; role != "" && entry.Now == "" && len(entry.All) == 0 {
			return Selection{State: StateObserved, Role: role}
		}
		if entry.Now == "" || !contains(entry.All, entry.Now) {
			break
		}
		visited[next] = true
		next = entry.Now
	}
	return Selection{State: StateUnknown, Reason: ReasonRouteUnbound}
}

func (o *Observer) active(raw json.RawMessage) Active {
	if len(raw) == 0 {
		return Active{State: StateUnknown, Reason: ReasonMalformedResponse}
	}
	var connections []struct {
		Chains []string `json:"chains"`
	}
	if bytes.Equal(raw, []byte("null")) {
		connections = nil
	} else if json.Unmarshal(raw, &connections) != nil {
		return Active{State: StateUnknown, Reason: ReasonMalformedResponse}
	}
	counts := make(map[Role]int, len(o.roles))
	for _, role := range o.roles {
		counts[role] = 0
	}
	unmapped := 0
	for _, connection := range connections {
		if len(connection.Chains) == 0 || contains(connection.Chains, "") {
			return Active{State: StateUnknown, Reason: ReasonMalformedResponse}
		}
		if !contains(connection.Chains, o.group) {
			continue
		}
		role := o.chainRole(connection.Chains)
		if role == "" {
			unmapped++
			continue
		}
		counts[role]++
	}
	return Active{State: StateObserved, Counts: counts, Unknown: &unmapped}
}

// chainRole maps a connection chain to exactly one bound token. A chain that
// mentions two different bound roles is ambiguous and stays unmapped (unknown),
// never direct.
func (o *Observer) chainRole(chain []string) Role {
	var matched Role
	for _, name := range chain {
		role := o.roles[name]
		if role == "" {
			continue
		}
		if matched != "" && matched != role {
			return ""
		}
		matched = role
	}
	return matched
}

func contains(list []string, value string) bool {
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}
