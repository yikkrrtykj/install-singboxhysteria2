// Package windowsobs projects local Mihomo snapshots onto configured VPS roles.
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

type Role string

const (
	AReality Role = "a_reality"
	AHY2     Role = "a_hy2"
	BReality Role = "b_reality"
	BHY2     Role = "b_hy2"
)

const (
	observed    = "observed"
	unknown     = "unknown"
	unavailable = "unavailable"
	maxBody     = 4 << 20
)

type Profile struct {
	Controller string          `json:"controller"`
	Group      string          `json:"group"`
	Routes     map[Role]string `json:"routes"`
}

type Selection struct {
	State string `json:"state"`
	Role  Role   `json:"role,omitempty"`
}

type Active struct {
	State   string       `json:"state"`
	Counts  map[Role]int `json:"counts,omitempty"`
	Unknown *int         `json:"unknown,omitempty"`
}

type Snapshot struct {
	Version    int       `json:"version"`
	ObservedAt time.Time `json:"observed_at"`
	Selection  Selection `json:"selection"`
	Active     Active    `json:"active_connections"`
}

type Observer struct {
	base   *url.URL
	group  string
	roles  map[string]Role
	secret string
	client *http.Client
}

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
		case AReality, AHY2, BReality, BHY2:
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

func (o *Observer) Collect(ctx context.Context) Snapshot {
	var proxies struct {
		Proxies map[string]*proxy `json:"proxies"`
	}
	selection := Selection{State: o.get(ctx, "/proxies", &proxies)}
	if selection.State == observed {
		selection = o.selected(proxies.Proxies)
	}

	var response struct {
		Connections json.RawMessage `json:"connections"`
	}
	active := Active{State: o.get(ctx, "/connections", &response)}
	if active.State == observed {
		active = o.active(response.Connections)
	}
	return Snapshot{Version: 1, ObservedAt: time.Now().UTC(), Selection: selection, Active: active}
}

func (o *Observer) get(ctx context.Context, path string, out any) string {
	endpoint := o.base.JoinPath(path)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return unknown
	}
	request.Header.Set("Accept", "application/json")
	if o.secret != "" {
		request.Header.Set("Authorization", "Bearer "+o.secret)
	}
	response, err := o.client.Do(request)
	if err != nil {
		return unavailable
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return unavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return unavailable
	}
	if len(body) > maxBody || json.Unmarshal(body, out) != nil {
		return unknown
	}
	return observed
}

type proxy struct {
	Now string   `json:"now"`
	All []string `json:"all"`
}

func (o *Observer) selected(proxies map[string]*proxy) Selection {
	next := o.group
	visited := map[string]bool{}
	for len(visited) < 16 && !visited[next] {
		entry, exists := proxies[next]
		if !exists || entry == nil {
			break
		}
		if role := o.roles[next]; role != "" && entry.Now == "" && len(entry.All) == 0 {
			return Selection{State: observed, Role: role}
		}
		if entry.Now == "" || !contains(entry.All, entry.Now) {
			break
		}
		visited[next] = true
		next = entry.Now
	}
	return Selection{State: unknown}
}

func (o *Observer) active(raw json.RawMessage) Active {
	if len(raw) == 0 {
		return Active{State: unknown}
	}
	var connections []struct {
		Chains []string `json:"chains"`
	}
	if bytes.Equal(raw, []byte("null")) {
		connections = nil
	} else if json.Unmarshal(raw, &connections) != nil {
		return Active{State: unknown}
	}
	counts := make(map[Role]int, len(o.roles))
	for _, role := range o.roles {
		counts[role] = 0
	}
	unmapped := 0
	for _, connection := range connections {
		if len(connection.Chains) == 0 || contains(connection.Chains, "") {
			return Active{State: unknown}
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
	return Active{State: observed, Counts: counts, Unknown: &unmapped}
}

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
