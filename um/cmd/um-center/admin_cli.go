package main

// Management CLI for UM-B4. It talks only to the authenticated /api/v1 admin
// API; it never opens SQLite or calls the store directly. This keeps RBAC,
// scope resolution and audit on the same service path as the HTTP API.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/management"
)

const adminUsage = `usage: um-center admin --url http://127.0.0.1:8090 --token-file /etc/um-center/admin.token [--json] <command> ...

commands:
  health
  event list [--state active|archived] [--limit N] [--offset N]
  event create --name NAME [--event-id UUID]
  event show EVENT_ID
  event rename EVENT_ID --name NAME
  event archive EVENT_ID
  event purge preview EVENT_ID
  event purge confirm EVENT_ID --confirm purge:EVENT_ID
  event purge status EVENT_ID
  node list EVENT_ID [--class linux_vps|windows_terminal] [--state active|revoked]
  node show EVENT_ID NODE_ID
  node revoke EVENT_ID NODE_ID
  token list EVENT_ID [--limit N] [--offset N]
  token create EVENT_ID --class linux_vps|windows_terminal [--ttl-seconds N]
  token status EVENT_ID TOKEN_ID
  token revoke EVENT_ID TOKEN_ID
  config show EVENT_ID NODE_ID
  config history EVENT_ID NODE_ID
  config update EVENT_ID NODE_ID --cadence N [--sources JSON] [--tags JSON]
  alias list EVENT_ID [--type node|device_ref|route]
  alias set EVENT_ID TYPE KEY --name NAME [--expected-version N]
  alias delete EVENT_ID TYPE KEY
  mapping list EVENT_ID WINDOWS_NODE_ID
  mapping create EVENT_ID WINDOWS_NODE_ID --version N --effective-from EPOCH --entries JSON
  mapping resolve EVENT_ID WINDOWS_NODE_ID [--at EPOCH]
  retention state|timeline|runs|run
  capacity
  audit list [--event EVENT_ID] [--action ACTION] [--result ok|denied|error] [--actor ID] [--since EPOCH] [--until EPOCH] [--limit N] [--offset N]
  audit verify
`

func runAdminCLI(args []string) int {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	adminURL := fs.String("url", "", "loopback admin API URL, e.g. http://127.0.0.1:8090")
	tokenFile := fs.String("token-file", envOr("UM_CENTER_ADMIN_TOKEN_FILE", ""), "protected 0600 admin bearer token file")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *adminURL == "" || *tokenFile == "" {
		fmt.Fprint(os.Stderr, adminUsage)
		return 2
	}
	client, err := management.NewClient(*adminURL, *tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-center admin:", err)
		return 1
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(os.Stderr, adminUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var data any
	err = runAdminCommand(ctx, client, rest, &data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-center admin:", adminError(err))
		return 1
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return 1
		}
		return 0
	}
	return printAdminHuman(data)
}

func adminError(err error) string {
	var api *management.APIError
	if errors.As(err, &api) {
		return fmt.Sprintf("API error %d (%s)", api.Status, api.Code)
	}
	return err.Error()
}

func printAdminHuman(data any) int {
	if m, ok := data.(map[string]any); ok {
		if events, ok := m["events"].([]any); ok {
			for _, item := range events {
				if e, ok := item.(map[string]any); ok {
					fmt.Printf("%s  %-10s  %-24s  nodes=%v\n", str(e["event_id"]), str(e["state"]), str(e["display_name"]), e["node_count"])
				}
			}
			return 0
		}
		if nodes, ok := m["nodes"].([]any); ok {
			for _, item := range nodes {
				if n, ok := item.(map[string]any); ok {
					fmt.Printf("%s  %-16s  %-14s  last_seen=%v\n", str(n["node_id"]), str(n["node_class"]), str(n["derived_status"]), n["last_seen_at"])
				}
			}
			return 0
		}
		if tokens, ok := m["tokens"].([]any); ok {
			for _, item := range tokens {
				if t, ok := item.(map[string]any); ok {
					fmt.Printf("%s  %-8s  %-16s  expires=%v\n", str(t["token_id"]), str(t["status"]), str(t["node_class"]), t["expires_at"])
				}
			}
			return 0
		}
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Println(string(raw))
	return 0
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// subFlags isolates each subcommand's flag set while sharing the global flags
// already parsed by runAdminCLI.
func subFlags(name string, args []string) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs, nil
}

func runAdminCommand(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) == 0 {
		return errors.New("missing command")
	}
	switch args[0] {
	case "health":
		return c.Call(ctx, "GET", "/api/v1/health", nil, nil, out)
	case "event":
		return runAdminEvent(ctx, c, args[1:], out)
	case "node":
		return runAdminNode(ctx, c, args[1:], out)
	case "token":
		return runAdminToken(ctx, c, args[1:], out)
	case "config":
		return runAdminConfig(ctx, c, args[1:], out)
	case "alias":
		return runAdminAlias(ctx, c, args[1:], out)
	case "mapping":
		return runAdminMapping(ctx, c, args[1:], out)
	case "retention":
		return runAdminRetention(ctx, c, args[1:], out)
	case "capacity":
		return c.Call(ctx, "GET", "/api/v1/capacity", nil, nil, out)
	case "audit":
		return runAdminAudit(ctx, c, args[1:], out)
	default:
		return errors.New("unknown command")
	}
}

func runAdminEvent(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) == 0 {
		return errors.New("missing event subcommand")
	}
	switch args[0] {
	case "list":
		fs, err := subFlags("event list", args[1:])
		if err != nil {
			return err
		}
		state := fs.String("state", "", "active|archived")
		limit := fs.Int("limit", 50, "page size")
		offset := fs.Int("offset", 0, "page offset")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		q := url.Values{}
		if *state != "" {
			q.Set("state", *state)
		}
		q.Set("limit", strconv.Itoa(*limit))
		q.Set("offset", strconv.Itoa(*offset))
		return c.Call(ctx, "GET", "/api/v1/events", q, nil, out)
	case "create":
		fs, _ := subFlags("event create", args[1:])
		name := fs.String("name", "", "event display name")
		id := fs.String("event-id", "", "optional caller-supplied UUIDv4")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return c.Call(ctx, "POST", "/api/v1/events", nil,
			map[string]any{"display_name": *name, "event_id": *id}, out)
	case "show":
		if len(args) < 2 {
			return errors.New("event show requires EVENT_ID")
		}
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(args[1]), nil, nil, out)
	case "rename":
		if len(args) < 2 {
			return errors.New("event rename requires EVENT_ID")
		}
		fs, _ := subFlags("event rename", args[2:])
		name := fs.String("name", "", "new display name")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return c.Call(ctx, "PATCH", "/api/v1/events/"+url.PathEscape(args[1]), nil,
			map[string]any{"display_name": *name}, out)
	case "archive":
		if len(args) < 2 {
			return errors.New("event archive requires EVENT_ID")
		}
		return c.Call(ctx, "POST", "/api/v1/events/"+url.PathEscape(args[1])+"/archive", nil, nil, out)
	case "purge":
		return runAdminPurge(ctx, c, args[1:], out)
	default:
		return errors.New("unknown event command")
	}
}

func runAdminPurge(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) < 2 {
		return errors.New("event purge requires preview|confirm|status EVENT_ID")
	}
	action, id := args[0], args[1]
	switch action {
	case "preview":
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(id)+"/purge/preview", nil, nil, out)
	case "status":
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(id)+"/purge/status", nil, nil, out)
	case "confirm":
		fs, _ := subFlags("event purge confirm", args[2:])
		confirm := fs.String("confirm", "", "must be purge:EVENT_ID")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *confirm != "purge:"+id {
			return errors.New("confirmation must be exactly purge:<event_id>")
		}
		return c.Call(ctx, "POST", "/api/v1/events/"+url.PathEscape(id)+"/purge/confirm", nil,
			map[string]any{"confirmation": *confirm}, out)
	default:
		return errors.New("unknown purge command")
	}
}

func runAdminNode(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) == 0 {
		return errors.New("missing node subcommand")
	}
	switch args[0] {
	case "list":
		if len(args) < 2 {
			return errors.New("node list requires EVENT_ID")
		}
		fs, _ := subFlags("node list", args[2:])
		class := fs.String("class", "", "linux_vps|windows_terminal")
		state := fs.String("state", "", "active|revoked")
		limit := fs.Int("limit", 50, "page size")
		offset := fs.Int("offset", 0, "page offset")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		q := url.Values{}
		if *class != "" {
			q.Set("class", *class)
		}
		if *state != "" {
			q.Set("state", *state)
		}
		q.Set("limit", strconv.Itoa(*limit))
		q.Set("offset", strconv.Itoa(*offset))
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(args[1])+"/nodes", q, nil, out)
	case "show":
		if len(args) < 3 {
			return errors.New("node show requires EVENT_ID NODE_ID")
		}
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(args[1])+"/nodes/"+url.PathEscape(args[2]), nil, nil, out)
	case "revoke":
		if len(args) < 3 {
			return errors.New("node revoke requires EVENT_ID NODE_ID")
		}
		return c.Call(ctx, "POST", "/api/v1/events/"+url.PathEscape(args[1])+"/nodes/"+url.PathEscape(args[2])+"/revoke", nil, nil, out)
	default:
		return errors.New("unknown node command")
	}
}

func runAdminToken(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) == 0 {
		return errors.New("missing token subcommand")
	}
	switch args[0] {
	case "list":
		if len(args) < 2 {
			return errors.New("token list requires EVENT_ID")
		}
		fs, _ := subFlags("token list", args[2:])
		limit := fs.Int("limit", 50, "page size")
		offset := fs.Int("offset", 0, "page offset")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(*limit))
		q.Set("offset", strconv.Itoa(*offset))
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(args[1])+"/tokens", q, nil, out)
	case "create":
		if len(args) < 2 {
			return errors.New("token create requires EVENT_ID")
		}
		fs, _ := subFlags("token create", args[2:])
		class := fs.String("class", "", "linux_vps|windows_terminal")
		ttl := fs.Int("ttl-seconds", 900, "token lifetime (60..900)")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return c.Call(ctx, "POST", "/api/v1/events/"+url.PathEscape(args[1])+"/tokens", nil,
			map[string]any{"node_class": strings.TrimSpace(*class), "ttl_seconds": *ttl}, out)
	case "status":
		if len(args) < 3 {
			return errors.New("token status requires EVENT_ID TOKEN_ID")
		}
		return c.Call(ctx, "GET", "/api/v1/events/"+url.PathEscape(args[1])+"/tokens/"+url.PathEscape(args[2]), nil, nil, out)
	case "revoke":
		if len(args) < 3 {
			return errors.New("token revoke requires EVENT_ID TOKEN_ID")
		}
		return c.Call(ctx, "POST", "/api/v1/events/"+url.PathEscape(args[1])+"/tokens/"+url.PathEscape(args[2])+"/revoke", nil, nil, out)
	default:
		return errors.New("unknown token command")
	}
}

func runAdminConfig(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) < 1 {
		return errors.New("missing config subcommand")
	}
	action := args[0]
	base := "/api/v1/events/"
	switch action {
	case "show":
		if len(args) < 3 {
			return errors.New("config show requires EVENT_ID NODE_ID")
		}
		return c.Call(ctx, "GET", base+url.PathEscape(args[1])+"/nodes/"+url.PathEscape(args[2])+"/config", nil, nil, out)
	case "history":
		if len(args) < 3 {
			return errors.New("config history requires EVENT_ID NODE_ID")
		}
		return c.Call(ctx, "GET", base+url.PathEscape(args[1])+"/nodes/"+url.PathEscape(args[2])+"/config/history", nil, nil, out)
	case "update":
		if len(args) < 3 {
			return errors.New("config update requires EVENT_ID NODE_ID")
		}
		fs, _ := subFlags("config update", args[3:])
		cadence := fs.Int("cadence", 60, "cadence seconds (30..300)")
		sourcesRaw := fs.String("sources", "", "JSON object of source switches")
		tagsRaw := fs.String("tags", "", "JSON array of {inbound_tag,kind}")
		if err := fs.Parse(args[3:]); err != nil {
			return err
		}
		sources := map[string]bool{}
		if *sourcesRaw != "" {
			if err := json.Unmarshal([]byte(*sourcesRaw), &sources); err != nil {
				return errors.New("--sources must be a JSON object of booleans")
			}
		}
		var tags []management.InboundTagView
		if *tagsRaw != "" {
			if err := json.Unmarshal([]byte(*tagsRaw), &tags); err != nil {
				return errors.New("--tags must be a JSON array of {inbound_tag,kind}")
			}
		}
		return c.Call(ctx, "PUT", base+url.PathEscape(args[1])+"/nodes/"+url.PathEscape(args[2])+"/config", nil,
			map[string]any{"cadence_seconds": *cadence, "sources": sources, "expected_inbound_tags": tags}, out)
	default:
		return errors.New("unknown config command")
	}
}

func runAdminAlias(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) < 2 {
		return errors.New("alias command requires action EVENT_ID")
	}
	action, eventID := args[0], args[1]
	base := "/api/v1/events/" + url.PathEscape(eventID) + "/aliases"
	switch action {
	case "list":
		fs, _ := subFlags("alias list", args[2:])
		typ := fs.String("type", "", "node|device_ref|route")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		q := url.Values{}
		if *typ != "" {
			q.Set("target_type", *typ)
		}
		return c.Call(ctx, "GET", base, q, nil, out)
	case "set":
		if len(args) < 4 {
			return errors.New("alias set requires EVENT_ID TYPE KEY")
		}
		fs, _ := subFlags("alias set", args[4:])
		name := fs.String("name", "", "display alias")
		expected := fs.Int64("expected-version", 0, "optimistic version (0 = create)")
		if err := fs.Parse(args[4:]); err != nil {
			return err
		}
		var expectedPtr *int64
		if *expected > 0 {
			expectedPtr = expected
		}
		return c.Call(ctx, "PUT", base+"/"+url.PathEscape(args[2])+"/"+url.PathEscape(args[3]), nil,
			map[string]any{"display_name": *name, "expected_version": expectedPtr}, out)
	case "delete":
		if len(args) < 4 {
			return errors.New("alias delete requires EVENT_ID TYPE KEY")
		}
		return c.Call(ctx, "DELETE", base+"/"+url.PathEscape(args[2])+"/"+url.PathEscape(args[3]), nil, nil, out)
	default:
		return errors.New("unknown alias command")
	}
}

func runAdminMapping(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) < 3 {
		return errors.New("mapping command requires action EVENT_ID WINDOWS_NODE_ID")
	}
	action, eventID, windowsID := args[0], args[1], args[2]
	base := "/api/v1/events/" + url.PathEscape(eventID) + "/mapping/" + url.PathEscape(windowsID)
	switch action {
	case "list":
		return c.Call(ctx, "GET", base, nil, nil, out)
	case "resolve":
		fs, _ := subFlags("mapping resolve", args[3:])
		at := fs.Int64("at", 0, "sample time (epoch seconds)")
		if err := fs.Parse(args[3:]); err != nil {
			return err
		}
		q := url.Values{}
		if *at > 0 {
			q.Set("at", strconv.FormatInt(*at, 10))
		}
		return c.Call(ctx, "GET", base+"/resolve", q, nil, out)
	case "create":
		fs, _ := subFlags("mapping create", args[3:])
		version := fs.Int("version", 1, "append-only version")
		effective := fs.Int64("effective-from", 0, "effective epoch seconds")
		entries := fs.String("entries", "{}", `JSON object {"a_reality":"<node>"}`)
		if err := fs.Parse(args[3:]); err != nil {
			return err
		}
		var m map[string]string
		if err := json.Unmarshal([]byte(*entries), &m); err != nil {
			return errors.New("--entries must be a JSON object")
		}
		list := make([]management.MappingEntryView, 0, len(m))
		for token, target := range m {
			list = append(list, management.MappingEntryView{RouteToken: token, TargetNodeID: target})
		}
		return c.Call(ctx, "POST", base, nil,
			map[string]any{"version": *version, "effective_from": *effective, "entries": list}, out)
	default:
		return errors.New("unknown mapping command")
	}
}

func runAdminRetention(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) < 1 {
		return errors.New("retention command requires state|timeline|runs|run")
	}
	switch args[0] {
	case "state":
		return c.Call(ctx, "GET", "/api/v1/retention/state", nil, nil, out)
	case "timeline":
		return c.Call(ctx, "GET", "/api/v1/retention/timeline", nil, nil, out)
	case "runs":
		q := url.Values{}
		if len(args) > 1 {
			if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
				q.Set("limit", strconv.Itoa(n))
			}
		}
		return c.Call(ctx, "GET", "/api/v1/retention/runs", q, nil, out)
	case "run":
		return c.Call(ctx, "POST", "/api/v1/retention/run", nil, nil, out)
	default:
		return errors.New("unknown retention command")
	}
}

func runAdminAudit(ctx context.Context, c *management.Client, args []string, out *any) error {
	if len(args) < 1 {
		return errors.New("audit command requires list|verify")
	}
	if args[0] == "verify" {
		return c.Call(ctx, "GET", "/api/v1/audit/verify", nil, nil, out)
	}
	if args[0] != "list" {
		return errors.New("unknown audit command")
	}
	fs, _ := subFlags("audit list", args[1:])
	eventID := fs.String("event", "", "event scope")
	action := fs.String("action", "", "closed action")
	result := fs.String("result", "", "ok|denied|error")
	actor := fs.String("actor", "", "actor id")
	since := fs.Int64("since", 0, "inclusive Unix-second lower bound")
	until := fs.Int64("until", 0, "inclusive Unix-second upper bound")
	limit := fs.Int("limit", 50, "page size")
	offset := fs.Int("offset", 0, "page offset")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	q := url.Values{}
	if *eventID != "" {
		q.Set("event_id", *eventID)
	}
	if *action != "" {
		q.Set("action", *action)
	}
	if *result != "" {
		q.Set("result", *result)
	}
	if *actor != "" {
		q.Set("actor", *actor)
	}
	if *since > 0 {
		q.Set("since", strconv.FormatInt(*since, 10))
	}
	if *until > 0 {
		q.Set("until", strconv.FormatInt(*until, 10))
	}
	q.Set("limit", strconv.Itoa(*limit))
	q.Set("offset", strconv.Itoa(*offset))
	return c.Call(ctx, "GET", "/api/v1/audit", q, nil, out)
}
