// Command um-lab is an isolated-lab helper for exercising a real local UM
// center/SQLite boundary. It is not part of the production agent or center and
// has no network listeners; it only operates on an explicitly supplied SQLite
// database and synthetic node/event ids.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "issue-token":
		err = issueToken(os.Args[2:])
	case "configure":
		err = configure(os.Args[2:])
	case "summary":
		err = summary(os.Args[2:])
	case "r1-project":
		err = r1Project(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "um-lab:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: um-lab <issue-token|configure|summary|r1-project> [flags]")
}

func openDB(path string) (*store.Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("--db is required")
	}
	return store.Open(path)
}

func issueToken(args []string) error {
	fs := flag.NewFlagSet("issue-token", flag.ExitOnError)
	db := fs.String("db", "", "center SQLite path")
	event := fs.String("event", "", "event UUID")
	class := fs.String("class", "linux_vps", "linux_vps|windows_terminal")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *event == "" {
		return fmt.Errorf("--event is required")
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	token, hash, err := store.NewEnrollToken()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if err := st.CreateEnrollToken(context.Background(), hash, *event, *class, now+int64(ttl.Seconds()), now); err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

func configure(args []string) error {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	db := fs.String("db", "", "center SQLite path")
	nodeID := fs.String("node-id", "", "enrolled node UUID")
	sources := fs.String("sources", "", "comma-separated source=true|false pairs")
	cadence := fs.Int("cadence", 60, "cadence seconds")
	tagsJSON := fs.String("tags", "", "JSON array of {inbound_tag,kind}")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *nodeID == "" {
		return fmt.Errorf("--node-id is required")
	}
	values := map[string]bool{"system": false, "services": false, "singbox_api": false,
		"mihomo_api": false, "terminal": false, "events": true}
	for _, pair := range strings.Split(*sources, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid source pair %q", pair)
		}
		v := strings.EqualFold(parts[1], "true") || parts[1] == "1"
		values[parts[0]] = v
	}
	var tags []store.InboundTag
	if *tagsJSON != "" {
		if err := json.Unmarshal([]byte(*tagsJSON), &tags); err != nil {
			return fmt.Errorf("--tags: %w", err)
		}
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.UpdateNodeConfig(context.Background(), *nodeID, values, tags, *cadence, time.Now().Unix()); err != nil {
		return err
	}
	fmt.Println("configured")
	return nil
}

func summary(args []string) error {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	db := fs.String("db", "", "center SQLite path")
	nodeID := fs.String("node-id", "", "node UUID")
	printPayload := fs.Bool("print-payload", false, "include the latest snapshot payload")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	out := map[string]any{}
	if *nodeID != "" {
		if boot, err := st.GetBoot(context.Background(), *nodeID); err == nil {
			out["boot"] = boot
		}
		if snap, err := st.GetLatestSnapshot(context.Background(), *nodeID); err == nil {
			latest := map[string]any{
				"collected_at": snap.CollectedAt, "report_id": snap.ReportID,
			}
			if *printPayload {
				latest["payload"] = string(snap.Payload)
			}
			out["latest_snapshot"] = latest
		}
	}
	stats, err := st.CapacityStats(context.Background())
	if err != nil {
		return err
	}
	out["capacity"] = stats
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func r1Project(args []string) error {
	fs := flag.NewFlagSet("r1-project", flag.ExitOnError)
	profilePath := fs.String("profile", "", "windowsobs profile JSON")
	secretPath := fs.String("secret", "", "controller secret file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rawProfile, err := os.ReadFile(*profilePath)
	if err != nil {
		return err
	}
	var profile windowsobs.Profile
	if err := json.Unmarshal(rawProfile, &profile); err != nil {
		return err
	}
	rawSecret, err := os.ReadFile(*secretPath)
	if err != nil {
		return err
	}
	secret := strings.TrimSpace(string(rawSecret))
	observer, err := windowsobs.New(profile, secret)
	if err != nil {
		return err
	}
	snapshot := observer.Collect(context.Background())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(snapshot)
}
