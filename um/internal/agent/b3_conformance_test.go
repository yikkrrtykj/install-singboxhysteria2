package agent

// B3 REC fixture binding. These are the frozen UM-B3 cases from
// docs/um/um-127/conformance/transport-recovery.cases.json; the runtime tests
// named REC17/18/27 execute those setup/expected semantics against the real
// center. This test prevents the fixture from silently drifting away from the
// values used by the agent tests.

import (
	"encoding/json"
	"os"
	"testing"
)

type b3RECDoc struct {
	ContractRevision int `json:"contract_revision"`
	Cases            []struct {
		ID    string `json:"id"`
		Slice string `json:"slice"`
		Setup struct {
			Agent struct {
				BootState        string   `json:"boot_state"`
				Spool            []string `json:"spool"`
				Generation       uint64   `json:"generation"`
				NextSeqPersisted *uint64  `json:"next_seq_persisted"`
				NextSeqVolatile  *uint64  `json:"next_seq_volatile"`
			} `json:"agent"`
			Center struct {
				HighestGen uint64 `json:"highest_gen"`
				LastSeq    uint64 `json:"last_seq"`
			} `json:"center"`
		} `json:"setup"`
		Expected struct {
			HTTPStatus     int    `json:"http_status"`
			Error          string `json:"error"`
			Result         string `json:"result"`
			CenterRequests int    `json:"center_requests"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadB3REC(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/um/um-127/conformance/transport-recovery.cases.json")
	if err != nil {
		t.Fatalf("read frozen REC fixture: %v", err)
	}
	var doc b3RECDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse frozen REC fixture: %v", err)
	}
	if doc.ContractRevision != 5 {
		t.Fatalf("fixture contract_revision=%d, want 5", doc.ContractRevision)
	}
	seen := map[string]bool{}
	for _, c := range doc.Cases {
		if c.ID == "REC-17" {
			if c.Slice != "UM-B3" || c.Setup.Agent.BootState != "missing" || len(c.Setup.Agent.Spool) != 2 || c.Expected.CenterRequests != 0 {
				t.Fatalf("REC-17 fixture drift: %+v", c)
			}
		}
		if c.ID == "REC-18" {
			if c.Slice != "UM-B3" || c.Setup.Center.HighestGen != 12 || c.Setup.Agent.Generation != 9 ||
				c.Expected.HTTPStatus != 409 || c.Expected.Error != "stale_boot_generation" {
				t.Fatalf("REC-18 fixture drift: %+v", c)
			}
		}
		if c.ID == "REC-27" {
			if c.Slice != "UM-B3" || c.Setup.Center.HighestGen != 3 || c.Setup.Center.LastSeq != 4 ||
				c.Setup.Agent.NextSeqPersisted == nil || *c.Setup.Agent.NextSeqPersisted != 4 ||
				c.Expected.HTTPStatus != 200 || c.Expected.Result != "duplicate" {
				t.Fatalf("REC-27 fixture drift: %+v", c)
			}
		}
		if c.Slice == "UM-B3" {
			seen[c.ID] = true
		}
	}
	for _, id := range []string{"REC-17", "REC-18", "REC-27"} {
		if !seen[id] {
			t.Fatalf("missing frozen B3 REC %s", id)
		}
	}
	return seen
}

func TestB3RECFixturesAreBound(t *testing.T) {
	seen := loadB3REC(t)
	if len(seen) != 3 {
		t.Fatalf("UM-B3 REC fixture count=%d, want 3", len(seen))
	}
}
