package center_test

// Normative REC fixture binding for B2. The scenarios are synthetic transport
// drivers, but every final status/error/result asserted by a B2 REC test is read
// from the frozen REC JSON rather than copied into the test.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

const b2RECPath = "../../../docs/um/um-127/conformance/transport-recovery.cases.json"

type b2RECDoc struct {
	ContractRevision int         `json:"contract_revision"`
	Cases            []b2RECCase `json:"cases"`
}

type b2RECCase struct {
	ID      string `json:"id"`
	Slice   string `json:"slice"`
	Title   string `json:"title"`
	Attempt struct {
		Gen      uint64 `json:"gen"`
		Seq      uint64 `json:"seq"`
		ReportID string `json:"report_id"`
	} `json:"attempt"`
	Expected struct {
		HTTP        int    `json:"http_status"`
		Result      string `json:"result"`
		Error       string `json:"error"`
		CenterState struct {
			HighestGen *uint64 `json:"highest_gen"`
			LastSeq    *uint64 `json:"last_seq"`
		} `json:"center_state"`
	} `json:"expected"`
}

func b2REC(t *testing.T, id string) b2RECCase {
	t.Helper()
	raw, err := os.ReadFile(b2RECPath)
	if err != nil {
		t.Fatalf("read REC fixture: %v", err)
	}
	var doc b2RECDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse REC fixture: %v", err)
	}
	if doc.ContractRevision != 5 {
		t.Fatalf("REC contract_revision=%d, want 5", doc.ContractRevision)
	}
	for _, c := range doc.Cases {
		if c.ID == id {
			if c.Slice != "UM-B2" && id != "REC-29" {
				t.Fatalf("%s slice=%q, want UM-B2", id, c.Slice)
			}
			return c
		}
	}
	t.Fatalf("REC case %s missing from fixture", id)
	return b2RECCase{}
}

// b2AssertREC compares the final HTTP status/result/error with the normative
// fixture expected fields. Center-state fields are checked separately where the
// fixture pins them.
func b2AssertREC(t *testing.T, id string, status int, resp map[string]any) {
	t.Helper()
	c := b2REC(t, id)
	if c.Expected.HTTP != 0 && status != c.Expected.HTTP {
		t.Fatalf("%s fixture HTTP=%d, got %d (%v)", id, c.Expected.HTTP, status, resp)
	}
	if c.Expected.Error != "" {
		if got, _ := resp["error"].(string); got != c.Expected.Error {
			t.Fatalf("%s fixture error=%q, got %q", id, c.Expected.Error, got)
		}
		return
	}
	if c.Expected.Result != "" {
		if got, _ := resp["result"].(string); got != c.Expected.Result {
			t.Fatalf("%s fixture result=%q, got %q", id, c.Expected.Result, got)
		}
	}
}

// b2AssertRECCenter compares the persistent center high-water with fixture
// center_state fields that are machine-readable (highest_gen/last_seq). The
// fixture's shorthand boot_id values are not protocol-formatted 32-hex ids and
// are not invented into the synthetic driver.
func b2AssertRECCenter(t *testing.T, id string, tc *testCenter, nodeID string) {
	t.Helper()
	c := b2REC(t, id)
	boot, err := tc.store.GetBoot(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("%s center boot read: %v", id, err)
	}
	if c.Expected.CenterState.HighestGen != nil && boot.HighestGen != *c.Expected.CenterState.HighestGen {
		t.Fatalf("%s highest_gen=%d, fixture want %d", id, boot.HighestGen, *c.Expected.CenterState.HighestGen)
	}
	if c.Expected.CenterState.LastSeq != nil && boot.LastSeq != *c.Expected.CenterState.LastSeq {
		t.Fatalf("%s last_seq=%d, fixture want %d", id, boot.LastSeq, *c.Expected.CenterState.LastSeq)
	}
}
