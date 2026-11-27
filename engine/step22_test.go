package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// E32: a rule that matches in phase 1 is part of the request's audit entry,
// as it is in the connector's audit log. The request is a query SQLi (942100,
// phase 2) sent with the numeric Host of the test server (920350, phase 1).
// Both ids are on the block page; the audit entry must name both. Found in
// step 22: the engine audit log never carried a 920350 or 920450 message.
func TestE32Phase1MatchInAuditLog(t *testing.T) {
	srv, _ := newEnv(t, nil)
	resp := get(t, srv, "/?id=1'%20OR%20'1'='1", nil, "")
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("E32: want 403, got %d", resp.StatusCode)
	}
	for _, id := range []string{"920350", "942100"} {
		if !strings.Contains(string(page), id) {
			t.Fatalf("E32 precondition: rule %s is not among the matched rules on the block page: %q", id, page)
		}
	}
	var audit string
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(os.Getenv("KORTEX_AUDIT_LOG"))
		audit = string(b)
		if strings.Contains(audit, `[id \"942100\"]`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(audit, `[id \"942100\"]`) {
		t.Fatalf("E32 control: no audit entry with the phase-2 rule 942100 (audit log %d bytes)", len(audit))
	}
	if !strings.Contains(audit, `[id \"920350\"]`) {
		t.Fatalf("E32: the audit entry names 942100 (phase 2) but not 920350 (phase 1)")
	}
}
