// kortex-engine: the step-15 engine skeleton. Coraza v3.7.0 + CRS 4.25.2 as
// the inspection core, wrapped by our own proxy that enforces framing checks,
// body size limits and a per-request time budget, with decision markers and
// a loopback-only admin endpoint.
//
// Configuration is environment-only (docs/block-discriminator.md):
//
//	KORTEX_BACKEND_URL            required, upstream (stub backend)
//	KORTEX_RULES_DIR              default crs
//	KORTEX_RULE_ENGINE            On | DetectionOnly (default On)
//	KORTEX_BLOCKING_PARANOIA      default 1
//	KORTEX_DETECTION_PARANOIA     default 1
//	KORTEX_MAX_BODY_BYTES         default 13107200
//	KORTEX_MAX_INSPECTED_BYTES    default 131072
//	KORTEX_ENGINE_TIME_BUDGET_MS  default 2000 (0 = expire immediately)
//	KORTEX_LISTEN_ADDR            default :8080
//	KORTEX_EVENTS_FILE            default kortex-events.jsonl
//	KORTEX_AUDIT_LOG              default audit.log
//	KORTEX_ERROR_LOG              default unset: no error log (step 25)
//	KORTEX_CRS_TEST_SETUP         "on" = CRS regression suite setup, TEST ONLY (step 25)
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	// worker-child mode (T3): the parent spawns this binary with
	// --kortex-worker-child; run the inspection loop and exit
	if len(os.Args) > 1 && os.Args[1] == "--kortex-worker-child" {
		workerMain()
		return
	}
	cfg := loadConfig()
	if cfg.BackendURL == "" {
		fmt.Fprintln(os.Stderr, "kortex-engine: KORTEX_BACKEND_URL is required")
		os.Exit(2)
	}
	handler := buildHandler(cfg)

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kortex-engine: listen: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("kortex-engine: effective config: backend_url=%s rule_engine=%s blocking_paranoia=%d "+
		"detection_paranoia=%d max_body_bytes=%d max_inspected_bytes=%d engine_time_budget_ms=%d "+
		"rules_dir=%s listen_addr=%s events_file=%s audit_log=%s request_body_target_updates=%d "+
		"error_log=%s crs_test_setup=%t\n",
		cfg.BackendURL, cfg.RuleEngine, cfg.BlockingParanoia, cfg.DetectionParanoia,
		cfg.MaxBodyBytes, cfg.MaxInspectedBytes, cfg.EngineTimeBudgetMS, cfg.RulesDir,
		cfg.ListenAddr, cfg.EventsFile, cfg.AuditLog, len(cfg.RequestBodyTargetIDs),
		cfg.ErrorLog, cfg.CRSTestSetup)

	srv := newEngineServer(handler)
	srv.ReadTimeout = 60 * time.Second
	if err := srv.Serve(newGatedListener(ln, cfg)); err != nil {
		fmt.Fprintf(os.Stderr, "kortex-engine: serve: %v\n", err)
		os.Exit(2)
	}
}

// newEngineServer is the one place main() and the tests build the HTTP
// server. The gate judges the first request of a connection, so a connection
// must never carry a second one: keep-alive is off, which closes the
// connection after every answer, including the ones net/http writes itself
// (OPTIONS *) and the admin paths.
func newEngineServer(handler http.Handler) *http.Server {
	srv := &http.Server{Handler: handler}
	srv.SetKeepAlivesEnabled(false)
	return srv
}
