// kortex-engine: the step-15 engine skeleton. Coraza v3.7.0 + CRS 4.25.2 as
// the inspection core, wrapped by our own proxy that enforces framing checks,
// body size limits and a per-request time budget, with decision markers and
// a loopback-only admin endpoint.
//
// Configuration is environment-only (docs/block-discriminator.md):
//   KORTEX_BACKEND_URL            required, upstream (stub backend)
//   KORTEX_RULES_DIR              default crs
//   KORTEX_RULE_ENGINE            On | DetectionOnly (default On)
//   KORTEX_BLOCKING_PARANOIA      default 1
//   KORTEX_DETECTION_PARANOIA     default 1
//   KORTEX_MAX_BODY_BYTES         default 13107200
//   KORTEX_MAX_INSPECTED_BYTES    default 131072
//   KORTEX_ENGINE_TIME_BUDGET_MS  default 2000 (0 = expire immediately)
//   KORTEX_LISTEN_ADDR            default :8080
//   KORTEX_EVENTS_FILE            default kortex-events.jsonl
//   KORTEX_AUDIT_LOG              default audit.log
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
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
		"rules_dir=%s listen_addr=%s events_file=%s audit_log=%s\n",
		cfg.BackendURL, cfg.RuleEngine, cfg.BlockingParanoia, cfg.DetectionParanoia,
		cfg.MaxBodyBytes, cfg.MaxInspectedBytes, cfg.EngineTimeBudgetMS, cfg.RulesDir,
		cfg.ListenAddr, cfg.EventsFile, cfg.AuditLog)

	srv := &http.Server{
		Handler:     handler,
		ReadTimeout: 60 * time.Second,
	}
	// the framing gate runs on the first request of every connection; the
	// handler answers Connection: close so every request is gated
	if err := srv.Serve(&gatedListener{Listener: ln, gateTimeout: 30 * time.Second}); err != nil {
		fmt.Fprintf(os.Stderr, "kortex-engine: serve: %v\n", err)
		os.Exit(2)
	}
}
