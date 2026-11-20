package main

import (
	"fmt"
	"os"
	"strconv"
)

// Config is the engine's runtime configuration, read from environment
// variables. All values are printed at startup and served on /__kortex/config
// (loopback only) so the effective configuration is provable in-container.
type Config struct {
	BackendURL         string
	RulesDir           string
	RuleEngine         string // On | DetectionOnly
	BlockingParanoia   int
	DetectionParanoia  int
	MaxBodyBytes       int64 // hard ceiling for a request body
	MaxInspectedBytes  int64 // bodies above this are rejected 413, not passed to the engine
	EngineTimeBudgetMS int64 // per-request engine time budget; 0 = expire immediately
	ListenAddr         string
	EventsFile         string
	AuditLog           string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return def
		}
		return n
	}
	return def
}

func loadConfig() *Config {
	return &Config{
		BackendURL:         envOr("KORTEX_BACKEND_URL", ""),
		RulesDir:           envOr("KORTEX_RULES_DIR", "crs"),
		RuleEngine:         envOr("KORTEX_RULE_ENGINE", "On"),
		BlockingParanoia:   int(envInt("KORTEX_BLOCKING_PARANOIA", 1)),
		DetectionParanoia:  int(envInt("KORTEX_DETECTION_PARANOIA", 1)),
		MaxBodyBytes:       envInt("KORTEX_MAX_BODY_BYTES", 13107200),
		MaxInspectedBytes:  envInt("KORTEX_MAX_INSPECTED_BYTES", 131072),
		EngineTimeBudgetMS: envInt("KORTEX_ENGINE_TIME_BUDGET_MS", 2000),
		ListenAddr:         envOr("KORTEX_LISTEN_ADDR", ":8080"),
		EventsFile:         envOr("KORTEX_EVENTS_FILE", "kortex-events.jsonl"),
		AuditLog:           envOr("KORTEX_AUDIT_LOG", "audit.log"),
	}
}

// directives renders the SecLang config: engine settings, the CRS setup
// SecActions mirroring the pinned container's activated crs-setup.conf
// (ids 900000, 900001, 900110), audit directives, and the rule Include.
func (c *Config) directives() string {
	engine := "On"
	if c.RuleEngine == "DetectionOnly" {
		engine = "DetectionOnly"
	}
	return fmt.Sprintf(`
SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:4|5)"
SecAuditLog %s
SecAuditLogFormat JSON
SecAuditLogType Serial

SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4252"

# C4 (decision 0002 addendum): the engine has NO content-type allow-list.
# The CRS customization point 900220 sets the allowed list per-request to the
# request's own content type, so 920420 never blocks on content type while
# body processors still act per content type.
SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\s]+" "id:900220,phase:1,pass,nolog,t:none,capture,setvar:'tx.allowed_request_content_type=|%%{tx.0}|'"

Include %s/owasp-crs/rules/*.conf
`, engine, c.MaxBodyBytes, c.MaxInspectedBytes, c.AuditLog,
		c.BlockingParanoia, c.DetectionParanoia, c.RulesDir)
}
