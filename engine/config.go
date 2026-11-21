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
	AllowedMethods     string // method allow-list handed to CRS 911100 (tx.allowed_methods)
	MaxInflightBody    int64  // hard cap on concurrent in-flight body-processing calls
	ListenAddr         string
	EventsFile         string
	CorazaDebugLevel   string
	CorazaDebugFile    string
	AuditLog           string
	// RequestBodyTargetIDs is the sorted list of CRS rule ids that received a
	// REQUEST_BODY target via SecRuleUpdateTargetById (step-18 T4, body
	// parsing fidelity). Computed by directives() at WAF build; printed at
	// startup and served on /__kortex/config so the effective configuration
	// is provable per run (rule 29).
	RequestBodyTargetIDs []int
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
		AllowedMethods:     envOr("KORTEX_ALLOWED_METHODS", "GET HEAD POST OPTIONS"),
		MaxInflightBody:    envInt("KORTEX_MAX_INFLIGHT_BODY", 8),
		ListenAddr:         envOr("KORTEX_LISTEN_ADDR", ":8080"),
		EventsFile:         envOr("KORTEX_EVENTS_FILE", "kortex-events.jsonl"),
		CorazaDebugLevel:   os.Getenv("KORTEX_CORAZA_DEBUG_LEVEL"),
		CorazaDebugFile:    os.Getenv("KORTEX_CORAZA_DEBUG_FILE"),
		AuditLog:           envOr("KORTEX_AUDIT_LOG", "audit.log"),
	}
}

// directives renders the SecLang config: engine settings, the CRS setup
// SecActions mirroring the pinned container's activated crs-setup.conf
// (ids 900000, 900001, 900110), audit directives, the rule Include, and the
// step-18 T4 REQUEST_BODY target updates (which must come after the Include:
// SecRuleUpdateTargetById addresses already-loaded rules).
func (c *Config) directives() (string, error) {
	engine := "On"
	if c.RuleEngine == "DetectionOnly" {
		engine = "DetectionOnly"
	}
	bodyTargets, err := requestBodyTargetUpdates(c.RulesDir)
	if err != nil {
		return "", fmt.Errorf("request-body target scan: %w", err)
	}
	c.RequestBodyTargetIDs = bodyTargets
	base := fmt.Sprintf(`
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

# Method allow-list (step-17 T2, parity with the connector's crs-setup.conf
# rule 900200): CRS 911100 (PL1, critical) rejects methods outside the list.
SecAction "id:900200,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=%s'"

# C4 (decision 0002 addendum): the engine has NO content-type allow-list.
# The CRS customization point 900220 sets the allowed list per-request to the
# request's own content type, so 920420 never blocks on content type while
# body processors still act per content type.
SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\s]+" "id:900220,phase:1,pass,nolog,t:none,capture,setvar:'tx.allowed_request_content_type=|%%{tx.0}|'"

# Connector-image body-processor selection and body-parse-failure rules
# (mirror of the pinned container's /opt/coraza/config/coraza.conf lines
# 31-41; step-16 T2 BUG fix, rule 40 tests E10-E15). Without 200001 the
# CRS 901340 forced-body-variable path makes coraza fall back to the
# URLENCODED processor for JSON bodies (coraza v3.7.0 transaction.go),
# which both missed and invented detections (step-16 T1, PROVEN).
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
    "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
    "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule &ARGS "@ge 1000" \
    "id:'200007',phase:2,t:none,log,deny,status:400,msg:'Failed to fully parse request body due to large argument count',severity:2"
SecRule REQBODY_ERROR "!@eq 0" \
    "id:'200002',phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%%{reqbody_error_msg}',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation.',severity:2"

Include %s/owasp-crs/rules/*.conf
`, engine, c.MaxBodyBytes, c.MaxInspectedBytes, c.AuditLog,
		c.BlockingParanoia, c.DetectionParanoia, c.AllowedMethods, c.RulesDir)
	return base + renderBodyTargetUpdates(bodyTargets), nil
}
