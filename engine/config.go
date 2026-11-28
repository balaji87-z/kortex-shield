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
	BackendURL           string
	RulesDir             string
	RuleEngine           string // On | DetectionOnly
	BlockingParanoia     int
	DetectionParanoia    int
	MaxBodyBytes         int64  // hard ceiling for a request body
	MaxInspectedBytes    int64  // bodies above this are rejected 413, not passed to the engine
	EngineTimeBudgetMS   int64  // per-request engine time budget; 0 = expire immediately
	AllowedMethods       string // method allow-list handed to CRS 911100 (tx.allowed_methods)
	MaxInflightBody      int64  // SMALL-lane cap: concurrent in-flight body-processing calls for bodies <= BodyLaneThreshold
	MaxInflightBodyLarge int64  // LARGE-lane cap: bodies > BodyLaneThreshold, or unknown framing (no Content-Length)
	BodyLaneThreshold    int64  // declared Content-Length at or below this uses the SMALL lane (default 65536)
	TestHoldBodyMS       int64  // TEST ONLY: with X-Kortex-Test-Hold:1, sleep this long inside the slot (deterministic hold; 0 = off)
	// Worker mode (step-21 T3): killable worker subprocesses for body
	// inspection; per-client fairness state.
	WorkerMode         bool   // run body inspection in worker subprocesses
	WorkerPool         int    // service workers (default: MaxInflightBodyLarge)
	WorkerSpares       int    // pre-spawned spares (default 1)
	WorkerRecycleAfter int    // recycle a worker after N jobs (0 = never)
	ClientMaxInflight  int    // per-client body-job cap per lane; 0 = floor(lane_cap/2), at least 1 (small 4, large 1); a higher value is clamped to that
	ClientPenaltyMS    int    // penalty duration after a kill (default 10000)
	ClientPenaltyMax   int    // penalty map cap (default 4096)
	TrustedProxies     string // comma-separated CIDRs; empty = XFF ignored
	ListenAddr         string
	EventsFile         string
	CorazaDebugLevel   string
	CorazaDebugFile    string
	AuditLog           string
	// ErrorLog (step-25, E49): when set, one line per matched rule with the
	// log action, in the ModSecurity error-log form. Empty = no such log.
	ErrorLog string
	// CRSTestSetup (step-25, E50): TEST ONLY. Renders the setup of the CRS
	// regression suite, including its marker rule 999999, which switches
	// every rule off for a request that carries an X-CRS-Test header.
	CRSTestSetup bool
	// HeadTimeoutMS (step-27, E58): how long the gate waits for the end of a
	// request head before it answers 400 kortex-decision=framing
	// (head-timeout). Default 30000.
	HeadTimeoutMS int64
	// MaxPendingHeads (step-27, E62): how many accepted connections may be
	// waiting for the end of their head at once; one more is answered 503
	// kortex-decision=overload (pending-heads). Default 256.
	MaxPendingHeads int64
	// XMLAttrInspect (step-27, E66): renders CRS opt-in 900510
	// (tx.crs_xml_attr_inspect=1) so that rule 901181 leaves the target
	// XML://@* on the attack rules and XML attribute values are inspected.
	// Default off, as in the setup of the pinned images.
	XMLAttrInspect bool
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
		BackendURL:           envOr("KORTEX_BACKEND_URL", ""),
		RulesDir:             envOr("KORTEX_RULES_DIR", "crs"),
		RuleEngine:           envOr("KORTEX_RULE_ENGINE", "On"),
		BlockingParanoia:     int(envInt("KORTEX_BLOCKING_PARANOIA", 1)),
		DetectionParanoia:    int(envInt("KORTEX_DETECTION_PARANOIA", 1)),
		MaxBodyBytes:         envInt("KORTEX_MAX_BODY_BYTES", 13107200),
		MaxInspectedBytes:    envInt("KORTEX_MAX_INSPECTED_BYTES", 131072),
		EngineTimeBudgetMS:   envInt("KORTEX_ENGINE_TIME_BUDGET_MS", 2000),
		AllowedMethods:       envOr("KORTEX_ALLOWED_METHODS", "GET HEAD POST OPTIONS"),
		MaxInflightBody:      envInt("KORTEX_MAX_INFLIGHT_BODY", 8),
		MaxInflightBodyLarge: envInt("KORTEX_MAX_INFLIGHT_BODY_LARGE", 2),
		BodyLaneThreshold:    envInt("KORTEX_BODY_LANE_THRESHOLD", 65536),
		TestHoldBodyMS:       envInt("KORTEX_TEST_HOLD_BODY_MS", 0),
		WorkerMode:           envOr("KORTEX_WORKER_MODE", "") == "on",
		WorkerPool:           int(envInt("KORTEX_WORKER_POOL", 0)),
		WorkerSpares:         int(envInt("KORTEX_WORKER_SPARES", 1)),
		WorkerRecycleAfter:   int(envInt("KORTEX_WORKER_RECYCLE_AFTER", 0)),
		ClientMaxInflight:    int(envInt("KORTEX_CLIENT_MAX_INFLIGHT", 0)),
		ClientPenaltyMS:      int(envInt("KORTEX_CLIENT_PENALTY_MS", 10000)),
		ClientPenaltyMax:     int(envInt("KORTEX_CLIENT_PENALTY_MAX_ENTRIES", 4096)),
		TrustedProxies:       envOr("KORTEX_TRUSTED_PROXIES", ""),
		ListenAddr:           envOr("KORTEX_LISTEN_ADDR", ":8080"),
		EventsFile:           envOr("KORTEX_EVENTS_FILE", "kortex-events.jsonl"),
		CorazaDebugLevel:     os.Getenv("KORTEX_CORAZA_DEBUG_LEVEL"),
		CorazaDebugFile:      os.Getenv("KORTEX_CORAZA_DEBUG_FILE"),
		AuditLog:             envOr("KORTEX_AUDIT_LOG", "audit.log"),
		ErrorLog:             os.Getenv("KORTEX_ERROR_LOG"),
		CRSTestSetup:         os.Getenv("KORTEX_CRS_TEST_SETUP") == "on",
		HeadTimeoutMS:        envInt("KORTEX_HEAD_TIMEOUT_MS", 30000),
		MaxPendingHeads:      envInt("KORTEX_MAX_PENDING_HEADS", 256),
		XMLAttrInspect:       os.Getenv("KORTEX_XML_ATTR_INSPECT") == "on",
	}
}

// crsTestSetup is the setup of the CRS regression suite (docs/baseline-config.md,
// step 25): rule 900005 of the suite's README without its ctl and paranoia
// actions, 900511 from the suite's compose file, and the log marker rule
// 999999 as in coraza's own harness for the suite.
const crsTestSetup = `
SecAction "id:900005,phase:1,nolog,pass,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"
SecAction "id:900511,phase:1,pass,nolog,setvar:tx.crs_xml_attr_inspect=1"
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:999999,phase:1,pass,t:none,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
`

// xmlAttrInspectSetup is the CRS opt-in for XML attribute inspection
// (docs/baseline-config.md, step 27): the id REQUEST-901-INITIALIZATION.conf
// names for it.
const xmlAttrInspectSetup = `
SecAction "id:900510,phase:1,pass,nolog,setvar:tx.crs_xml_attr_inspect=1"
`

// directives renders the SecLang config: engine settings, the CRS setup
// SecActions mirroring the pinned container's activated crs-setup.conf
// (ids 900000, 900001, 900110), audit directives, the default actions of the
// connector image's crs-setup.conf (so a match in any phase reaches the
// audit entry, E32), the rule Include, and the
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
	testSetup := ""
	if c.CRSTestSetup {
		testSetup = crsTestSetup
	}
	if c.XMLAttrInspect {
		testSetup += xmlAttrInspectSetup
	}
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

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"

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
%s
Include %s/owasp-crs/rules/*.conf
`, engine, c.MaxBodyBytes, c.MaxInspectedBytes, c.AuditLog,
		c.BlockingParanoia, c.DetectionParanoia, c.AllowedMethods, testSetup, c.RulesDir)
	return base + renderBodyTargetUpdates(bodyTargets), nil
}
