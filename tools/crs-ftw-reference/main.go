// crs-ftw-reference: stock coraza as a Go middleware in front of albedo, in
// the configuration coraza's own harness uses for the CRS regression suite
// (coraza v3.8.1 testing/coreruleset/coreruleset_test.go, TestFTW): the
// reference of step 25 for "what coraza itself does on this test"
// (docs/plan-step25-crs-regression.md). It is not the engine and shares no
// code with it.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	albedo "github.com/coreruleset/albedo/server"
)

// customTestingConfig is copied from coraza's TestFTW, without its three
// SecDefaultAction lines for phases 3 to 5: crs-setup.conf.example of CRS
// v4.25.2 defines them itself, and coraza refuses a second definition
// ("SecDefaultAction already defined for this phase").
const customTestingConfig = `
SecResponseBodyMimeType text/plain

SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  pass,\
  t:none,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
`

func main() {
	listen := flag.String("listen", "127.0.0.1:18090", "listen address")
	corazaConf := flag.String("coraza-conf", "", "path of coraza.conf-recommended")
	crsSetup := flag.String("crs-setup", "", "path of crs-setup.conf.example")
	rules := flag.String("rules", "", "directory with the CRS rule files")
	errorLog := flag.String("error-log", "error.log", "error log path")
	xmlAttr := flag.Bool("xml-attr-inspect", false, "add rule 900511 (tx.crs_xml_attr_inspect=1), as the CRS compose file of v4.25.2 does; coraza's harness does not")
	flag.Parse()

	rec, err := os.ReadFile(*corazaConf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coraza conf:", err)
		os.Exit(2)
	}
	f, err := os.OpenFile(*errorLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error log:", err)
		os.Exit(2)
	}
	extra := ""
	if *xmlAttr {
		extra = "\nSecAction \"id:900511,phase:1,pass,nolog,setvar:tx.crs_xml_attr_inspect=1\"\n"
	}
	var mu sync.Mutex
	conf := coraza.NewWAFConfig().
		WithDirectives(string(rec)).
		WithDirectives(customTestingConfig + extra).
		WithDirectives("Include " + *crsSetup).
		WithDirectives("Include " + *rules + "/*.conf").
		WithErrorCallback(func(mr types.MatchedRule) {
			mu.Lock()
			io.WriteString(f, mr.ErrorLog()+"\n")
			mu.Unlock()
		})
	waf, err := coraza.NewWAF(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "waf:", err)
		os.Exit(2)
	}
	handler := txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		// as in coraza's harness: albedo's answers are inspected as text/plain
		w.Header().Set("Content-Type", "text/plain")
		albedo.Handler().ServeHTTP(w, r)
	}))
	fmt.Printf("crs-ftw-reference: coraza middleware on %s, error log %s, rule 900511 (xml attribute inspection) %t\n", *listen, *errorLog, *xmlAttr)
	if err := http.ListenAndServe(*listen, handler); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(2)
	}
}
