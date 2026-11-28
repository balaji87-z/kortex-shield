// Step-23 T5: reference Go backend for the strict-parsing differential.
//
// A local net/http server (stdlib only) that answers every request with a
// JSON description of what it saw, in the same shape as
// tools/step23_parsing_backend.py. net/http parses the request line, the
// headers and the framing itself (and answers 400 on its own for what it
// refuses); the body is whatever r.Body yields. After the body the handler
// hijacks the connection and waits 150 ms for bytes that are still there
// (leftover_len): bytes this server would parse as the next request on a
// kept-alive connection.
//
// Usage: parsing-diff-gobackend PORT     (binds 127.0.0.1 only, rule 6)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// bodyParse (step 27): what the standard parsers make of the body, chosen by
// the media type as a handler would: every key and string value the parser
// yields, the content of file parts apart, or the parser's error.
type bodyParse struct {
	Kind        string   `json:"kind"`
	Strings     []string `json:"strings"`
	FileStrings []string `json:"file_strings"`
	Error       *string  `json:"error"`
}

func jsonStrings(doc any, out *[]string) {
	switch v := doc.(type) {
	case map[string]any:
		for k, x := range v {
			*out = append(*out, k)
			jsonStrings(x, out)
		}
	case []any:
		for _, x := range v {
			jsonStrings(x, out)
		}
	case string:
		*out = append(*out, v)
	}
}

func parseBody(r *http.Request, body []byte) bodyParse {
	out := bodyParse{Kind: "none", Strings: []string{}, FileStrings: []string{}}
	fail := func(err error) bodyParse {
		msg := fmt.Sprintf("%T", err)
		out.Error = &msg
		return out
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		media = strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	switch {
	case media == "application/x-www-form-urlencoded":
		out.Kind = "urlencoded"
		err := r.ParseForm()
		for k, vs := range r.PostForm {
			out.Strings = append(out.Strings, k)
			out.Strings = append(out.Strings, vs...)
		}
		if err != nil {
			return fail(err)
		}
	case media == "multipart/form-data":
		out.Kind = "multipart"
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			return fail(err)
		}
		for k, vs := range r.MultipartForm.Value {
			out.Strings = append(out.Strings, k)
			out.Strings = append(out.Strings, vs...)
		}
		for k, fhs := range r.MultipartForm.File {
			out.Strings = append(out.Strings, k)
			for _, fh := range fhs {
				out.Strings = append(out.Strings, fh.Filename)
				if f, err := fh.Open(); err == nil {
					b, _ := io.ReadAll(f)
					f.Close()
					out.FileStrings = append(out.FileStrings, string(b))
				}
			}
		}
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		out.Kind = "json"
		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			return fail(err)
		}
		jsonStrings(doc, &out.Strings)
	case media == "application/xml" || media == "text/xml" || strings.HasSuffix(media, "+xml"):
		out.Kind = "xml"
		dec := xml.NewDecoder(bytes.NewReader(body))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fail(err)
			}
			switch t := tok.(type) {
			case xml.StartElement:
				out.Strings = append(out.Strings, t.Name.Local)
				for _, a := range t.Attr {
					out.Strings = append(out.Strings, a.Value)
				}
			case xml.CharData:
				if s := strings.TrimSpace(string(t)); s != "" {
					out.Strings = append(out.Strings, s)
				}
			}
		}
	}
	return out
}

type view struct {
	Backend          string              `json:"backend"`
	Method           string              `json:"method"`
	Target           string              `json:"target"`
	PathRaw          string              `json:"path_raw"`
	PathDecoded      string              `json:"path_decoded"`
	QueryRaw         string              `json:"query_raw"`
	QueryDecoded     map[string][]string `json:"query_decoded"`
	QueryError       string              `json:"query_error,omitempty"`
	ContentLengthHdr []string            `json:"content_length_headers"`
	TransferEncHdr   []string            `json:"transfer_encoding_headers"`
	BodyFraming      string              `json:"body_framing"`
	BodyLen          int                 `json:"body_len"`
	BodySHA256       string              `json:"body_sha256"`
	LeftoverLen      int                 `json:"leftover_len"`
	BodyParse        bodyParse           `json:"body_parse"`
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	pathRaw, _, _ := strings.Cut(r.RequestURI, "?")
	query, qerr := url.ParseQuery(r.URL.RawQuery)
	framing := "none"
	switch {
	case len(r.TransferEncoding) > 0:
		framing = "transfer-encoding:" + strings.Join(r.TransferEncoding, ",")
	case r.ContentLength >= 0 && r.Header.Get("Content-Length") != "":
		framing = "content-length"
	}
	v := view{
		Backend:          "go-net/http",
		Method:           r.Method,
		Target:           r.RequestURI,
		PathRaw:          pathRaw,
		PathDecoded:      r.URL.Path,
		QueryRaw:         r.URL.RawQuery,
		QueryDecoded:     query,
		ContentLengthHdr: append([]string{}, r.Header.Values("Content-Length")...),
		TransferEncHdr:   append([]string{}, r.TransferEncoding...),
		BodyFraming:      framing,
		BodyLen:          len(body),
		BodySHA256:       hex.EncodeToString(sum[:]),
	}
	if qerr != nil {
		v.QueryError = qerr.Error()
	}
	v.BodyParse = parseBody(r, body)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	left, _ := io.ReadAll(io.LimitReader(rw.Reader, 65536))
	v.LeftoverLen = len(left)
	payload, _ := json.Marshal(v)
	fmt.Fprintf(rw.Writer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload))
	rw.Writer.Write(payload)
	rw.Writer.Flush()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: parsing-diff-gobackend PORT")
		os.Exit(2)
	}
	srv := &http.Server{Addr: "127.0.0.1:" + os.Args[1], Handler: http.HandlerFunc(handle), ReadTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
