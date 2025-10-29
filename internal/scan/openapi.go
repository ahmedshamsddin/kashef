package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
	brokenauth "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api2_broken_auth"
	ssrf "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api7_ssrf"
	securitymisconfig "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api8_security_misconfig"
	"github.com/getkin/kin-openapi/openapi3"
)

func RunOpenAPIScan(specPath, out string, headers []string, timeout time.Duration, concurrency int, failOn string, verbose bool, allowWrite bool, token string) (int, error) {
	ctx := context.Background()
	sp, err := openapi.Load(ctx, specPath)
	if err != nil {
		return 2, err
	}

	client := &http.Client{Timeout: timeout}
	hdrs := parseHeaders(headers)

	var findings []report.Finding
	findings = append(findings, headBase(client, sp.Server, hdrs)...)

	type job struct {
		op openapi.Operation
	}

	// Debug counters
	var testedSecured int32
	var flaggedNoToken int32

	detCtx := brokenauth.Context{
		BaseURL:    sp.Server,
		Client:     client,
		Headers:    hdrs,
		AllowWrite: allowWrite,
		Verbose:    verbose,
	}

	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			//1) Broken Auth (no-token) for ANY secured op (GET/POST/PUT/PATCH/DELETE)
			if j.op.RequiresAuth {
				atomic.AddInt32(&testedSecured, 1)
				if verbose {
					fmt.Printf("[no-token] testing %s %s\n", strings.ToUpper(j.op.Method), j.op.Path)
				}
			}
			fsNoTok := brokenauth.DetectNoToken(ctx, detCtx, j.op)
			if len(fsNoTok) > 0 {
				atomic.AddInt32(&flaggedNoToken, int32(len(fsNoTok)))
				if verbose {
					fmt.Printf("[no-token] FLAGGED %s %s -> %d finding(s)\n",
						strings.ToUpper(j.op.Method), j.op.Path, len(fsNoTok))
				}
			}
			fsJWT := brokenauth.DetectJWTAlgNone(ctx, detCtx, j.op)
			if len(fsJWT) > 0 {
				atomic.AddInt32(&flaggedNoToken, int32(len(fsJWT))) // you can keep using same counter or make separate
				if verbose {
					fmt.Printf("[jwt-none] FLAGGED %s %s -> %d finding(s)\n", strings.ToUpper(j.op.Method), j.op.Path, len(fsJWT))
				}
			}
			//2) Your existing GET-only checks (schema/spec mismatch)
			var fsGET []report.Finding
			if strings.ToUpper(j.op.Method) == http.MethodGet && j.op.Raw != nil {
				fsGET = checkGET(ctx, client, sp.Server, j.op.Path, j.op.Raw, hdrs)
			}
			//Error disclosure
			fsED := securitymisconfig.CheckErrorDisclosure(ctx, client, sp.Server, j.op.Path, j.op.Method, hdrs)
			if len(fsED) > 0 {
				fmt.Printf("[error-disclosure] FLAGGED %s %s -> %d finding(s)\n", j.op.Method, j.op.Path, len(fsED))
			}

			api7Ctx := ssrf.Context{
				BaseURL:    detCtx.BaseURL,
				Client:     detCtx.Client,
				Headers:    detCtx.Headers,
				AllowWrite: detCtx.AllowWrite,
				Verbose:    detCtx.Verbose,
				Token:      token,
			}
			fsSSRF := ssrf.DetectSSRF(ctx, api7Ctx, j.op)
			if len(fsSSRF) > 0 {
				fmt.Printf("[ssrf] FLAGGED %s %s -> %d finding(s)\n", j.op.Method, j.op.Path, len(fsSSRF))
			}

			// merge
			mu.Lock()
			findings = append(findings, fsNoTok...)
			findings = append(findings, fsGET...)
			findings = append(findings, fsJWT...)
			findings = append(findings, fsED...)
			findings = append(findings, fsSSRF...)
			mu.Unlock()
		}
	}

	// Spin up workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	// Enqueue ALL operations (not just GET)
	for _, o := range sp.Operations() {
		jobs <- job{op: o}
	}
	close(jobs)
	wg.Wait()

	if verbose {
		fmt.Printf("BrokenAuth(no-token): tested=%d flagged=%d\n", testedSecured, flaggedNoToken)
	}

	// Global header/CORS checks (base URL)
	findings = append(findings, checkCORSandHeaders(client, sp.Server, hdrs)...)

	// Write report
	rep := report.Report{Scanner: "kashef", Target: sp.Server, Findings: findings}
	if strings.HasSuffix(strings.ToLower(out), ".md") {
		if err := writeMarkdown(rep, out); err != nil {
			return 2, err
		}
	} else {
		if err := writeJSON(rep, out); err != nil {
			return 2, err
		}
	}

	// CI fail-on severity
	threshold := report.Rank(strings.ToLower(failOn))
	maxSeen := 0
	for _, f := range findings {
		if r := report.Rank(f.Severity); r > maxSeen {
			maxSeen = r
		}
	}
	if maxSeen >= threshold && threshold > 0 {
		return 1, nil
	}
	return 0, nil
}

func headBase(client *http.Client, base string, hdr http.Header) []report.Finding {
	req, _ := http.NewRequest(http.MethodHead, base, nil)
	req.Header = hdr.Clone()
	resp, err := client.Do(req)
	out := []report.Finding{}
	if err != nil {
		return append(out, report.Finding{
			ID: "A-0002", Severity: "high", Category: "connectivity",
			Evidence: map[string]interface{}{"error": err.Error()},
		})
	}
	defer closeBody(resp)
	out = append(out, report.Finding{
		ID: "A-0000", Severity: "info", Category: "connectivity",
		Evidence: map[string]interface{}{"status": resp.StatusCode},
	})
	if resp.StatusCode >= 500 {
		out = append(out, report.Finding{
			ID: "A-0001", Severity: "medium", Category: "runtime",
			Evidence: map[string]interface{}{"status": resp.StatusCode},
		})
	}
	return out
}

func parseHeaders(hs []string) http.Header {
	h := http.Header{}

	for _, s := range hs {
		if i := strings.Index(s, ":"); i > 0 {
			k := strings.TrimSpace(s[:i])
			v := strings.TrimSpace(s[i+1:])
			h.Add(k, v)
		}
	}
	return h
}

func compareAgainstSchemaObject(schema *openapi3.Schema, data any) []map[string]interface{} {
	results := []map[string]interface{}{}
	if schema == nil {
		return results
	}

	// If array: best-effort validate first item as object
	if schema.Items != nil && schema.Items.Value != nil {
		if arr, ok := data.([]any); ok && len(arr) > 0 {
			return compareAgainstSchemaObject(schema.Items.Value, arr[0])
		}
		// Type hint (schema says array, got non-array)
		if _, ok := data.([]any); !ok {
			results = append(results, map[string]interface{}{
				"reason":   "expected array per schema",
				"dataType": fmt.Sprintf("%T", data),
			})
		}
		return results
	}

	// Treat as object-like if there are properties, or additionalProperties is defined (boolean or schema)
	objLike := len(schema.Properties) > 0 ||
		schema.AdditionalProperties.Schema != nil ||
		schema.AdditionalProperties.Has != nil
	if !objLike {
		return results // nothing concrete to check
	}

	// Must be an object at runtime
	obj, ok := data.(map[string]any)
	if !ok {
		results = append(results, map[string]interface{}{
			"reason":   "expected object per schema",
			"dataType": fmt.Sprintf("%T", data),
		})
		return results
	}

	// Declared property set
	declared := map[string]struct{}{}
	for name := range schema.Properties {
		declared[name] = struct{}{}
	}

	// Missing required
	var missing []string
	for _, req := range schema.Required {
		if _, ok := obj[req]; !ok {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		results = append(results, map[string]interface{}{"missingRequired": missing})
	}

	// Determine if additionalProperties is allowed.
	// Default OpenAPI behavior: allowed unless explicitly set to false.
	allowed := true
	ap := schema.AdditionalProperties
	switch {
	case ap.Schema != nil:
		allowed = true // schema for additional props → allowed
	case ap.Has != nil:
		allowed = *ap.Has // boolean form provided
	default:
		allowed = true // no info → default allow
	}

	// Extra fields (only when explicitly disallowed)
	if !allowed {
		var extra []string
		for k := range obj {
			if _, ok := declared[k]; !ok {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			results = append(results, map[string]interface{}{"extraFields": extra})
		}
	}

	return results
}
func checkGET(ctx context.Context, client *http.Client, base, pth string, op *openapi3.Operation, hdr http.Header) []report.Finding {
	url := strings.TrimRight(base, "/") + pth

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header = hdr.Clone()

	resp, err := client.Do(req)
	out := []report.Finding{}
	if err != nil {
		return append(out, report.Finding{
			ID: "A-012", Severity: "high", Category: "runtime",
			Endpoint: pth, Method: "GET",
			Evidence: map[string]interface{}{"error": err.Error()},
		})
	}
	// close once, at the end
	defer closeBody(resp)

	// --- Status drift check ---
	decl := map[int]struct{}{}
	for code := range op.Responses.Map() {
		if n, e := parseStatus(code); e == nil {
			decl[n] = struct{}{}
		}
	}
	if len(decl) > 0 {
		if _, ok := decl[resp.StatusCode]; !ok {
			out = append(out, report.Finding{
				ID: "A-010", Severity: "medium", Category: "spec-runtime-mismatch",
				Endpoint: pth, Method: "GET",
				Evidence: map[string]interface{}{"status": resp.StatusCode, "declared": keys(decl)},
				Remedy:   "Align handler or declare status in OpenAPI.",
			})
		}
	}

	// --- JSON schema validation (only if JSON) ---
	ct := strings.ToLower(resp.Header.Get("content-type"))
	if strings.HasPrefix(ct, "application/json") {
		body, _ := io.ReadAll(resp.Body)

		if len(body) == 0 {
			out = append(out, report.Finding{
				ID: "A-013", Severity: "medium", Category: "runtime",
				Endpoint: pth, Method: "GET",
				Evidence: map[string]interface{}{"reason": "empty JSON body"},
				Remedy:   "Ensure handler returns a valid JSON body or correct Content-Type.",
			})
			return out
		}

		// Pick the declared schema (for this status or fallback 200)
		if sch := pickJSONSchema(op, resp.StatusCode); sch != nil && sch.Value != nil {
			var data any
			if err := json.Unmarshal(body, &data); err != nil {
				out = append(out, report.Finding{
					ID: "A-014", Severity: "medium", Category: "runtime",
					Endpoint: pth, Method: "GET",
					Evidence: map[string]interface{}{"jsonParseError": err.Error()},
					Remedy:   "Return valid JSON or fix Content-Type.",
				})
			} else {
				// Lightweight object/array-of-objects check against properties/required
				findings := compareAgainstSchemaObject(sch.Value, data)
				if len(findings) > 0 {
					for _, ev := range findings {
						out = append(out, report.Finding{
							ID: "A-011", Severity: "high", Category: "schema",
							Endpoint: pth, Method: "GET",
							Evidence: ev,
							Remedy:   "Fix response to match schema properties/required or update the schema.",
						})
					}
				}
			}
		}
	}

	return out
}

func parseStatus(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func keys(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func pickJSONSchema(op *openapi3.Operation, status int) *openapi3.SchemaRef {
	if op == nil || op.Responses == nil {
		return nil
	}
	respMap := op.Responses.Map()

	codeStr := fmt.Sprintf("%d", status)
	var respRef *openapi3.ResponseRef
	if ref, ok := respMap[codeStr]; ok {
		respRef = ref
	} else if ref, ok := respMap["200"]; ok {
		respRef = ref
	}
	if respRef == nil || respRef.Value == nil {
		return nil
	}
	mt := respRef.Value.Content.Get("application/json")
	if mt == nil || mt.Schema == nil {
		return nil
	}
	return mt.Schema
}

func checkCORSandHeaders(client *http.Client, base string, hdr http.Header) []report.Finding {
	out := []report.Finding{}
	req, _ := http.NewRequest(http.MethodOptions, base, nil)
	req.Header = hdr.Clone()
	if resp, err := client.Do(req); err == nil {
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acc := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
		if acao == "*" && acc == "true" {
			out = append(out, report.Finding{
				ID: "A-020", Severity: "high", Category: "cors",
				Evidence: map[string]interface{}{"allow-origin": acao, "allow-credentials": acc},
				Remedy:   "Do not use wildcard origin with credentials; restrict origins.",
			})
		}
		closeBody(resp)
	}

	req2, _ := http.NewRequest(http.MethodOptions, base, nil)
	req2.Header = hdr.Clone()

	if resp, err := client.Do(req2); err == nil {
		present := map[string]bool{}
		for k := range resp.Header {
			present[strings.ToLower(k)] = true
		}
		var missing []string

		for _, h := range []string{"strict-transport-security", "x-frame-options", "x-content-type-options"} {
			if !present[h] {
				missing = append(missing, h)
			}
		}

		if len(missing) > 0 {
			out = append(out, report.Finding{
				ID: "A-023", Severity: "medium", Category: "headers",
				Evidence: map[string]interface{}{"missing": missing},
				Remedy:   "Add standard security headers.",
			})
		}
		closeBody(resp)
	}

	return out
}

// Write JSON
func writeJSON(rep report.Report, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// Write Markdown
func writeMarkdown(rep report.Report, out string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# kashef Report\n- Target: `%s`\n\n", rep.Target)
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "## %s — %s\n- Severity: **%s**\n- Category: `%s`\n",
			f.ID, f.Category, f.Severity, f.Category)
		if f.Endpoint != "" {
			fmt.Fprintf(&b, "- Endpoint: `%s` `%s`\n", f.Endpoint, f.Method)
		}
		if len(f.Evidence) > 0 {
			ev, _ := json.MarshalIndent(f.Evidence, "", "  ")
			fmt.Fprintf(&b, "```json\n%s\n```\n", ev)
		}
		if f.Remedy != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n", f.Remedy)
		}
		fmt.Fprintln(&b)
	}
	return os.WriteFile(out, []byte(b.String()), 0o644)
}
