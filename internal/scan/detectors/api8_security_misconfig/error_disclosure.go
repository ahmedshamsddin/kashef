package api8securitymisconfig

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/report"
)

// ...existing code...

func CheckErrorDisclosure(ctx context.Context, client *http.Client, baseURL, path, method string, headers http.Header) []report.Finding {
	// ensure context
	if ctx == nil {
		ctx = context.Background()
	}

	// default method
	if method == "" {
		method = http.MethodGet
	}

	// safe client with timeout
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	// build URL
	url := baseURL + path

	// create request
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		// on request creation error, return no findings
		return nil
	}

	// safe headers cloning
	var hdr http.Header
	if headers == nil {
		hdr = http.Header{}
	} else {
		hdr = headers.Clone()
	}
	// Inject a synthetic/unsigned JWT only if no Authorization header exists
	if hdr.Get("Authorization") == "" {
		hdr.Set("Authorization", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
	}
	req.Header = hdr

	// perform request
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	// Read a limited body snippet (avoid huge bodies)
	limited := io.LimitReader(resp.Body, 4096) // slightly larger snippet for richer detection
	bodyBytes, _ := io.ReadAll(limited)        // ignore read error but best-effort

	// normalize snippet: replace excessive whitespace and keep bytes sane
	snippet := strings.TrimSpace(bytesToPrintableString(bodyBytes, 2048))

	return DetectErrorDisclosure(path, method, resp.StatusCode, snippet, resp.Header)
}

// DetectErrorDisclosure inspects an endpoint response body and headers for error disclosures.
// It returns zero or more findings. Evidence includes matched pattern and a small snippet.
func DetectErrorDisclosure(endpoint, method string, status int, body string, respHeader http.Header) []report.Finding {
	out := []report.Finding{}

	// Only consider error responses
	if status < 400 {
		return out
	}

	lowerBody := strings.ToLower(body)

	// regex patterns to detect stack traces, framework names, file/line references, and common error phrases
	regexes := []string{
		`(?i)\btraceback\b`,
		`(?i)\bexception\b`,
		`(?i)\bsyntaxerror\b`,
		`(?i)\btypeerror\b`,
		`(?i)\breferenceerror\b`,
		`(?i)\bevalerror\b`,
		`(?i)\brangeerror\b`,
		`(?i)\bstack(?:\s*trace)?\b`,
		`(?i)\bexpress\b`,
		`(?i)\bflask\b`,
		`(?i)\bdjango\b`,
		`(?i)\bspring\b`,
		`(?i)\blaravel\b`,
		`(?i)at\s+[\w\./\\:-]+:\d+`, // file path with line number
		`(?i)on\s+line\s+\d+`,
		`(?i)\bundefined\b`,
		`(?i)cannot\s+read\s+property`,
		`(?i)\bserver\s+misconfiguration\b`,
		`(?i)\bruntimeerror\b`,
		`(?i)stacktrace`,
		`(?i)panic:`,
		`(?i)fatal error`,
		`(?i)internal server error`,
	}

	// compile once and test
	for _, r := range regexes {
		re, err := regexp.Compile(r)
		if err != nil {
			continue
		}
		if loc := re.FindStringIndex(lowerBody); loc != nil {
			// extract a safe snippet around the match
			start := loc[0] - 60
			if start < 0 {
				start = 0
			}
			end := loc[1] + 60
			if end > len(body) {
				end = len(body)
			}
			match := body[loc[0]:loc[1]]
			snippet := sanitizeSnippet(body[start:end], 1000)

			evidence := map[string]any{
				"pattern":  re.String(),
				"match":    match,
				"snippet":  snippet,
				"status":   status,
				"header":   headerSummary(respHeader),
				"endpoint": endpoint,
			}

			out = append(out, report.Finding{
				ID:       "A-801",
				Severity: "medium",
				Category: "error.disclosure",
				Endpoint: endpoint,
				Method:   method,
				Evidence: evidence,
				Remedy:   "Avoid exposing detailed error messages, stack traces, or internal file paths to clients. Return generic error responses and log detailed errors server-side.",
			})
			break
		}
	}

	return out
}

// bytesToPrintableString returns a UTF-8 string from bytes and truncates to maxLen.
// Non-printable bytes are replaced by spaces.
func bytesToPrintableString(b []byte, maxLen int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	// replace control chars (except common whitespace) with spaces
	for i := range b {
		if b[i] < 0x09 || (b[i] > 0x0D && b[i] < 0x20) {
			b[i] = ' '
		}
	}
	return string(b)
}

// sanitizeSnippet trims and collapses whitespace, ensures reasonable length
func sanitizeSnippet(s string, max int) string {
	compact := strings.Join(strings.Fields(s), " ")
	if len(compact) > max {
		return compact[:max] + "..."
	}
	return compact
}

// headerSummary returns a minimal header summary (content-type and server) to include in evidence.
func headerSummary(h http.Header) map[string]string {
	if h == nil {
		return nil
	}
	out := map[string]string{}
	if ct := h.Get("Content-Type"); ct != "" {
		out["content-type"] = ct
	}
	if srv := h.Get("Server"); srv != "" {
		out["server"] = srv
	}
	return out
}
