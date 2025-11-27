package api8securitymisconfig

import (
	"context"
	"net/http"
	"strings"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

// CORSDetector checks for CORS misconfigurations
type CORSDetector struct{}

func init() {
	detector.Register(&CORSDetector{})
}

func (d *CORSDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "cors-misconfiguration",
		Name:          "CORS Misconfiguration",
		Description:   "Detects dangerous CORS configurations that allow credentials with wildcard origins",
		OWASP:         "API8:2023",
		Category:      "security-misconfig",
		RequiresAuth:  false,
		RequiresWrite: false,
		AppliesTo:     detector.AppliesTo{}, // Global check, not per-operation
	}
}

func (d *CORSDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	// This is a global check - only run once for the base URL
	// We'll use a special marker to run it only once
	// In practice, this should be called separately, but for now we'll check on first operation
	return nil // Handled by global checks in scanner
}

// CheckCORS performs the actual CORS check (called from scanner)
func CheckCORS(client *http.Client, baseURL string, headers http.Header) []report.Finding {
	req, err := http.NewRequest(http.MethodOptions, baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header = headers.Clone()

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acc := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	if acao == "*" && acc == "true" {
		return detector.NewFinding("A-020", "cors").
			WithSeverity("high").
			WithEvidence("allow-origin", acao).
			WithEvidence("allow-credentials", acc).
			WithReason("wildcard origin (*) used with credentials=true").
			WithRemedy("Do not use wildcard origin (*) with credentials=true. Specify exact allowed origins.").
			BuildSlice()
	}

	return nil
}

// SecurityHeadersDetector checks for missing security headers
type SecurityHeadersDetector struct{}

func init() {
	detector.Register(&SecurityHeadersDetector{})
}

func (d *SecurityHeadersDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "missing-security-headers",
		Name:          "Missing Security Headers",
		Description:   "Detects missing standard security headers like HSTS, X-Frame-Options, etc.",
		OWASP:         "API8:2023",
		Category:      "security-misconfig",
		RequiresAuth:  false,
		RequiresWrite: false,
		AppliesTo:     detector.AppliesTo{}, // Global check
	}
}

func (d *SecurityHeadersDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	// This is a global check - handled by scanner
	return nil
}

// CheckSecurityHeaders performs the actual security headers check (called from scanner)
func CheckSecurityHeaders(client *http.Client, baseURL string, headers http.Header) []report.Finding {
	req, err := http.NewRequest(http.MethodOptions, baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header = headers.Clone()

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	requiredHeaders := []string{
		"strict-transport-security",
		"x-frame-options",
		"x-content-type-options",
	}

	present := make(map[string]bool)
	for k := range resp.Header {
		present[strings.ToLower(k)] = true
	}

	var missing []string
	for _, header := range requiredHeaders {
		if !present[header] {
			missing = append(missing, header)
		}
	}

	if len(missing) > 0 {
		return detector.NewFinding("A-023", "headers").
			WithSeverity("medium").
			WithEvidence("missing", missing).
			WithReason("standard security headers are missing").
			WithRemedy("Add standard security headers: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options.").
			BuildSlice()
	}

	return nil
}
