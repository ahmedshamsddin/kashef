package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
	ssrf "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api7_ssrf"
	securitymisconfig "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api8_security_misconfig"
	"github.com/ahmedshamsddin/kashef/internal/scan/detectors/connectivity"
)

// RunOpenAPIScan orchestrates the complete security scan of an OpenAPI specification
func RunOpenAPIScan(
	specPath, out string,
	headers []string,
	timeout time.Duration,
	concurrency int,
	failOn string,
	verbose bool,
	allowWrite bool,
	token string,
) (int, error) {
	ctx := context.Background()

	// Load and validate OpenAPI specification
	spec, err := openapi.Load(ctx, specPath)
	if err != nil {
		return 2, fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	// Initialize HTTP client and scanner context
	client := &http.Client{Timeout: timeout}
	parsedHeaders := parseHeaders(headers)

	scanner := newScanner(spec, client, parsedHeaders, token, allowWrite, verbose, timeout)

	if verbose {
		scanner.printDetectorInfo()
	}

	// Run the scan
	findings := scanner.scan(ctx, concurrency)

	// Generate and write report
	if err := scanner.writeReport(findings, out); err != nil {
		return 2, fmt.Errorf("failed to write report: %w", err)
	}

	// Determine exit code based on severity threshold
	return scanner.evaluateExitCode(findings, failOn), nil
}

// scanner encapsulates all scanning logic and state
type scanner struct {
	spec        *openapi.Spec
	client      *http.Client
	headers     http.Header
	detectorCtx *detector.Context
	verbose     bool
}

// newScanner creates a new scanner instance with properly configured context
func newScanner(
	spec *openapi.Spec,
	client *http.Client,
	headers http.Header,
	token string,
	allowWrite bool,
	verbose bool,
	timeout time.Duration,
) *scanner {
	// Setup detector context with all necessary configuration
	detectorCtx := detector.NewContext(spec.Server, client, headers).
		WithToken(token).
		WithAllowWrite(allowWrite).
		WithVerbose(verbose).
		WithTimeout(timeout)

	// Configure OOB server factory for SSRF detection
	detectorCtx.OOBServerFactory = ssrf.NewOOBFactory()

	return &scanner{
		spec:        spec,
		client:      client,
		headers:     headers,
		detectorCtx: detectorCtx,
		verbose:     verbose,
	}
}

// printDetectorInfo displays registered detector information
func (s *scanner) printDetectorInfo() {
	fmt.Printf("Registered detectors: %d\n", detector.Count())
	for _, d := range detector.List() {
		info := d.Info()
		fmt.Printf("  - %s (%s)\n", info.Name, info.ID)
	}
	fmt.Println()
}

// scan performs the actual security scanning using concurrent workers
func (s *scanner) scan(ctx context.Context, concurrency int) []report.Finding {
	var findings []report.Finding

	// Initial connectivity check
	findings = append(findings, s.checkConnectivity()...)

	// Scan all operations concurrently
	operationFindings := s.scanOperations(ctx, concurrency)
	findings = append(findings, operationFindings...)

	// Global security checks (CORS, headers)
	findings = append(findings, s.checkGlobalSecurity()...)

	return findings
}

// scanOperations scans all API operations using a worker pool
func (s *scanner) scanOperations(ctx context.Context, concurrency int) []report.Finding {
	type job struct {
		op openapi.Operation
	}

	jobs := make(chan job, len(s.spec.Operations()))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []report.Finding

	// Worker function
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			opFindings := s.scanOperation(ctx, j.op)

			mu.Lock()
			findings = append(findings, opFindings...)
			mu.Unlock()
		}
	}

	// Start worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	// Enqueue all operations
	for _, op := range s.spec.Operations() {
		jobs <- job{op: op}
	}
	close(jobs)

	// Wait for all workers to complete
	wg.Wait()

	return findings
}

// scanOperation scans a single API operation using the detector registry
func (s *scanner) scanOperation(ctx context.Context, op openapi.Operation) []report.Finding {
	// Run all registered detectors via registry
	return detector.RunAll(ctx, s.detectorCtx, op)
}

// checkConnectivity performs initial connectivity check against the base URL
func (s *scanner) checkConnectivity() []report.Finding {
	return connectivity.CheckConnectivity(s.client, s.spec.Server, s.headers)
}

// checkGlobalSecurity performs global security checks (CORS, headers)
func (s *scanner) checkGlobalSecurity() []report.Finding {
	var findings []report.Finding

	corsFindings := s.checkCORS()
	findings = append(findings, corsFindings...)

	headerFindings := s.checkSecurityHeaders()
	findings = append(findings, headerFindings...)

	return findings
}

// checkCORS checks for CORS misconfigurations
func (s *scanner) checkCORS() []report.Finding {
	return securitymisconfig.CheckCORS(s.client, s.spec.Server, s.headers)
}

// checkSecurityHeaders checks for missing security headers
func (s *scanner) checkSecurityHeaders() []report.Finding {
	return securitymisconfig.CheckSecurityHeaders(s.client, s.spec.Server, s.headers)
}

// writeReport generates and writes the scan report
func (s *scanner) writeReport(findings []report.Finding, outputPath string) error {
	rep := report.Report{
		Scanner:  "kashef",
		Target:   s.spec.Server,
		Findings: findings,
	}

	if strings.HasSuffix(strings.ToLower(outputPath), ".md") {
		return writeMarkdown(rep, outputPath)
	}
	return writeJSON(rep, outputPath)
}

// evaluateExitCode determines exit code based on severity threshold
func (s *scanner) evaluateExitCode(findings []report.Finding, failOn string) int {
	threshold := report.Rank(strings.ToLower(failOn))
	if threshold == 0 {
		return 0 // No threshold set
	}

	maxSeverity := 0
	for _, f := range findings {
		if rank := report.Rank(f.Severity); rank > maxSeverity {
			maxSeverity = rank
		}
	}

	if maxSeverity >= threshold {
		return 1 // Threshold exceeded
	}
	return 0
}

// Helper functions

func parseHeaders(headers []string) http.Header {
	h := http.Header{}
	for _, s := range headers {
		if idx := strings.Index(s, ":"); idx > 0 {
			key := strings.TrimSpace(s[:idx])
			value := strings.TrimSpace(s[idx+1:])
			h.Add(key, value)
		}
	}
	return h
}

// Report writing functions

func writeJSON(rep report.Report, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func writeMarkdown(rep report.Report, outputPath string) error {
	var b strings.Builder

	fmt.Fprintf(&b, "# Kashef Security Report\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`\n\n", rep.Target)
	fmt.Fprintf(&b, "**Total Findings:** %d\n\n", len(rep.Findings))

	// Group findings by severity
	severityGroups := groupBySeverity(rep.Findings)
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		findings := severityGroups[severity]
		if len(findings) == 0 {
			continue
		}

		// Properly capitalize severity (strings.Title is deprecated)
		severityTitle := strings.ToUpper(severity[:1]) + severity[1:]
		fmt.Fprintf(&b, "## %s Severity (%d)\n\n", severityTitle, len(findings))

		for _, f := range findings {
			fmt.Fprintf(&b, "### %s - %s\n\n", f.ID, f.Category)

			if f.Endpoint != "" {
				fmt.Fprintf(&b, "**Endpoint:** `%s %s`\n\n", f.Method, f.Endpoint)
			}

			if len(f.Evidence) > 0 {
				fmt.Fprintf(&b, "**Evidence:**\n\n```json\n")
				ev, _ := json.MarshalIndent(f.Evidence, "", "  ")
				fmt.Fprintf(&b, "%s\n```\n\n", ev)
			}

			if f.Remedy != "" {
				fmt.Fprintf(&b, "**Remediation:** %s\n\n", f.Remedy)
			}

			fmt.Fprintln(&b, "---\n")
		}
	}

	return os.WriteFile(outputPath, []byte(b.String()), 0o644)
}

func groupBySeverity(findings []report.Finding) map[string][]report.Finding {
	groups := make(map[string][]report.Finding)
	for _, f := range findings {
		severity := strings.ToLower(f.Severity)
		groups[severity] = append(groups[severity], f)
	}
	return groups
}
