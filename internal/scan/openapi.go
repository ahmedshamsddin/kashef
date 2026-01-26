package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
	ssrf "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api7_ssrf"
	securitymisconfig "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api8_security_misconfig"
	"github.com/ahmedshamsddin/kashef/internal/scan/detectors/connectivity"
)

// --- UI Constants (ANSI Colors) ---
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
	ColorBold   = "\033[1m"
)

// RunOpenAPIScan orchestrates the complete security scan
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

	spec, err := openapi.Load(ctx, specPath)
	if err != nil {
		return 2, fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	client := &http.Client{Timeout: timeout}
	parsedHeaders := parseHeaders(headers)

	scanner := newScanner(spec, client, parsedHeaders, token, allowWrite, verbose, timeout)

	// UI: Print Banner
	printBanner(spec.Server, specPath, concurrency)

	if verbose {
		scanner.printDetectorInfo()
	}

	// Run scan
	findings := scanner.scan(ctx, concurrency)

	if err := scanner.writeReport(findings, out); err != nil {
		return 2, fmt.Errorf("failed to write report: %w", err)
	}

	// UI: Print Summary
	printSummary(findings, out)

	return scanner.evaluateExitCode(findings, failOn), nil
}

type scanner struct {
	spec        *openapi.Spec
	client      *http.Client
	headers     http.Header
	detectorCtx *detector.Context
	verbose     bool
}

func newScanner(
	spec *openapi.Spec,
	client *http.Client,
	headers http.Header,
	token string,
	allowWrite bool,
	verbose bool,
	timeout time.Duration,
) *scanner {
	detectorCtx := detector.NewContext(spec.Server, client, headers).
		WithToken(token).
		WithAllowWrite(allowWrite).
		WithVerbose(verbose).
		WithTimeout(timeout)

	detectorCtx.OOBServerFactory = ssrf.NewOOBFactory()

	return &scanner{
		spec:        spec,
		client:      client,
		headers:     headers,
		detectorCtx: detectorCtx,
		verbose:     verbose,
	}
}

func (s *scanner) printDetectorInfo() {
	fmt.Printf("Registered detectors: %d\n", detector.Count())
	for _, d := range detector.List() {
		info := d.Info()
		fmt.Printf("  - %s (%s)\n", info.Name, info.ID)
	}
	fmt.Println()
}

func (s *scanner) scan(ctx context.Context, concurrency int) []report.Finding {
	var findings []report.Finding

	connectivityFindings := s.checkConnectivity()
	findings = append(findings, connectivityFindings...)

	for _, f := range connectivityFindings {
		if f.ID == "A-0002" {
			fmt.Printf("%s\n❌ Fatal: Could not connect to target. Aborting.%s\n", ColorRed, ColorReset)
			return findings
		}
	}

	operationFindings := s.scanOperations(ctx, concurrency)
	findings = append(findings, operationFindings...)

	findings = append(findings, s.checkGlobalSecurity()...)

	return findings
}

func (s *scanner) scanOperations(ctx context.Context, concurrency int) []report.Finding {
	type job struct {
		op openapi.Operation
	}

	jobs := make(chan job, len(s.spec.Operations()))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []report.Finding

	total := int32(len(s.spec.Operations()))
	var processed int32

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			opFindings := s.scanOperation(ctx, j.op)

			current := atomic.AddInt32(&processed, 1)

			if !s.verbose {
				// We add a few spaces at the end to overwrite any lingering chars
				fmt.Printf("\r%s⏳ Scanning endpoints... [%d/%d]%s   ", ColorCyan, current, total, ColorReset)
			}

			mu.Lock()
			findings = append(findings, opFindings...)
			mu.Unlock()
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	for _, op := range s.spec.Operations() {
		jobs <- job{op: op}
	}
	close(jobs)

	wg.Wait()

	if !s.verbose {
		fmt.Printf("\r%s✅ Scan complete!        [%d/%d]%s   \n", ColorGreen, total, total, ColorReset)
	}

	return findings
}

func (s *scanner) scanOperation(ctx context.Context, op openapi.Operation) []report.Finding {
	return detector.RunAll(ctx, s.detectorCtx, op)
}

func (s *scanner) checkConnectivity() []report.Finding {
	return connectivity.CheckConnectivity(s.client, s.spec.Server, s.headers)
}

func (s *scanner) checkGlobalSecurity() []report.Finding {
	var findings []report.Finding
	findings = append(findings, s.checkCORS()...)
	findings = append(findings, s.checkSecurityHeaders()...)
	return findings
}

func (s *scanner) checkCORS() []report.Finding {
	return securitymisconfig.CheckCORS(s.client, s.spec.Server, s.headers)
}

func (s *scanner) checkSecurityHeaders() []report.Finding {
	return securitymisconfig.CheckSecurityHeaders(s.client, s.spec.Server, s.headers)
}

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

func (s *scanner) evaluateExitCode(findings []report.Finding, failOn string) int {
	threshold := report.Rank(strings.ToLower(failOn))
	if threshold == 0 {
		return 0
	}
	maxSeverity := 0
	for _, f := range findings {
		if rank := report.Rank(f.Severity); rank > maxSeverity {
			maxSeverity = rank
		}
	}
	if maxSeverity >= threshold {
		return 1
	}
	return 0
}

// --- UI Helper Functions ---

func printBanner(target, specPath string, workers int) {
	art := `
    __ __           __          ____
   / //_/___ ______/ /_  ___   / __/
  / ,< / __  / ___/ __ \/ _ \ / /_  
 / /| / /_/ (__  ) / / /  __// __/  
/_/ |_\__,_/____/_/ /_/\___/_/      
`
	fmt.Println()
	fmt.Print(ColorCyan + ColorBold + art + ColorReset)
	fmt.Println()
	fmt.Printf("   %sTarget:%s  %s\n", ColorGray, ColorReset, target)
	fmt.Printf("   %sSpec:%s    %s\n", ColorGray, ColorReset, specPath)
	fmt.Printf("   %sThreads:%s %d\n", ColorGray, ColorReset, workers)
	fmt.Println()
}

func printSummary(findings []report.Finding, outputPath string) {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[strings.ToUpper(f.Severity)]++
	}

	type row struct {
		label string
		count int
		icon  string
		color string
	}

	var rows []row
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	hasIssues := false

	for _, sev := range order {
		count := counts[sev]
		if count > 0 {
			hasIssues = true
			color := ColorReset
			icon := ""
			switch sev {
			case "CRITICAL":
				color = ColorRed + ColorBold
				icon = "❌"
			case "HIGH":
				color = ColorRed
				icon = "❌"
			case "MEDIUM":
				color = ColorYellow
				icon = "⚠️ "
			case "LOW":
				color = ColorBlue
				icon = "ℹ️ "
			case "INFO":
				color = ColorGray
				icon = "📝"
			}
			rows = append(rows, row{label: sev, count: count, icon: icon, color: color})
		}
	}

	if !hasIssues {
		rows = append(rows, row{label: "ALL CLEAR", count: 0, icon: "✅", color: ColorGreen})
	}

	// Dynamic Width Calculation
	minWidth := 40
	contentWidth := minWidth
	for _, r := range rows {
		// Calculate visual length approx
		w := len(r.label) + 15
		if w > contentWidth {
			contentWidth = w
		}
	}

	// Draw Box
	drawBoxTop(contentWidth)
	drawCenteredText("SCAN COMPLETE", contentWidth, ColorBold)
	drawBoxDivider(contentWidth)

	if !hasIssues {
		drawRow("No Vulnerabilities Found", 0, "✅", ColorGreen, contentWidth)
	} else {
		for _, r := range rows {
			drawRow(r.label, r.count, r.icon, r.color, contentWidth)
		}
	}

	drawBoxBottom(contentWidth)
	fmt.Println()
	fmt.Printf("%s📄 Report saved to:%s %s\n", ColorBlue, ColorReset, outputPath)
	fmt.Println()
}

// --- Box Drawing (Fixed Formats) ---

func drawBoxTop(width int) {
	// Fixed: Added correct number of %s placeholders
	fmt.Printf("%s┌%s┐%s%s\n", ColorGray, strings.Repeat("─", width+2), ColorGray, ColorReset)
}

func drawBoxBottom(width int) {
	fmt.Printf("%s└%s┘%s%s\n", ColorGray, strings.Repeat("─", width+2), ColorGray, ColorReset)
}

func drawBoxDivider(width int) {
	fmt.Printf("%s├%s┤%s%s\n", ColorGray, strings.Repeat("─", width+2), ColorGray, ColorReset)
}

func drawCenteredText(text string, width int, colorCode string) {
	padding := (width - len(text)) / 2
	rightPadding := width - len(text) - padding
	// Fixed: Matches arg count
	fmt.Printf("%s│ %s%s%s%s%s │%s%s\n",
		ColorGray,
		strings.Repeat(" ", padding),
		colorCode, text, ColorReset,
		strings.Repeat(" ", rightPadding),
		ColorGray, ColorReset,
	)
}

func drawRow(label string, count int, icon string, colorCode string, width int) {
	countStr := ""
	if count > 0 {
		countStr = fmt.Sprintf("%d", count)
	}

	textLen := len(label)
	countLen := len(countStr)

	// Spacing calculation
	gap := width - textLen - countLen - 4
	if gap < 2 {
		gap = 2
	}

	// Fixed: Matches arg count
	fmt.Printf("%s│ %s%s%s%s%s %s │%s%s\n",
		ColorGray,
		colorCode, label, ColorReset,
		strings.Repeat(" ", gap),
		countStr, icon,
		ColorGray, ColorReset,
	)
}

// Helper functions (Unchanged)
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

// Report writing functions (Unchanged)
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
	severityGroups := groupBySeverity(rep.Findings)
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		findings := severityGroups[severity]
		if len(findings) == 0 {
			continue
		}
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
