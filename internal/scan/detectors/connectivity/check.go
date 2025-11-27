package connectivity

import (
	"context"
	"net/http"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

// ConnectivityDetector checks basic connectivity to the target API
type ConnectivityDetector struct{}

func init() {
	detector.Register(&ConnectivityDetector{})
}

func (d *ConnectivityDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "connectivity-check",
		Name:          "Connectivity Check",
		Description:   "Verifies basic connectivity and server health",
		OWASP:         "",
		Category:      "connectivity",
		RequiresAuth:  false,
		RequiresWrite: false,
		AppliesTo:     detector.AppliesTo{}, // Global check
	}
}

func (d *ConnectivityDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	// This is a global check - handled by scanner
	return nil
}

// CheckConnectivity performs the actual connectivity check (called from scanner)
func CheckConnectivity(client *http.Client, baseURL string, headers http.Header) []report.Finding {
	req, err := http.NewRequest(http.MethodHead, baseURL, nil)
	if err != nil {
		return []report.Finding{
			{
				ID:       "A-0002",
				Severity: "high",
				Category: "connectivity",
				Evidence: map[string]interface{}{"error": err.Error()},
				Remedy:   "Ensure the target server is accessible and the URL is correct.",
			},
		}
	}

	req.Header = headers.Clone()
	resp, err := client.Do(req)
	if err != nil {
		return []report.Finding{
			{
				ID:       "A-0002",
				Severity: "high",
				Category: "connectivity",
				Evidence: map[string]interface{}{"error": err.Error()},
				Remedy:   "Check network connectivity and DNS resolution.",
			},
		}
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	findings := []report.Finding{
		{
			ID:       "A-0000",
			Severity: "info",
			Category: "connectivity",
			Evidence: map[string]interface{}{"status": resp.StatusCode},
		},
	}

	if resp.StatusCode >= 500 {
		findings = append(findings, report.Finding{
			ID:       "A-0001",
			Severity: "medium",
			Category: "runtime",
			Evidence: map[string]interface{}{"status": resp.StatusCode},
			Remedy:   "Server is experiencing errors. Check server logs and health.",
		})
	}

	return findings
}
