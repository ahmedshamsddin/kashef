package report

// Finding represents a single security issue discovered during scanning
type Finding struct {
	ID       string                 `json:"id"`
	Severity string                 `json:"severity"` // info|low|medium|high|critical
	Category string                 `json:"category"` // e.g. cors, schema, auth
	Endpoint string                 `json:"endpoint,omitempty"`
	Method   string                 `json:"method,omitempty"`
	Evidence map[string]interface{} `json:"evidence,omitempty"`
	Remedy   string                 `json:"remediation,omitempty"`
}

// Report represents the complete scan report
type Report struct {
	Scanner  string    `json:"scanner"`
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
}

// Rank returns the numeric severity level for comparison and threshold checking.
// Higher numbers indicate more severe issues.
//
// Severity levels:
//   - critical: 4 (most severe, immediate action required)
//   - high: 3 (serious issues, fix soon)
//   - medium: 2 (notable issues, should fix)
//   - low: 1 (minor issues, nice to fix)
//   - info/other: 0 (informational, no action needed)
func Rank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
