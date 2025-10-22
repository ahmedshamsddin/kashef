package report

type Finding struct {
	ID       string                 `json:"id"`
	Severity string                 `json:"severity"` // info|low|medium|high
	Category string                 `json:"category"` // e.g. cors, schema, auth
	Endpoint string                 `json:"endpoint,omitempty"`
	Method   string                 `json:"method,omitempty"`
	Evidence map[string]interface{} `json:"evidence,omitempty"`
	Remedy   string                 `json:"remediation,omitempty"`
}

type Report struct {
	Scanner  string    `json:"scanner"`
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
}

func Rank(s string) int {
	switch s {
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
