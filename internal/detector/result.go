package detector

import "github.com/ahmedshamsddin/kashef/internal/report"

type FindingBuilder struct {
	finding report.Finding
}

func NewFinding(id, category string) *FindingBuilder {
	return &FindingBuilder{
		finding: report.Finding{
			ID:       id,
			Category: category,
			Evidence: make(map[string]interface{}),
		},
	}
}

func (fb *FindingBuilder) WithSeverity(severity string) *FindingBuilder {
	fb.finding.Severity = severity
	return fb
}

func (fb *FindingBuilder) WithEndpoint(method, path string) *FindingBuilder {
	fb.finding.Method = method
	fb.finding.Endpoint = path
	return fb
}

func (fb *FindingBuilder) WithEvidence(key string, value interface{}) *FindingBuilder {
	fb.finding.Evidence[key] = value
	return fb
}

func (fb *FindingBuilder) WithReason(reason string) *FindingBuilder {
	fb.finding.Evidence["reason"] = reason
	return fb
}

func (fb *FindingBuilder) WithRemedy(remedy string) *FindingBuilder {
	fb.finding.Remedy = remedy
	return fb
}

func (fb *FindingBuilder) Build() report.Finding {
	return fb.finding
}

func (fb *FindingBuilder) BuildSlice() []report.Finding {
	return []report.Finding{fb.finding}
}
