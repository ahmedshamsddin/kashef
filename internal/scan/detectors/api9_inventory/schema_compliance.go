package api9inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
	"github.com/getkin/kin-openapi/openapi3"
)

type SchemaComplianceDetector struct{}

func init() {
	detector.Register(&SchemaComplianceDetector{})
}

func (d *SchemaComplianceDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "schema-compliance",
		Name:          "Schema Compliance Validator",
		Description:   "Validates API responses against OpenAPI schema definitions",
		OWASP:         "API9:2023",
		Category:      "inventory-management",
		RequiresAuth:  false,
		RequiresWrite: false,
		AppliesTo:     detector.OnlyMethods("GET"),
	}
}

func (d *SchemaComplianceDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	if op.Raw == nil {
		return nil
	}

	url := strings.TrimRight(sc.BaseURL, "/") + op.Path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return detector.NewFinding("A-012", "runtime").
			WithSeverity("high").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("error", err.Error()).
			WithReason("failed to create HTTP request").
			WithRemedy("Check endpoint URL format and accessibility.").
			BuildSlice()
	}

	req.Header = sc.Headers.Clone()
	if authHeader := sc.GetAuthHeader(); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.Client.Do(req)
	if err != nil {
		return detector.NewFinding("A-012", "runtime").
			WithSeverity("high").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("error", err.Error()).
			WithReason("endpoint failed to respond").
			WithRemedy("Ensure endpoint is accessible and server is running.").
			BuildSlice()
	}
	defer resp.Body.Close()

	var findings []report.Finding

	// Check status code drift
	statusFindings := d.checkStatusCodeDrift(op, resp)
	findings = append(findings, statusFindings...)

	// Check JSON schema compliance
	schemaFindings := d.checkJSONSchema(op, resp)
	findings = append(findings, schemaFindings...)

	return findings
}

func (d *SchemaComplianceDetector) checkStatusCodeDrift(op openapi.Operation, resp *http.Response) []report.Finding {
	declaredStatuses := make(map[int]struct{})
	for code := range op.Raw.Responses.Map() {
		if n, err := parseStatus(code); err == nil {
			declaredStatuses[n] = struct{}{}
		}
	}

	if len(declaredStatuses) == 0 {
		return nil
	}

	if _, ok := declaredStatuses[resp.StatusCode]; !ok {
		return detector.NewFinding("A-010", "spec-runtime-mismatch").
			WithSeverity("medium").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", resp.StatusCode).
			WithEvidence("declared", mapKeys(declaredStatuses)).
			WithReason("response status code not declared in OpenAPI spec").
			WithRemedy("Update OpenAPI spec to include actual status codes or fix handler.").
			BuildSlice()
	}

	return nil
}

func (d *SchemaComplianceDetector) checkJSONSchema(op openapi.Operation, resp *http.Response) []report.Finding {
	ct := strings.ToLower(resp.Header.Get("content-type"))
	if !strings.HasPrefix(ct, "application/json") {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if len(body) == 0 {
		return detector.NewFinding("A-013", "runtime").
			WithSeverity("medium").
			WithEndpoint(op.Method, op.Path).
			WithReason("empty JSON body with application/json content-type").
			WithRemedy("Return valid JSON body or use correct Content-Type header.").
			BuildSlice()
	}

	schema := pickJSONSchema(op.Raw, resp.StatusCode)
	if schema == nil || schema.Value == nil {
		return nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return detector.NewFinding("A-014", "runtime").
			WithSeverity("medium").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("jsonParseError", err.Error()).
			WithReason("invalid JSON in response body").
			WithRemedy("Return valid JSON or fix Content-Type header.").
			BuildSlice()
	}

	violations := compareAgainstSchemaObject(schema.Value, data)
	if len(violations) == 0 {
		return nil
	}

	var findings []report.Finding
	for _, evidence := range violations {
		finding := detector.NewFinding("A-011", "schema").
			WithSeverity("high").
			WithEndpoint(op.Method, op.Path).
			WithRemedy("Fix response to match schema properties/required or update schema definition.")

		for k, v := range evidence {
			finding = finding.WithEvidence(k, v)
		}

		findings = append(findings, finding.Build())
	}

	return findings
}

// Helper functions

func parseStatus(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func mapKeys(m map[int]struct{}) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
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

func compareAgainstSchemaObject(schema *openapi3.Schema, data interface{}) []map[string]interface{} {
	var results []map[string]interface{}
	if schema == nil {
		return results
	}

	// Handle array schema
	if schema.Items != nil && schema.Items.Value != nil {
		arr, ok := data.([]interface{})
		if !ok {
			return []map[string]interface{}{
				{
					"reason":   "expected array per schema",
					"dataType": fmt.Sprintf("%T", data),
				},
			}
		}
		if len(arr) > 0 {
			return compareAgainstSchemaObject(schema.Items.Value, arr[0])
		}
		return results
	}

	// Check if schema defines an object
	objLike := len(schema.Properties) > 0 ||
		schema.AdditionalProperties.Schema != nil ||
		schema.AdditionalProperties.Has != nil

	if !objLike {
		return results
	}

	// Validate object structure
	obj, ok := data.(map[string]interface{})
	if !ok {
		return []map[string]interface{}{
			{
				"reason":   "expected object per schema",
				"dataType": fmt.Sprintf("%T", data),
			},
		}
	}

	// Check required fields
	var missing []string
	for _, req := range schema.Required {
		if _, ok := obj[req]; !ok {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		results = append(results, map[string]interface{}{
			"missingRequired": missing,
		})
	}

	// Check additional properties
	additionalAllowed := true
	if schema.AdditionalProperties.Has != nil {
		additionalAllowed = *schema.AdditionalProperties.Has
	}

	if !additionalAllowed {
		declared := make(map[string]struct{})
		for name := range schema.Properties {
			declared[name] = struct{}{}
		}

		var extra []string
		for k := range obj {
			if _, ok := declared[k]; !ok {
				extra = append(extra, k)
			}
		}

		if len(extra) > 0 {
			results = append(results, map[string]interface{}{
				"extraFields": extra,
			})
		}
	}

	return results
}
