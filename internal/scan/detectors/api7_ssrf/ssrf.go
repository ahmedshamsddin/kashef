package api7ssrf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type SSRFDetector struct{}

func init() {
	detector.Register(&SSRFDetector{})
}

func (d *SSRFDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "ssrf-oob",
		Name:          "SSRF via Out-of-Band",
		Description:   "Detects Server-Side Request Forgery using OOB callbacks",
		OWASP:         "API7:2023",
		Category:      "ssrf",
		RequiresAuth:  false,
		RequiresWrite: false,                // can test GET params
		AppliesTo:     detector.AppliesTo{}, // all methods
	}
}

func (d *SSRFDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	urlParams := extractURLParams(op)
	requestBodyParams := extractURLRequestBodyFields(op)

	if len(urlParams) == 0 && len(requestBodyParams) == 0 {
		return nil
	}

	// Check if OOB server factory is available
	if sc.OOBServerFactory == nil {
		if sc.Verbose {
			fmt.Printf("[ssrf] OOB server factory not configured, skipping\n")
		}
		return nil
	}

	oobServer, err := sc.OOBServerFactory.Create()
	if err != nil {
		if sc.Verbose {
			fmt.Printf("[ssrf] failed to create OOB server: %v\n", err)
		}
		return nil
	}

	if err := oobServer.Start(); err != nil {
		if sc.Verbose {
			fmt.Printf("[ssrf] failed to start OOB server: %v\n", err)
		}
		return nil
	}
	defer oobServer.Stop()

	var findings []report.Finding

	// Test URL parameters
	for _, param := range urlParams {
		results := d.testSSRFWithOOB(ctx, sc, op, param, "param", oobServer)
		findings = append(findings, results...)
	}

	// Test request body fields
	for _, field := range requestBodyParams {
		results := d.testSSRFWithOOB(ctx, sc, op, field, "body", oobServer)
		findings = append(findings, results...)
	}

	return findings
}

func (d *SSRFDetector) testSSRFWithOOB(ctx context.Context, sc *detector.Context, op openapi.Operation,
	paramName, paramType string, oobServer detector.OOBServer) []report.Finding {

	identifier := fmt.Sprintf("ssrf-%s-%s-%d",
		sanitize(op.Path),
		sanitize(paramName),
		time.Now().UnixNano())

	oobURL := oobServer.GenerateURL(identifier)

	if sc.Verbose {
		fmt.Printf("[ssrf] testing %s=%s with OOB URL: %s\n",
			paramName, paramType, oobURL)
	}

	var err error
	if paramType == "param" {
		err = d.sendRequestWithURLParam(ctx, sc, op, paramName, oobURL)
	} else {
		if !sc.AllowWrite {
			return nil // skip body tests if write not allowed
		}
		err = d.sendRequestWithBodyField(ctx, sc, op, paramName, oobURL)
	}

	if err != nil {
		if sc.Verbose {
			fmt.Printf("[ssrf] request failed: %v\n", err)
		}
		return nil
	}

	timeout := 5 * time.Second
	callbackReceived := oobServer.CheckCallback(identifier, timeout)

	if callbackReceived {
		return detector.NewFinding("A-706", "ssrf").
			WithSeverity("critical").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("parameter_name", paramName).
			WithEvidence("parameter_type", paramType).
			WithEvidence("oob_url", oobURL).
			WithEvidence("callback_received", true).
			WithReason("target API made request to OOB server, confirming SSRF").
			WithRemedy("Validate and sanitize all URL inputs. Implement allowlist of permitted domains. Block private IP ranges and localhost.").
			BuildSlice()
	}

	return nil
}

func (d *SSRFDetector) sendRequestWithURLParam(ctx context.Context, sc *detector.Context, op openapi.Operation,
	paramName, oobURL string) error {

	reqURL := strings.TrimRight(sc.BaseURL, "/") + op.Path

	if strings.Contains(reqURL, "?") {
		reqURL += "&"
	} else {
		reqURL += "?"
	}
	reqURL += paramName + "=" + url.QueryEscape(oobURL)

	req, err := http.NewRequestWithContext(ctx, op.Method, reqURL, nil)
	if err != nil {
		return err
	}

	req.Header = sc.Headers.Clone()
	if authHeader := sc.GetAuthHeader(); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
	return nil
}

func (d *SSRFDetector) sendRequestWithBodyField(ctx context.Context, sc *detector.Context, op openapi.Operation,
	fieldName, oobURL string) error {

	payload := fmt.Sprintf(`{"%s": "%s"}`, fieldName, oobURL)
	reqURL := strings.TrimRight(sc.BaseURL, "/") + op.Path

	req, err := http.NewRequestWithContext(ctx, op.Method, reqURL,
		strings.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header = sc.Headers.Clone()
	req.Header.Set("Content-Type", "application/json")
	if authHeader := sc.GetAuthHeader(); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
	return nil
}
func extractURLParams(op openapi.Operation) []string {
	params := []string{}

	if op.Raw == nil || op.Raw.Parameters == nil {
		return params
	}

	for _, paramRef := range op.Raw.Parameters {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}

		pname := strings.ToLower(paramRef.Value.Name)

		// Look for URL-like parameter names
		urlPatterns := []string{
			"url", "uri", "link", "href", "callback", "webhook", "image", "avatar", "icon",
			"thumbnail", "redirect", "fetch", "proxy", "source",
		}

		for _, pattern := range urlPatterns {
			if strings.Contains(pname, pattern) {
				params = append(params, paramRef.Value.Name)
				break
			}
		}
	}

	return params
}

func extractURLRequestBodyFields(op openapi.Operation) []string {
	var fields []string

	if op.Raw == nil || op.Raw.RequestBody == nil || op.Raw.RequestBody.Value == nil || op.Raw.RequestBody.Value.Content == nil {
		return fields
	}

	jsonContent := op.Raw.RequestBody.Value.Content.Get("application/json")

	if jsonContent != nil && jsonContent.Schema != nil && jsonContent.Schema.Value != nil {
		schema := jsonContent.Schema.Value
		for propName := range schema.Properties {
			if looksURLish(propName) {
				fields = append(fields, propName)
			}
		}
		if len(fields) > 0 {
			return fields
		}
	}

	// 2) Fallback: infer from request example
	for _, ex := range op.RequestExamples {
		var m map[string]any
		if json.Unmarshal(ex, &m) == nil {
			for k := range m {
				if looksURLish(k) {
					fields = append(fields, k)
				}
			}
		}
	}

	return fields
}

func looksURLish(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"url", "uri", "link", "href", "callback", "webhook", "image", "avatar", "icon", "thumbnail", "redirect", "fetch", "proxy", "source"} {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

func sanitize(s string) string {
	// Remove special characters
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")
	return s
}
