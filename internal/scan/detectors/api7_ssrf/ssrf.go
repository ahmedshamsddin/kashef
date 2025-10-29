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

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type Context struct {
	BaseURL    string
	Client     *http.Client
	Headers    http.Header
	AllowWrite bool
	Verbose    bool
	Token      string
}

// var internalPayloads = []string{
// 	"http://127.0.0.1/admin",
// 	"http://localhost/admin",
// 	"http://169.254.169.254/latest/meta-data/",
// 	"file:///etc/passwd",
// }

// var externalPayloads = []string{
// 	"http://example.com/",
// 	"https://example.com/probe-ssrf",
// }

func DetectSSRF(ctx context.Context, sc Context, op openapi.Operation) []report.Finding {
	out := []report.Finding{}
	// Loop thourgh parameters and query strings to find potential SSRF vectors

	urlParams := extractURLParams(op)
	requestBodyParams := extractURLRequestBodyFields(op)
	if len(urlParams) == 0 && len(requestBodyParams) == 0 {
		return out
	}

	oobServer := newSimpleOOBServer()
	if err := oobServer.Start(ctx); err != nil {
		if sc.Verbose {
			fmt.Printf("[ssrf] failed to start OOB server: %v\n", err)
		}
		return out
	}
	defer oobServer.Stop()

	if sc.Verbose {
		fmt.Printf("[ssrf] OOB server listening at %s\n", oobServer.GetBaseURL())
	}

	// Test URL parameters
	for _, param := range urlParams {
		findings := testSSRFWithOOB(ctx, sc, op, param, "param", oobServer)
		out = append(out, findings...)
	}

	// Test request body fields
	for _, field := range requestBodyParams {
		findings := testSSRFWithOOB(ctx, sc, op, field, "body", oobServer)
		out = append(out, findings...)
	}

	return out
}

func testSSRFWithOOB(ctx context.Context, sc Context, op openapi.Operation,
	paramName, paramType string, oobServer *SimpleOOBServer) []report.Finding {

	out := []report.Finding{}

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
		err = sendRequestWithURLParam(ctx, sc, op, paramName, oobURL)
	} else {
		err = sendRequestWithBodyField(ctx, sc, op, paramName, oobURL)
	}

	if err != nil {
		if sc.Verbose {
			fmt.Printf("[ssrf] request failed: %v\n", err)
		}
		return out
	}

	timeout := 5 * time.Second
	callbackReceived := oobServer.CheckCallback(identifier, timeout)

	if callbackReceived {
		// SSRF confirmed!
		record := oobServer.GetCallbackRecord(identifier)

		out = append(out, report.Finding{
			ID:       "A-706",
			Severity: "critical",
			Category: "ssrf.confirmed",
			Endpoint: op.Path,
			Method:   op.Method,
			Evidence: map[string]interface{}{
				"parameter_name":    paramName,
				"parameter_type":    paramType,
				"oob_url":           oobURL,
				"callback_received": true,
				"callback_time":     record.ReceivedAt.Format(time.RFC3339),
				"callback_method":   record.Method,
				"reason":            "target API made request to OOB server, confirming SSRF",
			},
			Remedy: "Validate and sanitize all URL inputs. Implement allowlist of permitted domains. Block private IP ranges and localhost.",
		})
	}

	return out
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

func sendRequestWithURLParam(ctx context.Context, sc Context, op openapi.Operation,
	paramName, oobURL string) error {
	fmt.Println("sending request with url")

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
	// add auth token if available
	if sc.Token != "" {
		req.Header.Set("Authorization", "Bearer "+sc.Token)
	}

	resp, err := sc.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Drain and discard body
	io.Copy(io.Discard, resp.Body)

	return nil
}

// Send request with body field
func sendRequestWithBodyField(ctx context.Context, sc Context, op openapi.Operation,
	fieldName, oobURL string) error {

	if !sc.AllowWrite {
		return fmt.Errorf("write operations not allowed")
	}

	// Build JSON payload
	payload := fmt.Sprintf(`{"%s": "%s"}`, fieldName, oobURL)
	fmt.Println(payload)
	reqURL := strings.TrimRight(sc.BaseURL, "/") + op.Path
	req, err := http.NewRequestWithContext(ctx, op.Method, reqURL,
		strings.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header = sc.Headers.Clone()
	req.Header.Set("Content-Type", "application/json")
	// add auth token if available
	if sc.Token != "" {
		req.Header.Set("Authorization", "Bearer "+sc.Token)
	}

	resp, err := sc.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Drain and discard body
	io.Copy(io.Discard, resp.Body)

	return nil
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
