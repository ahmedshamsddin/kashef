package broken_auth

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type NoTokenDetector struct{}

func init() {
	detector.Register(&NoTokenDetector{})
}

func (d *NoTokenDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "auth-no-token",
		Name:          "Missing Authentication Token",
		Description:   "Detects secured endpoints that respond successfully without authentication token",
		OWASP:         "API2:2023",
		Category:      "broken-auth",
		RequiresAuth:  true,
		RequiresWrite: false,
		AppliesTo:     detector.AppliesTo{}, // all methods
	}
}

func (d *NoTokenDetector) Detect(ctx context.Context, scanCtx *detector.Context, op openapi.Operation) []report.Finding {
	method := strings.ToUpper(op.Method)

	switch method {
	case http.MethodGet:
		return d.tryNoToken(ctx, scanCtx, op, nil, "")
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		if !scanCtx.AllowWrite {
			if method == http.MethodDelete {
				return nil
			}

			mt, body := pickExample(op.RequestExamples)
			if body == nil {
				return nil
			}
			return d.tryNoToken(ctx, scanCtx, op, body, mt)
		}
	default:
		return nil
	}

	return nil
}

func (d *NoTokenDetector) tryNoToken(ctx context.Context, scanCtx *detector.Context, op openapi.Operation, body []byte, contentType string) []report.Finding {
	headers := scanCtx.Headers.Clone()
	headers.Del("Authorization")

	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequestWithContext(ctx, op.Method, strings.TrimRight(scanCtx.BaseURL, "/")+op.Path, bodyReader)
	if err != nil {
		return nil
	}
	req.Header = headers

	resp, err := scanCtx.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	ct := strings.ToLower(resp.Header.Get("content-type"))
	status := resp.StatusCode
	statusClass := status / 100

	switch {
	case statusClass == 2 || statusClass == 3:
		return detector.NewFinding("A-201", "broken-auth").
			WithSeverity("high").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", status).
			WithReason("secured endpoint responded success without Authorization").
			WithRemedy("Enforce auth middleware; return 401/403 to unauthenticated requests.").
			BuildSlice()
	case status == 401 || status == 403:
		// Expected denial - no finding
		return nil

	case status == 404:
		// Hidden route - no finding
		return nil

	case status == 400 || status == 415:
		// Validation before auth (inconclusive) - no finding
		return nil

	case status >= 500:
		return detector.NewFinding("A-202", "broken-auth").
			WithSeverity("medium").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", status).
			WithReason("server error when accessing secured endpoint without token").
			WithRemedy("Handle unauthenticated access gracefully; avoid server crashes.").
			BuildSlice()
	case statusClass == 3 && strings.Contains(ct, "text/html") &&
		strings.Contains(strings.ToLower(string(snippet)), "<html"):
		// HTML redirect to login page
		return detector.NewFinding("A-203", "broken-auth").
			WithSeverity("low").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", status).
			WithEvidence("content-type", ct).
			WithEvidence("body-snippet", string(snippet)).
			WithReason("redirected to HTML login page instead of API-style JSON 401/403").
			WithRemedy("Return JSON 401/403 errors for APIs instead of HTML login pages.").
			BuildSlice()
	default:
		return nil
	}
}

// pickExample selects one request example if present.
func pickExample(m map[string][]byte) (string, []byte) {
	for mt, b := range m {
		if len(b) > 0 {
			return mt, b
		}
	}
	return "", nil
}

func bytesOrNil(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return strings.NewReader(string(b))
}
