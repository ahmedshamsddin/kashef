package broken_auth

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

// Context is detector runtime context.
type Context struct {
	BaseURL    string
	Client     *http.Client
	Headers    http.Header
	AllowWrite bool
	Verbose    bool
}

func DetectNoToken(ctx context.Context, sc Context, op openapi.Operation) []report.Finding {
	out := []report.Finding{}
	if !op.RequiresAuth {
		return out
	}

	method := strings.ToUpper(op.Method)
	switch method {
	case http.MethodGet:
		return tryNoToken(ctx, sc, op, nil, "")
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		// Only attempt if user allows writes, otherwise do a conservative probe.
		if !sc.AllowWrite {
			// For POST/PUT/PATCH send the best example body if available (benign).
			// For DELETE, we can only probe if it won't harm; in read-only, skip delete.
			if method == http.MethodDelete {
				return out
			}
			mt, body := pickExample(op.RequestExamples)
			if body == nil {
				// No example -> sending an empty body will likely be 400; inconclusive.
				return out
			}
			return tryNoToken(ctx, sc, op, body, mt)
		}
		// AllowWrite=true: proceed with example-based body for create/update; for DELETE it’s caller’s choice.
		mt, body := pickExample(op.RequestExamples)
		if method != http.MethodDelete && body == nil {
			// No example -> avoid blind writes; inconclusive.
			return out
		}
		return tryNoToken(ctx, sc, op, body, mt)
	default:
		return out
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

func tryNoToken(ctx context.Context, sc Context, op openapi.Operation, body []byte, contentType string) []report.Finding {
	out := []report.Finding{}

	// Build request WITHOUT Authorization.
	h := sc.Headers.Clone()
	h.Del("Authorization")
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}

	req, _ := http.NewRequestWithContext(ctx, op.Method, strings.TrimRight(sc.BaseURL, "/")+op.Path, bytesOrNil(body))
	req.Header = h

	resp, err := sc.Client.Do(req)
	if err != nil {
		return out // connectivity is handled elsewhere
	}
	defer func() { _ = resp.Body.Close() }()

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	ct := strings.ToLower(resp.Header.Get("content-type"))
	status := resp.StatusCode
	cls := status / 100

	// Decision table
	switch {
	case cls == 2 || cls == 3:
		out = append(out, report.Finding{
			ID:       "A-201",
			Severity: "high",
			Category: "broken-auth",
			Endpoint: op.Path,
			Method:   strings.ToUpper(op.Method),
			Evidence: map[string]any{
				"status": status,
				"reason": "secured endpoint responded success without Authorization",
			},
			Remedy: "Enforce auth middleware; return 401/403 to unauthenticated requests.",
		})
	case status == 401 || status == 403:
		// Expected denial -> no finding
	case status == 404:
		// Hidden route -> no finding
	case status == 400 || status == 415:
		// Likely validation before auth (inconclusive) -> no finding
	case status >= 500:
		out = append(out, report.Finding{
			ID:       "A-202",
			Severity: "medium",
			Category: "broken-auth",
			Endpoint: op.Path,
			Method:   strings.ToUpper(op.Method),
			Evidence: map[string]any{
				"status": status,
				"reason": "server error when accessing secured endpoint without token",
			},
			Remedy: "Handle unauthenticated access gracefully; avoid server crashes.",
		})
		// Optional heuristic: APIs returning HTML redirects for login in 3xx
	case cls == 3 && strings.Contains(ct, "text/html") && strings.Contains(strings.ToLower(string(snippet)), "<html"):
		out = append(out, report.Finding{
			ID:       "A-203",
			Severity: "low",
			Category: "broken-auth",
			Endpoint: op.Path,
			Method:   strings.ToUpper(op.Method),
			Evidence: map[string]any{
				"status":       status,
				"content-type": ct,
				"body-snippet": string(snippet),
				"reason":       "redirected to HTML login page instead of API-style JSON 401/403",
			},
			Remedy: "Return JSON 401/403 errors for APIs instead of HTML login pages.",
		})
	}

	return out
}

func bytesOrNil(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return strings.NewReader(string(b))
}
