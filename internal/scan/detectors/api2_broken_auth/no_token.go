package api2brokenauth

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type Context struct {
	BaseURL string
	Client  *http.Client
	Headers http.Header
}

func DetectNoToken(ctx context.Context, sc Context, op openapi.Operation) []report.Finding {
	out := []report.Finding{}

	if strings.ToUpper(op.Method) != http.MethodGet || !op.RequiresAuth {
		return out
	}

	h := sc.Headers.Clone()
	h.Del("Authorizatio")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(sc.BaseURL, "/")+op.Path, nil)
	req.Header = h

	resp, err := sc.Client.Do(req)
	if err != nil {
		// connectivity handled elsewhere; stay silent here
		return out
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	ct := strings.ToLower(resp.Header.Get("content-type"))

	status := resp.StatusCode
	statusClass := status / 100

	switch {
	case statusClass == 2 || statusClass == 3:
		out = append(out, report.Finding{
			ID:       "A-201",
			Severity: "high",
			Category: "broken-auth",
			Endpoint: op.Path,
			Method:   op.Method,
			Evidence: map[string]any{
				"status": status,
				"reason": "secured endpoint responded success without Authorization",
			},
			Remedy: "Enforce auth middleware; respond 401/403 to unauthenticated requests.",
		})
	case status == 404:
		// Do nothing (safe behavior)
	case status == 400:
	case status == 401 || status == 403:
	case status >= 500:
		out = append(out, report.Finding{
			ID:       "A-202",
			Severity: "medium",
			Category: "broken-auth",
			Endpoint: op.Path,
			Method:   op.Method,
			Evidence: map[string]any{
				"status": status,
				"reason": "server error when accessing secured endpoint without token",
			},
			Remedy: "Handle unauthenticated access gracefully; avoid server crashes.",
		})
	case statusClass == 3 && strings.Contains(ct, "text/html") && strings.Contains(string(body), "<html"):
		out = append(out, report.Finding{
			ID:       "A-203",
			Severity: "low",
			Category: "broken-auth",
			Endpoint: op.Path,
			Method:   op.Method,
			Evidence: map[string]any{
				"status":       status,
				"content-type": ct,
				"body-snippet": string(body),
				"reason":       "redirected to HTML login page instead of API-style error",
			},
			Remedy: "Return JSON 401/403 errors instead of HTML for consistency.",
		})
	}

	return out
}
