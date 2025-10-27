package api8securitymisconfig

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ahmedshamsddin/kashef/internal/report"
)

func CheckErrorDisclosure(ctx context.Context, client *http.Client, baseURL, path, method string, headers http.Header) []report.Finding {
	url := baseURL + path
	req, _ := http.NewRequestWithContext(ctx, method, url, nil)
	req.Header = headers.Clone()

	// Inject a synthetic/unsigned JWT *only if* no Authorization was provided.
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read a small snippet only (avoid huge bodies)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	return DetectErrorDisclosure(path, method, resp.StatusCode, string(bodyBytes))

}

func DetectErrorDisclosure(endpoint, method string, status int, body string) []report.Finding {
	out := []report.Finding{}

	if status < 400 {
		return out
	}

	patterns := []string{
		"traceback", "exception", "syntaxerror", "typeerror",
		"referenceerror", "evalerror", "rangeerror", "stack",
		"express", "flask", "django", "spring", "laravel",
		"at ", "line ", "undefined", "cannot read property",
		"sever misconfiguration", "runtimeerror",
	}

	lowerBody := strings.ToLower(body)

	for _, p := range patterns {
		if strings.Contains(lowerBody, p) {
			out = append(out, report.Finding{
				ID:       "A-801",
				Severity: "medium",
				Category: "error.disclosure",
				Endpoint: endpoint,
				Method:   method,
				Evidence: map[string]any{"pattern": lowerBody},
				Remedy:   "Avoid exposing detailed error messages or stack traces to clients. Return generic error responses.",
			})
			break
		}
	}

	return out
}
