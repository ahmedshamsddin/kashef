package broken_auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

func DetectJWTAlgNone(ctx context.Context, sc Context, op openapi.Operation) []report.Finding {
	out := []report.Finding{}

	if !op.RequiresAuth {
		return out
	}

	header := map[string]interface{}{"alg": "none", "typ": "JWT"}
	payload := map[string]interface{}{
		"sub": fmt.Sprintf("kashef-%d", time.Now().Unix()%100000), // non-sensitive unique subject
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(), // short expiry
	}

	hj, _ := json.Marshal(header)
	pj, _ := json.Marshal(payload)

	enc := base64.RawURLEncoding.EncodeToString
	token := enc(hj) + "." + enc(pj) + "."

	hdr := sc.Headers.Clone()
	hdr.Set("Authorization", "Bearer "+token)

	req, _ := http.NewRequestWithContext(ctx, op.Method, strings.TrimRight(sc.BaseURL, "/")+op.Path, nil)
	req.Header = hdr

	resp, err := sc.Client.Do(req)
	if err != nil {
		return out
	}

	defer func() { _ = resp.Body.Close() }()

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	ct := strings.ToLower(resp.Header.Get("content-type"))
	status := resp.StatusCode
	cls := status / 100
	switch {
	case cls == 2 || cls == 3:
		out = append(out, report.Finding{
			ID:       "A-210",
			Severity: "high",
			Category: "broken-auth.jwt",
			Endpoint: op.Path,
			Method:   strings.ToUpper(op.Method),
			Evidence: map[string]any{
				"status":           status,
				"token_example":    token, // include token used so reviewer can reproduce
				"response_snippet": string(snippet),
				"content_type":     ct,
				"reason":           "server accepted unsigned JWT (alg=none)",
			},
			Remedy: "Reject tokens with `alg: none` and verify signatures and claims (exp/iat/sub).",
		})
	case status == 401 || status == 403:
		// correct behaviour
	case status >= 500:
		out = append(out, report.Finding{
			ID:       "A-211",
			Severity: "medium",
			Category: "broken-auth.jwt",
			Endpoint: op.Path,
			Method:   strings.ToUpper(op.Method),
			Evidence: map[string]any{
				"status": status,
				"reason": "server error when testing unsigned JWT",
			},
			Remedy: "Ensure auth validation handles malformed/unauthorized tokens gracefully.",
		})
	default:
		// 400/404 etc — treat as inconclusive; don't flag
	}

	return out
}
