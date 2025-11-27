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

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type JWTAlgNoneDetector struct{}

func init() {
	detector.Register(&JWTAlgNoneDetector{})
}

func (d *JWTAlgNoneDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "jwt-alg-none",
		Name:          "JWT Algorithm None",
		Description:   "Detects if server accepts unsigned JWT tokens (alg=none)",
		OWASP:         "API2:2023",
		Category:      "broken-auth",
		RequiresAuth:  true,
		RequiresWrite: false,
		AppliesTo:     detector.AppliesTo{}, // all methods
	}
}

func (d *JWTAlgNoneDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	header := map[string]interface{}{"alg": "none", "typ": "JWT"}
	payload := map[string]interface{}{
		"sub": fmt.Sprintf("kashef-%d", time.Now().Unix()%100000),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
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
		return nil
	}
	defer resp.Body.Close()

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	ct := strings.ToLower(resp.Header.Get("content-type"))
	status := resp.StatusCode
	cls := status / 100

	switch {
	case cls == 2 || cls == 3:
		return detector.NewFinding("A-210", "broken-auth.jwt").
			WithSeverity("high").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", status).
			WithEvidence("token_example", token).
			WithEvidence("response_snippet", string(snippet)).
			WithEvidence("content_type", ct).
			WithReason("server accepted unsigned JWT (alg=none)").
			WithRemedy("Reject tokens with `alg: none` and verify signatures and claims (exp/iat/sub).").
			BuildSlice()

	case status >= 500:
		return detector.NewFinding("A-211", "broken-auth.jwt").
			WithSeverity("medium").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", status).
			WithReason("server error when testing unsigned JWT").
			WithRemedy("Ensure auth validation handles malformed/unauthorized tokens gracefully.").
			BuildSlice()

	default:
		return nil
	}
}
