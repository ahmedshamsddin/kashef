package broken_auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type JWTExpiryDetector struct{}

func init() {
	detector.Register(&JWTExpiryDetector{})
}

func (d *JWTExpiryDetector) Info() detector.DetectorInfo {
	return detector.DetectorInfo{
		ID:            "jwt-no-expiry",
		Name:          "Missing JWT Expiration Validation",
		Description:   "Detects if server accepts expired JWT tokens (exp claim in the past)",
		OWASP:         "API2:2023",
		Category:      "broken-auth",
		RequiresAuth:  true,
		RequiresWrite: false,
		AppliesTo:     detector.AppliesTo{}, // Runs on all methods
	}
}

func (d *JWTExpiryDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
	// 1. Construct the Header
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	headerStr := base64.RawURLEncoding.EncodeToString(headerBytes)

	// 2. Construct the Payload with 'exp' in the past
	payload := map[string]interface{}{
		"sub": "kashef-scan",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadStr := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// 3. Sign it with a dummy secret ("secret")
	// If the server accepts this, it's ignoring signatures AND/OR expiry.
	signingInput := headerStr + "." + payloadStr
	signature := d.computeHMACSHA256(signingInput, "secret")

	token := signingInput + "." + signature

	// 4. Send the Request
	reqURL := strings.TrimRight(sc.BaseURL, "/") + op.Path
	req, err := http.NewRequestWithContext(ctx, op.Method, reqURL, nil)
	if err != nil {
		return nil
	}

	req.Header = sc.Headers.Clone()
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := sc.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 5. Analyze Response
	// If we get a success code (2xx), the server failed to block the expired/forged token
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return detector.NewFinding("A-205", "broken-auth.jwt").
			WithSeverity("critical").
			WithEndpoint(op.Method, op.Path).
			WithEvidence("status", resp.StatusCode).
			WithEvidence("token_used", token).
			WithEvidence("exp_claim", payload["exp"]).
			WithReason("Server accepted a JWT with an expiration (exp) timestamp in the past.").
			WithRemedy("Ensure the JWT middleware verifies the 'exp' claim and rejects expired tokens.").
			BuildSlice()
	}

	return nil
}

func (d *JWTExpiryDetector) computeHMACSHA256(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
