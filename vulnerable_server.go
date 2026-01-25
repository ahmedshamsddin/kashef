package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// This server intentionally has vulnerabilities to test Kashef
func main() {
	mux := http.NewServeMux()

	// 1. API2: Broken Auth (No Token)
	// Spec says this requires auth, but code doesn't check it
	mux.HandleFunc("/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id": 1, "name": "admin"}]`))
	})

	// 2. API2: Broken Auth (JWT Vulnerabilities)
	// Accepts any token, even expired or alg:none
	mux.HandleFunc("/v1/admin", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// VULNERABILITY: No actual validation of JWT signature or expiry
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "welcome admin"}`))
	})

	// 3. API7: SSRF
	// Vulnerable to "url" parameter
	mux.HandleFunc("/v1/fetch", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			// Simulate server making a request (SSRF)
			// In a real test, this would hit Kashef's OOB server
			http.Get(target)
		}
		w.WriteHeader(http.StatusOK)
	})

	// 4. API8: Security Misconfig (Error Disclosure & CORS)
	mux.HandleFunc("/v1/debug", func(w http.ResponseWriter, r *http.Request) {
		// CORS Misconfiguration
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Error Disclosure
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`RuntimeError: Unhandled exception at /app/src/main.py:42
		Traceback (most recent call last): ...`))
	})

	// 5. API9: Inventory (Schema Non-Compliance)
	// Returns fields not in spec ("internal_ip")
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "ok",
			"internal_ip": "10.0.0.5", // Unexpected field
		})
	})

	fmt.Println("Vulnerable Server running on :8080...")
	http.ListenAndServe(":8080", mux)
}
