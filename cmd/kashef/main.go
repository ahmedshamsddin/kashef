package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/scan"
	"github.com/spf13/cobra"

	// Register all detectors via blank imports
	// These run init() functions that call detector.Register()
	_ "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api2_broken_auth"
	_ "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api7_ssrf"
	_ "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api8_security_misconfig"
	_ "github.com/ahmedshamsddin/kashef/internal/scan/detectors/api9_inventory"
	_ "github.com/ahmedshamsddin/kashef/internal/scan/detectors/connectivity"
)

var (
	out         string
	concurrency int
	timeout     time.Duration
	headers     []string
	failOn      string
	verbose     bool
	allowWrite  bool
	token       string
)

func main() {
	root := &cobra.Command{
		Use:   "kashef",
		Short: "kashef — API Vulnerability Scanner",
		Long: `Kashef is an API security scanner that detects vulnerabilities aligned with 
OWASP API Security Top 10. It analyzes OpenAPI specifications and tests 
running APIs for security issues.`,
	}

	root.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 15*time.Second, "HTTP request timeout")

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan API targets for vulnerabilities",
	}

	openapiCmd := &cobra.Command{
		Use:   "openapi <spec-file-or-url>",
		Short: "Scan API using OpenAPI/Swagger specification",
		Long: `Scan an API by analyzing its OpenAPI (Swagger) specification.
The scanner will test all endpoints defined in the spec for common
security vulnerabilities including:
  - Broken Authentication (API2:2023)
  - SSRF (API7:2023)
  - Security Misconfiguration (API8:2023)
  - Improper Inventory Management (API9:2023)

Examples:
  # Scan local spec file
  kashef scan openapi ./openapi.yaml

  # Scan remote spec
  kashef scan openapi https://api.example.com/openapi.json

  # Scan with authentication
  kashef scan openapi ./spec.yaml --token "your-jwt-token"

  # Allow testing of write operations (use on staging only!)
  kashef scan openapi ./spec.yaml --allow-write

  # Output markdown report
  kashef scan openapi ./spec.yaml -o report.md

  # Fail CI if high severity issues found
  kashef scan openapi ./spec.yaml --fail-on high`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := scan.RunOpenAPIScan(
				args[0], out, headers, timeout, concurrency,
				failOn, verbose, allowWrite, token,
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}

	openapiCmd.Flags().StringVarP(&out, "out", "o", "report.json", "Output file path (json|md by extension)")
	openapiCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 12, "Number of concurrent requests")
	openapiCmd.Flags().StringVar(&failOn, "fail-on", "medium", "Fail CI on >= severity (none|low|medium|high|critical)")
	openapiCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print detailed scan information")
	openapiCmd.Flags().BoolVar(&allowWrite, "allow-write", false, "Allow POST/PUT/PATCH/DELETE probes (DANGEROUS - use only on staging!)")
	openapiCmd.Flags().StringVar(&token, "token", "", "Bearer token for Authorization header")

	scanCmd.AddCommand(openapiCmd)
	root.AddCommand(scanCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}
