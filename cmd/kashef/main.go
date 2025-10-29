package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/scan"
	"github.com/spf13/cobra"
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
	root := &cobra.Command{Use: "kashef", Short: "kashef — API Vulnerability scanner"}

	//root.PersistentFlags().StringSliceVarP(&headers, "header", "H", nil, `-H "Authorization: Bearer XXX"`)
	root.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 15*time.Second, "HTTP timeout")

	scanCmd := &cobra.Command{Use: "scan", Short: "Scan targets"}
	openapiCmd := &cobra.Command{
		Use:   "openapi <spec-file-or-url>",
		Short: "Scan using an OpenAPI spec",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := scan.RunOpenAPIScan(args[0], out, headers, timeout, concurrency, failOn, verbose, allowWrite, token)
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	openapiCmd.Flags().StringVarP(&out, "out", "o", "report.json", "Output (json|md by extension)")
	openapiCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 12, "Concurrent requests")
	openapiCmd.Flags().StringVar(&failOn, "fail-on", "medium", "Fail CI on >= severity (none|low|medium|high)")
	openapiCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print debug scan info")
	openapiCmd.Flags().BoolVar(&allowWrite, "allow-write", false, "Allow POST/PUT/PATCH/DELETE probes (use only on staging)")
	openapiCmd.Flags().StringVar(&token, "token", "", "Bearer token for Authorization header")

	scanCmd.AddCommand(openapiCmd)
	root.AddCommand(scanCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
