  ```
         / /__  ____ _   _____   / /_   ___    / __/
        / //_/ / __ `/  / ___/  / __ \ / _ \  / /_  
       / ,<   / /_/ /  (__  )  / / / //  __/ / __/  
      /_/|_|  \__,_/  /____/  /_/ /_/ \___/ /_/     
```
                                              
# kashef 🔎

**kashef** (Arabic: كاشف, "detector/revealer") is a fast, comprehensive API security scanner that detects vulnerabilities in OpenAPI-based REST APIs aligned with the OWASP API Security Top 10.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/ahmedshamsddin/kashef)](https://github.com/ahmedshamsddin/kashef/releases)

## 🎯 Features

- **OWASP API Security Top 10 Coverage** - Detects vulnerabilities from the latest OWASP API Security standard
- **OpenAPI/Swagger Integration** - Analyzes API specifications and validates runtime behavior
- **Fast Concurrent Scanning** - Configurable parallel request execution for rapid results
- **CI/CD Ready** - Built-in exit codes and severity thresholds for seamless pipeline integration
- **Multiple Output Formats** - Generate JSON or Markdown reports 


## 📋 Supported Vulnerability Classes

| Category | Detectors | OWASP Mapping |
|----------|-----------|---------------|
| **Broken Authentication** | JWT Algorithm None, Missing Expiry, No Token | API2:2023 |
| **SSRF (Server-Side Request Forgery)** | Out-of-Band Detection | API7:2023 |
| **Security Misconfiguration** | CORS, Error Disclosure, Missing Security Headers | API8:2023 |
| **Improper Inventory Management** | Schema Compliance, Status Code Drift | API9:2023 |
| **Connectivity** | Health Checks | - |

## 🚀 Quick Start

### Installation

#### Using Go

```bash
go install github.com/ahmedshamsddin/kashef/cmd/kashef@latest
```

#### From Source

```bash
git clone https://github.com/ahmedshamsddin/kashef.git
cd kashef
go build -o kashef cmd/kashef/main.go
sudo mv kashef /usr/local/bin/
```

### Basic Usage

```bash
# Scan using OpenAPI specification
kashef scan openapi ./openapi.yaml

# Scan remote API
kashef scan openapi https://api.example.com/openapi.json

# Scan with authentication token
kashef scan openapi ./spec.yaml --token "your-jwt-token"

# Generate Markdown report
kashef scan openapi ./spec.yaml -o report.md

# Verbose output for debugging
kashef scan openapi ./spec.yaml -v
```

## 📖 Command Reference

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `15s` | HTTP request timeout |

### Scan OpenAPI Command

```bash
kashef scan openapi <spec-file-or-url> [flags]
```

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--out` | `-o` | `report.json` | Output file path (json\|md by extension) |
| `--concurrency` | `-c` | `12` | Number of concurrent requests |
| `--fail-on` | | `medium` | Fail CI on >= severity (none\|low\|medium\|high\|critical) |
| `--verbose` | `-v` | `false` | Print detailed scan information |
| `--allow-write` | | `false` | Allow POST/PUT/PATCH/DELETE probes (⚠️ DANGEROUS - staging only!) |
| `--token` | | `""` | Bearer token for Authorization header |

## 💡 Usage Examples

### Basic Scanning

```bash
# Scan local API specification
kashef scan openapi ./api-spec.yaml

# Scan with verbose output to see what's happening
kashef scan openapi ./api-spec.yaml -v

# Custom output location
kashef scan openapi ./api-spec.yaml -o ./reports/security-scan.json

# Scan remote specification
kashef scan openapi https://petstore.swagger.io/v2/swagger.json
```

### Authentication

```bash
# Using bearer token
kashef scan openapi ./api-spec.yaml --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Scan authenticated endpoints (token required for auth checks)
kashef scan openapi ./secure-api.yaml --token "$AUTH_TOKEN" -v
```

### CI/CD Integration

```bash
# Fail build on high or critical severity issues
kashef scan openapi ./api-spec.yaml --fail-on high

# Fail on any issues (including low severity)
kashef scan openapi ./api-spec.yaml --fail-on low

# Never fail build (reporting only)
kashef scan openapi ./api-spec.yaml --fail-on none

# Generate markdown report for PR comments
kashef scan openapi ./api-spec.yaml -o security-report.md --fail-on medium
```

### Advanced Options

```bash
# Adjust concurrency for faster scans
kashef scan openapi ./api-spec.yaml -c 20

# Increase timeout for slow APIs
kashef scan openapi ./api-spec.yaml --timeout 30s

# Comprehensive scan with all options
kashef scan openapi ./api-spec.yaml \
  --token "$JWT_TOKEN" \
  --concurrency 15 \
  --timeout 20s \
  --fail-on high \
  --verbose \
  -o ./reports/full-scan.json
```

### Testing Write Operations (⚠️ Staging Only)

```bash
# Enable POST/PUT/PATCH/DELETE testing (DANGEROUS!)
kashef scan openapi ./staging-api.yaml --allow-write

# Use on non-production environments only
kashef scan openapi https://staging.api.example.com/openapi.json \
  --allow-write \
  --token "$STAGING_TOKEN" \
  -v
```

**⚠️ Warning:** Only use `--allow-write` on non-production environments as it may create, modify, or delete data through the API.

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: API Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install Kashef
        run: go install github.com/ahmedshamsddin/kashef/cmd/kashef@latest
      
      - name: Run Security Scan
        run: |
          kashef scan openapi ./openapi.yaml \
            --fail-on high \
            -o report.json
      
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: report.json
      
      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        run: |
          kashef scan openapi ./openapi.yaml -o report.md --fail-on none
          gh pr comment ${{ github.event.pull_request.number }} -F report.md
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
## 🏗️ Architecture

Kashef uses a modular detector architecture for extensibility and maintainability:

```
┌─────────────────┐
│  CLI Interface  │
│   (Cobra CLI)   │
└────────┬────────┘
         │
┌────────▼────────┐
│  Scan Executor  │
│ (Orchestration) │
└────────┬────────┘
         │
         ├─────────────────┬──────────────────┬────────────────┬──────────────┐
         ▼                 ▼                  ▼                ▼              ▼
┌────────────────┐ ┌──────────────┐ ┌───────────────┐ ┌──────────┐ ┌──────────┐
│ Auth Detectors │ │SSRF Detector │ │Config Detector│ │Inventory │ │Connectivity│
│  - JWT Alg     │ │  - OOB Check │ │  - CORS       │ │ - Schema │ │  - Health  │
│  - Expiry      │ │  - URL Params│ │  - Headers    │ │ - Status │ │  - Errors  │
│  - No Token    │ │  - Body Fuzz │ │  - Errors     │ │          │ │            │
└────────────────┘ └──────────────┘ └───────────────┘ └──────────┘ └──────────┘
         │                 │                  │                │              │
         └─────────────────┴──────────────────┴────────────────┴──────────────┘
                                   │
                           ┌───────▼────────┐
                           │ Report Builder │
                           │  (JSON/MD)     │
                           └────────────────┘
```

### Key Components

- **Detector Registry**: Automatically discovers and registers all security detectors at runtime
- **OpenAPI Parser**: Extracts endpoints, schemas, security requirements, and examples
- **Concurrent Scanner**: Parallel execution with configurable worker pools for performance
- **OOB Server**: Out-of-band callback server for SSRF and blind vulnerability detection
- **Report Generator**: Produces both JSON (machine-readable) and Markdown (human-readable) outputs
- **Context Manager**: Manages authentication, headers, and scan configuration across detectors

## 🛠️ Development


### Building from Source

```bash
# Clone repository
git clone https://github.com/ahmedshamsddin/kashef.git
cd kashef

# Install dependencies
go mod download

# Build binary
go build -o kashef cmd/kashef/main.go

# Run with local changes
go run cmd/kashef/main.go scan openapi examples/vulnerable_server.yaml
```

### Adding New Detectors

Create a new detector by implementing the `Detector` interface:

```go
package mydetector

import (
    "context"
    "github.com/ahmedshamsddin/kashef/internal/detector"
    "github.com/ahmedshamsddin/kashef/internal/openapi"
    "github.com/ahmedshamsddin/kashef/internal/report"
)

type MyDetector struct{}

// Register detector on package import
func init() {
    detector.Register(&MyDetector{})
}

// Provide detector metadata
func (d *MyDetector) Info() detector.DetectorInfo {
    return detector.DetectorInfo{
        ID:            "my-detector-id",
        Name:          "My Security Detector",
        Description:   "Detects XYZ vulnerability pattern",
        OWASP:         "API1:2023",
        Category:      "my-category",
        RequiresAuth:  false,
        RequiresWrite: false,
        AppliesTo:     detector.OnlyMethods("GET", "POST"),
    }
}

// Implement detection logic
func (d *MyDetector) Detect(ctx context.Context, sc *detector.Context, op openapi.Operation) []report.Finding {
    // Your detection logic here
    // Return findings or nil if no issues found
    
    return detector.NewFinding("A-999", "my-category").
        WithSeverity("high").
        WithEndpoint(op.Method, op.Path).
        WithEvidence("detail", "vulnerability detected").
        WithRemedy("Fix by doing XYZ").
        BuildSlice()
}
```

Import the detector in `cmd/kashef/main.go`:

```go
import (
    // ... other imports
    _ "github.com/ahmedshamsddin/kashef/internal/scan/detectors/mydetector"
)
```

The detector will be automatically registered and used in scans!


## 🧪 Testing

The project includes a vulnerable test server for validation:

### Start Test Server

```bash
# Terminal 1: Start vulnerable server
go run tests/vulnerable_server.go

# Server starts on http://localhost:8080
```

### Run Scan Against Test Server

```bash
# Terminal 2: Run scan
kashef scan openapi examples/vulnerable_server.yaml -v

# Expected output: Multiple high/critical findings
```
## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
