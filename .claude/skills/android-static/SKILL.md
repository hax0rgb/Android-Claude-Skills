---
name: android-static
description: Run static analysis on an Android APK - automated scanner + deep manual code review for vulnerability discovery
argument-hint: <apk_path> [instructions...]
context: fork
agent: android-static
model: opus
---

# Android Static Analysis

Perform deep static security analysis on an Android APK.

## Arguments
- `$ARGUMENTS[0]` - Path to the target APK file (required)
- `$ARGUMENTS[1+]` - Additional instructions (optional): focus areas, known credentials, scope limits, output directory

**Examples:**
```
/android-static /path/to/app.apk
/android-static /path/to/app.apk Focus on WebView and content provider vulnerabilities. Check for hardcoded AWS keys.
```
- `$ARGUMENTS[1]` - Output directory (optional, defaults to `outputs/YYYYMMDD_<package>/static/`)

## What It Does

### Phase 1: Automated Scanner
Runs the security scanner at `/Users/gaurangbhatnagar/Documents/android-security-scanner/backend/scanner.py` which performs:
- Manifest analysis (exported components, permissions, flags)
- Pattern detection (WebView, crypto, data storage)
- Heuristic analysis (IPC, network, crypto misuse)
- Taint flow analysis (source-to-sink data flows)

### Phase 2: Finding Verification
For each scanner finding, reads decompiled source code to verify exploitability.

### Phase 3: Manual Code Review
Goes beyond the scanner to find:
- Hardcoded secrets and API keys
- Intent injection points
- Deep link vulnerabilities
- Custom crypto weaknesses
- Data storage issues
- WebView attack surface

### Output
- `scanner_results.json` - Raw scanner output
- `verified_findings.json` - Verified and enriched findings with exploitation paths
- `static_report.md` - Human-readable report

## Reference Files
- [Scanner Integration](reference/scanner-integration.md) - Scanner invocation and output format
- [Manual Review Patterns](reference/manual-review.md) - Code review checklist beyond scanner
- [Vuln Patterns from Writeups](reference/vuln-patterns-from-writeups.md) - Real-world vulnerability patterns from CVEs, Samsung 0-days, MHL/8kSec labs
- [API Key Validation](reference/api-key-validation.md) - Verify exploitability of 99 API key types (KeyHacks) with curl commands
- [Android Security Evolution](reference/android-security-evolution.md) - What attacks work on which Android versions (API 21-36), pentest strategy by target SDK
