# Pentest Report Template

The orchestrator must generate a comprehensive report following this structure. Reports are generated in both Markdown (.md) and DOCX (.docx) formats.

## Report Structure

```markdown
# Android Penetration Test Report

**Target Application:** <app_name> (<package_name>) v<version>
**Date:** <YYYY-MM-DD>
**Target SDK:** <targetSdkVersion> | **Min SDK:** <minSdkVersion>
**Device:** <model> (Android <version>, API <level>), <Rooted/Not Rooted>
**Tester:** Android Pentest Agent (Claude Code)

---

## Table of Contents
1. Executive Summary
2. Scope & Methodology
3. Findings Summary
4. Detailed Findings
5. Attack Chain Analysis
6. Recommendations
7. Appendix

---

## 1. Executive Summary

<2-3 paragraph overview describing:
- What was tested and how
- Overall security posture (good/moderate/poor/critical)
- Most critical findings and their business impact
- Key recommendations>

| Severity | Count |
|----------|-------|
| Critical | X |
| High     | X |
| Medium   | X |
| Low      | X |
| Info     | X |

---

## 2. Scope & Methodology

### Scope
- Application: <package_name> v<version>
- APK SHA256: <hash>
- Testing type: Static analysis, Dynamic analysis, Exploit validation
- Device: <details>
- Out of scope: API/server-side testing

### Methodology
- Static analysis via automated scanner (manifest, pattern, heuristic, taint engines) + manual code review
- Dynamic analysis via ADB, Frida, Medusa
- Exploit validation via PoC Android apps, Frida scripts
- Reference: OWASP MASTG, OWASP Mobile Top 10

### Tools Used
- Static scanner (custom, Contract v0.4.0)
- Frida <version>
- Medusa
- ADB
- jadx-gui

---

## 3. Findings Summary

| # | Title | Severity | Category | Exploitable | PoC |
|---|-------|----------|----------|-------------|-----|
| 1 | <title> | Critical | <cat> | Yes | App |
| 2 | <title> | High | <cat> | Yes | App |
| ... | | | | | |

---

## 4. Detailed Findings

### VULN-001: <Title>

**Severity:** Critical / High / Medium / Low / Info
**CVSS:** <score> (<vector>)
**Category:** <Component Exposure / Intent Injection / Data Storage / Crypto / WebView / etc.>
**CWE:** CWE-XXX (<name>)
**Affected Component:** <component name> (exported=<true/false>)
**Affected File:** <file:line>

#### Description

<Detailed explanation of the vulnerability in 3-5 sentences. Explain:
- What the vulnerable code does
- Why it is insecure
- What security control is missing or broken
- Context: is this a design flaw, implementation bug, or misconfiguration?>

#### Vulnerable Code

```java
// <file>:<line>
<relevant code snippet with vulnerable line highlighted>
```

#### Impact

<Explain the real-world impact from an attacker's perspective:
- What can an attacker gain? (data theft, code execution, privilege escalation, DoS)
- What are the prerequisites? (app installed, user interaction, root, etc.)
- How many users are affected?
- What is the business impact?>

#### Proof of Concept

**Attack Scenario:**
1. Attacker creates a malicious app and publishes it (or victim installs via sideload)
2. Malicious app sends crafted intent to <component>
3. <what happens>
4. Attacker gains <access/data/execution>

**PoC App:** `exploits/poc_VULN-001/` (see BUILD_INSTRUCTIONS.md)

**Key PoC Code:**
```java
// From exploits/poc_VULN-001/java/.../MainActivity.java
<key exploit code snippet - not the full file, just the exploit logic>
```

**ADB Quick Validation:**
```bash
<adb command that demonstrates the vulnerability>
```

**Evidence:**

| Before | After |
|--------|-------|
| ![Before](exploits/VULN-001_before.png) | ![After](exploits/VULN-001_after.png) |

**Logcat Output:**
```
<relevant logcat lines showing the exploit succeeded>
```

#### Remediation

<Specific, actionable fix. Include:
- What to change in code (with code example if possible)
- What security control to add
- Android API to use (e.g., FLAG_IMMUTABLE, setPackage(), getCanonicalPath())
- Reference to Android developer docs>

**Recommended fix:**
```java
// Instead of:
<vulnerable code>

// Use:
<fixed code>
```

#### References
- <CWE link>
- <OWASP MASTG reference>
- <Android developer docs link>
- <Related CVE if applicable>

---

(Repeat for each finding)

---

## 5. Attack Chain Analysis

<Describe how multiple findings can be chained together for greater impact>

### Chain 1: <Name>
```
<Step-by-step attack chain with arrows>
Attacker App → Vuln A (exported activity) → Vuln B (intent redirection)
  → Vuln C (WebView file access) → File Exfiltration to attacker server
```

**Combined Impact:** <what the full chain achieves>
**PoC:** <reference to chain PoC if created>

---

## 6. Recommendations

### Priority 1 (Fix Immediately)
1. <recommendation for critical finding>
2. <recommendation for critical finding>

### Priority 2 (Fix in Next Release)
3. <recommendation for high finding>
4. <recommendation for high finding>

### Priority 3 (Planned Fix)
5. <recommendations for medium findings>

### General Hardening
- <general security improvements>

---

## 7. Appendix

### A. Exported Components
| Component | Type | Permission | Exploitable |
|-----------|------|------------|-------------|
| <name> | Activity | None | Yes |
| <name> | Receiver | normal | Yes |

### B. Permissions Requested
| Permission | Protection Level | Risk |
|------------|-----------------|------|
| INTERNET | Normal | Network access |

### C. Deep Links
| Scheme | Host | Handler | Validated |
|--------|------|---------|-----------|
| <scheme> | <host> | <activity> | No |

### D. PoC Apps Index
| Finding | PoC Directory | Build Status |
|---------|--------------|-------------|
| VULN-001 | exploits/poc_VULN-001/ | Source provided |

### E. Tool Output
- Scanner JSON: `static/scanner_results.json`
- Verified findings: `static/verified_findings.json`
- Dynamic findings: `dynamic/dynamic_findings.json`
- Exploit results: `exploits/*_exploit_result.json`
```

## Screenshot Embedding

Always capture and embed screenshots:

```bash
# Before exploit
adb shell screencap -p /sdcard/before.png
adb pull /sdcard/before.png <output_dir>/VULN-001_before.png

# After exploit
adb shell screencap -p /sdcard/after.png
adb pull /sdcard/after.png <output_dir>/VULN-001_after.png
```

In markdown, reference as:
```markdown
![Before exploit](exploits/VULN-001_before.png)
![After exploit](exploits/VULN-001_after.png)
```

## DOCX Generation

After writing the markdown report, convert to DOCX:
```bash
# If pandoc is available:
pandoc report.md -o report.docx --reference-doc=template.docx

# If python-docx is available:
python3 -c "
from docx import Document
# ... generate DOCX programmatically
"
```

## Logging

Use `pidcat` for cleaner, filtered logs:
```bash
# If pidcat is available (pip install pidcat):
pidcat <package_name> > <output_dir>/pidcat_log.txt &

# Fallback:
adb logcat --pid=$(adb shell pidof <package_name>) -v time
```
