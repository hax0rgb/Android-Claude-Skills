---
name: orchestrator
description: Run full Android penetration test - orchestrates static analysis, dynamic testing, native fuzzing, and exploit validation across all agents
argument-hint: <apk_path> [device] [additional instructions...]
---

# Android Pentest Orchestrator

Run a comprehensive Android penetration test on the provided APK.

**IMPORTANT:** This skill runs in the main conversation context (NOT forked) because it needs the `Agent` tool to spawn sub-agents. Subagents cannot spawn other subagents in Claude Code.

## Arguments
- `$ARGUMENTS[0]` - Path to the target APK file (required)
- `$ARGUMENTS[1]` - Device identifier (optional). Accepts:
  - IP:port for WiFi/network: `192.168.1.100:5555`
  - USB serial number: `2cf4fc4d`
  - Skip or omit for static-only mode
- `$ARGUMENTS[2+]` - Additional instructions (optional). Free-text instructions passed to all agents. Examples:
  - Credentials: `Use admin:password123 to login`
  - Focus areas: `Focus on WebView and deep link attack surface`
  - Scope limits: `Only test exported components, skip native analysis`
  - App context: `App is already installed on device, package name is com.example.app`

## Quick Start

Execute all phases of Android security testing:

1. **Static Analysis** - Run automated scanner + manual code review
2. **Dynamic Analysis** - Runtime testing on connected device
3. **Native Fuzzing** - Analyze and fuzz native libraries
4. **Exploit Validation** - Create and execute PoCs for verified findings
5. **Reporting** - Consolidated findings report

## Usage Examples
```
# Full test with WiFi device
/orchestrator /path/to/app.apk 192.168.1.100:5555

# Full test with USB device
/orchestrator /path/to/app.apk 2cf4fc4d

# Static-only (no device)
/orchestrator /path/to/app.apk

# With credentials and focus area
/orchestrator /path/to/app.apk 192.168.1.16:5555 Use testuser:Pass123! to login. Focus on intent redirection and WebView vulnerabilities.

# App already installed, provide package name
/orchestrator /path/to/app.apk 2cf4fc4d App is already installed. Package: com.example.app. Skip native fuzzing.
```

## Execution Instructions

You are the orchestrator. You have access to `Bash`, `Agent`, `Read`, `Write`, and all other tools. Follow the orchestrator agent definition in `.claude/agents/orchestrator.md` for the full workflow.

### Phase 0: Setup

**Parse arguments:**
- `$ARGUMENTS[0]` = APK path
- `$ARGUMENTS[1]` = Device identifier (may be IP:port OR USB serial, or absent)
- `$ARGUMENTS[2+]` = Additional user instructions (join into single string)

**Detect device type:**
```bash
# If device arg contains ":" -> it's IP:port, connect via network
adb connect <ip:port>

# If device arg is alphanumeric without ":" -> it's USB serial, use -s flag
adb -s <serial> devices

# If no device arg -> static-only mode
```

**All ADB commands must use the device flag:**
- Network: `adb -s <ip:port> shell ...`
- USB: `adb -s <serial> shell ...`

**Steps:**
1. Extract package name: `aapt dump badging <apk> | grep package` (or `aapt2`, or parse manifest)
2. Create output directory: `mkdir -p outputs/YYYYMMDD_<package>/{static,dynamic,native,exploits}`
3. If device provided: connect/verify with `adb devices`
4. Store additional instructions to pass to all sub-agents
5. **Initialize dashboard and auto-launch it:**
```bash
# Initialize status file
python3 .claude/scripts/status_writer.py \
  --status-file outputs/YYYYMMDD_<package>/status.json \
  --init <package> <version> <device_id> <model> <android_ver> <rooted>

# Auto-launch dashboard in a new macOS Terminal window
osascript -e 'tell application "Terminal" to do script "cd '"$(pwd)"' && python3 .claude/scripts/dashboard.py outputs/YYYYMMDD_<package>/status.json"'
```
This opens a new Terminal window with the live dashboard automatically. No manual step needed.

**STATUS_FILE:** Set `STATUS_FILE=outputs/YYYYMMDD_<package>/status.json` and pass this to ALL sub-agents in their prompts. Every agent must call `status_writer.py` to update findings, activity, and notes.

### Phase 1: Static Analysis
Spawn the `android-static` agent. Pass STATUS_FILE and any additional instructions from the user:
```
Agent(prompt="You are the android-static agent. Follow .claude/agents/android-static.md.
Target APK: <path>
Output dir: outputs/YYYYMMDD_<pkg>/static/
STATUS_FILE: outputs/YYYYMMDD_<pkg>/status.json
Update the dashboard: call python3 .claude/scripts/status_writer.py --status-file <STATUS_FILE> for findings, activity, and notes.
Additional instructions from user: <user_instructions>")
```

### Phase 2: Dynamic Analysis (if device provided)
After static completes, spawn `android-dynamic` agent with findings from Phase 1. Pass device identifier (IP:port or serial) and user instructions:
```
Agent(prompt="You are the android-dynamic agent. Follow .claude/agents/android-dynamic.md.
APK: <path>
Device: <device_id>  (use 'adb -s <device_id>' for all commands)
Package: <pkg>
Output: outputs/.../dynamic/
Static findings: <summary of Phase 1 findings>
Additional instructions from user: <user_instructions>")
```

### Phase 3: Native Analysis (CONDITIONAL - not default)

**DO NOT run native fuzzer by default.** Only spawn it when ONE of these conditions is met:
1. Static analysis scanner reports a finding titled "Exported Activity Exposes Native Library to Arbitrary Invocation" or similar native-related finding
2. An exported component directly calls a native method (JNI) with attacker-controllable input (found during static code review)
3. The user explicitly requests native fuzzing in additional instructions

**How to check:** After Phase 1 completes, search the static findings for:
- Native library references in exported components
- `System.loadLibrary` / `System.load` called from exported activities/services
- JNI methods (`native` keyword) invoked with intent extra data
- Scanner findings mentioning native/JNI/`.so` vulnerabilities

If condition is met:
```
Agent(prompt="You are the native-fuzzer agent. Follow .claude/agents/native-fuzzer.md.
APK: <path>. Device: <device_id>. Output: outputs/.../native/
CONTEXT: Static analysis found the following native-related findings: <relevant_findings>
Focus fuzzing on the native functions reachable from these exported components: <component_list>
Additional instructions from user: <user_instructions>")
```

If no condition is met, skip Phase 3 and note in the report: "Native fuzzing skipped - no native libraries reachable from exported attack surface."

### Phase 4: Exploit Validation
For each high/critical finding, spawn exploit-validator. **The exploit-validator MUST create PoC Android apps** (not just ADB commands) for intent/broadcast/provider/WebView/deep link findings. ADB-only proves reachability, not real-world exploitability.
```
Agent(prompt="You are the exploit-validator agent. Follow .claude/agents/exploit-validator.md.
IMPORTANT: Create a complete PoC Android app for this finding - not just ADB commands.
The PoC app must demonstrate how a malicious third-party app exploits this vulnerability.
Write complete Java source + AndroidManifest.xml + BUILD_INSTRUCTIONS.md to the output dir.
Finding: <details>. Device: <ip>. Package: <pkg>. Output: outputs/.../exploits/")
```

### Phase 5: Reporting
Generate a **comprehensive** report following the template in `.claude/skills/orchestrator/reference/report-template.md`.

The report MUST include for each finding:
- **Description**: 3-5 sentences explaining the vulnerability, root cause, and missing security control
- **Vulnerable Code**: Relevant code snippet with line numbers
- **Impact**: Real-world attacker impact, prerequisites, business impact
- **Proof of Concept**: Attack scenario steps, PoC app reference, ADB validation command, evidence screenshots, logcat output
- **Remediation**: Specific code fix with before/after examples

Generate both:
- `outputs/YYYYMMDD_<pkg>/report.md` (Markdown with embedded screenshot references)
- `outputs/YYYYMMDD_<pkg>/report.docx` (if pandoc available: `pandoc report.md -o report.docx`)

Use `pidcat <pkg>` for logging if available (cleaner than raw logcat).

## Reference Files
- [OWASP MASTG Checklist](reference/owasp-mastg-checklist.md) - 139 Android security tests mapped to agent phases
- [Report Template](reference/report-template.md) - Comprehensive report format with finding structure
- [Finding Template](reference/finding_template.md) - Per-finding documentation template
- [Finding Schema](reference/finding.json) - Structured JSON schema for findings
- [Quick Wins](reference/quick_wins.md) - Fast vulnerability identification (5-15 min checks)
- [Pre-Engagement Checklist](reference/pre_engagement.md) - Pre-test verification checklist

## Key Rules
- Never ask the user how to proceed - make autonomous decisions
- Chain context: pass relevant findings from prior phases to new agents
- Run independent agents in parallel (native-fuzzer alongside dynamic)
- If an agent fails, retry once before moving on
- Skip dynamic/exploit phases if no device IP provided
- **PoC apps are mandatory** for intent/broadcast/provider/WebView findings - ADB-only is insufficient
- **Capture before/after screenshots** for every exploited finding
- **Report must be detailed** - follow the template in reference/report-template.md
