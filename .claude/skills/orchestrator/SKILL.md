---
name: orchestrator
description: Run full Android penetration test - orchestrates ranking, parallel hunters, dynamic analysis, chain-finding, exploit validation, and coverage verification
argument-hint: <apk_path> [device] [additional instructions...]
---

# Android Pentest Orchestrator

**IMPORTANT:** This skill runs in the main conversation context (NOT forked) because it needs the `Agent` tool to spawn sub-agents.

## Arguments
- `$ARGUMENTS[0]` - Path to the target APK file (required)
- `$ARGUMENTS[1]` - Device identifier: IP:port or USB serial (optional)
- `$ARGUMENTS[2+]` - Additional instructions (optional): credentials, focus areas, scope limits

## Pipeline Overview

```
Phase 0: Setup + Dashboard Launch
Phase 0.5: Attack Surface Ranking → targets.json
Phase 1: Parallel Static Hunters (8-12 lane-specific agents)
Phase 2: Dynamic Analysis (if device)
Phase 3: Native Fuzzing (CONDITIONAL - only if ranking/scanner found native attack surface)
Phase 3.5: Chain Finder (composes findings into multi-step chains)
Phase 4: Dedup → Exploit Validation (PoC apps)
Phase 5: Coverage Verification → Reporting
```

## Phase 0: Setup

1. Extract package name: `aapt dump badging <apk> | grep package`
2. Create output dirs: `mkdir -p outputs/YYYYMMDD_<pkg>/{static,dynamic,native,exploits,findings}`
3. If device: `adb connect <ip:port>` or verify `adb -s <serial> devices`
4. Initialize + auto-launch dashboard:
```bash
python3 .claude/scripts/status_writer.py --status-file outputs/YYYYMMDD_<pkg>/status.json \
  --init <pkg> <ver> <device_id> <model> <android_ver> <rooted>
osascript -e 'tell application "Terminal" to do script "cd '"$(pwd)"' && python3 .claude/scripts/dashboard.py outputs/YYYYMMDD_<pkg>/status.json"'
```

**STATUS_FILE=`outputs/YYYYMMDD_<pkg>/status.json`** — pass to ALL sub-agents.

## Phase 0.5: Attack Surface Ranking

**Run FIRST, before any hunters.** This drives everything downstream.

```bash
python3 .claude/scripts/status_writer.py --status-file $STATUS_FILE \
  --set-stage static running "ranking attack surface"
```

Spawn the ranking agent:
```
Agent(prompt="You are the attack-surface-ranker. Follow .claude/agents/attack-surface-ranker.md.
Run the scanner first:
/Users/gaurangbhatnagar/Documents/android-security-scanner/backend/venv/bin/python3 \
  /Users/gaurangbhatnagar/Documents/android-security-scanner/backend/scanner.py <apk> \
  -o outputs/.../static/scanner_results.json --work-dir outputs/.../static/work
Then rank the attack surface using scanner results + decompiled sources.
Output: outputs/.../targets.json
STATUS_FILE: <path>")
```

Wait for `targets.json`. Read it. This tells you:
- Which lanes have rank-5 targets (must be covered)
- Whether native code is reachable (determines Phase 3)
- App type (informs dynamic testing strategy)

## Phase 1: Parallel Static Hunters

Fan out into **lane-specific hunter agents running in parallel**. Each hunter gets:
- Its lane (what to look for)
- Its targets from `targets.json` (only rank ≥ 3 items in its lane)
- Excluded lanes (what other hunters are doing — note but don't pursue)
- Reference to relevant KB section
- Decompiled source path

**Spawn ALL hunters in a single message (parallel):**

```
# Launch all applicable hunters at once
Agent(prompt="You are the IPC hunter. Focus ONLY on intent handling, exported components, PendingIntents, broadcast receivers.
Your targets from targets.json: <ipc_targets>
Excluded lanes: webview, crypto, auth, storage, native, deeplinks, network
Decompiled sources: outputs/.../static/work/decompiled/sources/
Output findings to: outputs/.../findings/static/ipc.json
STATUS_FILE: <path>
If you spot a bug in another lane, write a one-line note for that hunter and move on.")

Agent(prompt="You are the WebView hunter. Focus ONLY on WebView security: JS enabled, addJavascriptInterface, file access, URL validation, shouldOverrideUrlLoading.
Your targets: <webview_targets>
...")

Agent(prompt="You are the ContentProvider hunter. Focus ONLY on content providers: SQL injection, path traversal, grantUriPermissions, openFile, URI validation.
Your targets: <provider_targets>
...")

Agent(prompt="You are the Crypto/Storage hunter. Focus ONLY on: hardcoded keys, weak algorithms, ECB mode, SharedPreferences plaintext, database encryption, external storage.
Your targets: <crypto_storage_targets>
...")

Agent(prompt="You are the Auth/Session/Logic hunter. Focus ONLY on: authentication flow, biometric implementation, session management, token storage, credential handling, AND business logic flaws (paywall bypass, client-side enforcement of server-side rules, race conditions in state machines, quota/entitlement issues).
App type from targets.json: <app_type> (use this to focus business logic checks — e.g., banking=payment flow, social=profile manipulation, enterprise=MDM bypass).
Your targets: <auth_targets>
...")

Agent(prompt="You are the Deep Link hunter. Focus ONLY on: deep link schemes, URL validation in handlers, parameter injection, scheme hijacking, Jetpack Navigation deepLinkIds.
Your targets: <deeplink_targets>
...")

Agent(prompt="You are the Native Bridge hunter. Follow .claude/agents/native-bridge-hunter.md.
Focus ONLY on the JNI boundary: tainted data flowing into native methods, return-value trust, RegisterNatives hidden bindings, library loading from writable paths, type mismatches at JNI interface.
Your targets: <native_targets>
...")

Agent(prompt="You are the secrets-hunter. Follow .claude/agents/secrets-hunter.md.
Run semgrep + trufflehog + nuclei on decompiled sources, dedup by fingerprint, AI-validate each finding, verify exploitable keys.
Decompiled sources: outputs/.../static/work/decompiled/sources/
APK path: <path>
Your targets: <all app classes>
...")
```

**Only spawn hunters for lanes that have rank ≥ 3 targets.** Check `lane_summary` in `targets.json`. If a lane has 0 targets, skip it.

After all hunters complete, collect findings from `findings/static/*.json`.

```bash
python3 .claude/scripts/status_writer.py --status-file $STATUS_FILE \
  --set-stage static completed "$(ls findings/static/*.json | wc -l) hunters completed"
```

## Phase 2: Dynamic Analysis (if device provided)

```bash
python3 .claude/scripts/status_writer.py --status-file $STATUS_FILE \
  --set-stage dynamic running "connecting to device"
```

Spawn `android-dynamic` agent with:
- All static findings (summarized)
- `targets.json` rank-5 components to test first
- Device identifier
- STATUS_FILE

## Phase 3: Native Fuzzing (CONDITIONAL)

**Trigger conditions** (expanded to include ranking agent's judgment):
1. Scanner reports native-related finding
2. Exported component directly calls JNI with attacker input
3. `targets.json` has rank ≥ 4 items in the `native` lane
4. User explicitly requests it

If no condition met: skip, note "Native fuzzing skipped — no native attack surface."

## Phase 3.5: Chain Finder (NEW)

**Run after all hunters + dynamic complete, before Validator.**

```bash
python3 .claude/scripts/status_writer.py --status-file $STATUS_FILE \
  --add-activity "Running chain-finder: composing findings into attack chains"
```

```
Agent(prompt="You are the chain-finder. Follow .claude/agents/chain-finder.md.
Read all findings from:
- outputs/.../findings/static/*.json
- outputs/.../dynamic/dynamic_findings.json
- outputs/.../targets.json
Look for multi-step attack chains where finding A's output feeds finding B's input.
Output: outputs/.../findings/chains.json
STATUS_FILE: <path>")
```

## Phase 4: Dedup → Exploit Validation

### Step 4a: Dedup

```
Agent(model="sonnet", prompt="You are the dedup-agent. Follow .claude/agents/dedup-agent.md.
Read all findings from outputs/.../findings/ and outputs/.../dynamic/.
Cluster by root cause, pick best representative.
Output: outputs/.../findings/deduped_findings.json")
```

### Step 4b: Exploit Validation

For each **unique** HIGH/CRITICAL finding from deduped set + all chains:

```
Agent(prompt="You are the exploit-validator. Follow .claude/agents/exploit-validator.md.
IMPORTANT: Create a complete PoC Android app for this finding.
Finding: <details from deduped_findings.json>
Device: <id>. Package: <pkg>. Output: outputs/.../exploits/
STATUS_FILE: <path>")
```

## Phase 5: Coverage → Reporting

### Step 5a: Coverage Verification

```
Agent(model="sonnet", prompt="You are the coverage-agent. Follow .claude/agents/coverage-agent.md.
Cross-reference targets.json against all findings and activity.
Flag rank-5 gaps for re-run.
Output: outputs/.../findings/coverage_report.json")
```

**If coverage agent flags critical gaps (rank-5 with no activity):** re-run the specific hunter for that lane with a **diversity prompt**:

```
Agent(prompt="You are the <lane> hunter, SECOND PASS.
Previous run found these bugs: <list from first run>
DO NOT rediscover those. Look for what was MISSED.
Perspective: Assume the obvious bugs are already found. You are a paranoid auditor —
every method is suspect, every input path might have a subtle flaw.
Focus ONLY on these rank-5 targets that had no activity: <gap_targets>
Budget: 100k tokens max. If nothing found, confirm 'audited with low confidence.'
...")
```

**Re-run budget:** Maximum ONE re-run per rank-5 gap. After that, mark as "audited with low confidence" in the report.

### Step 5b: Report Generation

Generate comprehensive report following `reference/report-template.md`. Include:
- All deduped findings with PoC references
- All chains as separate findings (CHAIN-001, etc.)
- Coverage table from coverage agent
- Attack chain diagrams

```bash
python3 .claude/scripts/status_writer.py --status-file $STATUS_FILE \
  --set-stage reporting completed "report generated"
```

## Reference Files
- [OWASP MASTG Checklist](reference/owasp-mastg-checklist.md)
- [Report Template](reference/report-template.md)
- [Finding Template](reference/finding_template.md)
- [Quick Wins](reference/quick_wins.md)
- [Pre-Engagement Checklist](reference/pre_engagement.md)

## Key Rules
- Never ask user how to proceed — autonomous decisions
- **Always run ranking before hunters** — targets.json drives everything
- **Fan out static hunters in parallel** — one message, multiple Agent calls
- **Chain-finder runs after hunters, before Validator** — catches composite bugs
- **Dedup before Validator** — don't build 14 PoC apps for one root cause
- **Coverage check before report** — re-run for rank-5 gaps
- Pass STATUS_FILE to every sub-agent
- PoC apps mandatory for intent/broadcast/provider/WebView findings
