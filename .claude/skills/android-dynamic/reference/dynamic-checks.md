# Dynamic Security Checks Methodology

## Pre-flight Checks

| Check | Command | Root? | Pass Criteria |
|---|---|---|---|
| Device connected | `adb devices` | No | Device listed |
| Root access | `adb shell su -c id` | Yes | uid=0 |
| Frida server | `adb shell su -c "ls /data/local/tmp/frida-server*"` | Yes | File exists |
| Frida running | `frida-ps -U` | Yes | Process list returned |
| App installed | `adb shell pm list packages \| grep <pkg>` | No | Package found |
| SELinux status | `adb shell getenforce` | No | Note enforcing/permissive |

## Check Categories

### 1. Component Exposure Testing

**Goal**: Verify that exported components can be abused by third-party apps.

For each exported component:
1. Launch/invoke it from ADB (simulates third-party app)
2. If it accepts extras/data, send malicious payloads
3. Observe: does it crash, leak data, perform privileged actions?

**Severity mapping:**
| Behavior | Severity |
|---|---|
| Access to user data without auth | Critical |
| Perform privileged action (delete, modify) | Critical |
| Information disclosure (non-sensitive) | Medium |
| DoS (crash) | Low-Medium |
| No impact | Info / False positive |

### 2. Data Storage Analysis (Root)

**Goal**: Find sensitive data stored insecurely on the device.

**Sequence:**
1. Launch app, create account / login
2. Use app features (make purchases, send messages, etc.)
3. Force stop the app
4. Inspect storage:

| Location | What to Look For | Severity if Found |
|---|---|---|
| `shared_prefs/*.xml` | Passwords, tokens, PII in plaintext | High-Critical |
| `databases/*.db` | Unencrypted sensitive data | High |
| `files/` | Config files with secrets | Medium-High |
| `cache/` | Cached responses with sensitive data | Medium |
| `/sdcard/Android/data/<pkg>/` | Any sensitive data (world-readable) | High |

### 3. Network Security

**Goal**: Verify secure network communication.

| Check | Method | Finding if Failed |
|---|---|---|
| Cleartext traffic | `dumpsys package` + Frida HTTP hook | Medium-High |
| SSL pinning | mitmproxy + Frida bypass | Medium (defense-in-depth) |
| Certificate validation | Frida hook TrustManager | Critical |
| Sensitive data in URLs | Logcat + Frida URL hook | Medium |

### 4. Logging Analysis

**Goal**: Find sensitive data leaked to system logs.

**Process:**
1. Clear logcat: `adb logcat -c`
2. Launch app and perform sensitive operations (login, payment, etc.)
3. Dump logs: `adb logcat -d`
4. Search for: tokens, passwords, PII, API keys, SQL queries, file paths

### 5. Runtime Hooking Checks (Root + Frida)

| Hook Target | What to Capture | Why |
|---|---|---|
| Cipher.doFinal | Encryption/decryption I/O | Find weak crypto, extract plaintext |
| SecretKeySpec.$init | Key material | Find hardcoded/weak keys |
| SharedPreferences.put* | Stored values | Find sensitive data storage |
| WebView.loadUrl | Loaded URLs | Find injected content |
| Intent.putExtra | Intent data | Find data leaks between components |
| Clipboard.set/get | Clipboard content | Find clipboard data leaks |

### 6. Authentication & Session

| Check | Method | Severity |
|---|---|---|
| Session token in SharedPrefs (plaintext) | Root + read prefs | High |
| Token doesn't expire | Observe token reuse over time | Medium |
| No re-auth for sensitive actions | Frida + observe flow | Medium-High |
| Biometric bypass | Frida hook BiometricPrompt | High |

### 7. Input Validation (via Components)

For each input point (activity extras, deep link params, provider queries):

| Payload Type | Test String | What to Observe |
|---|---|---|
| SQL injection | `' OR 1=1--` | Data returned, crash |
| Path traversal | `../../etc/passwd` | File contents returned |
| XSS (WebView) | `javascript:alert(1)` | JS execution |
| Command injection | `; id` | Command output |
| Long string | `A` * 10000 | Crash (buffer overflow) |
| Null | (empty/null extra) | Crash (null pointer) |
| Format string | `%s%s%s%s%s` | Crash or leak |

## Reporting Priority

1. **Critical**: Direct data theft, RCE, full auth bypass
2. **High**: Sensitive data exposure, privilege escalation, component abuse leading to data modification
3. **Medium**: Information disclosure, defense-in-depth failures, DoS
4. **Low**: Minor info leaks, theoretical issues
5. **Info**: Observations, hardening recommendations
