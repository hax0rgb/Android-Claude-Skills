# OWASP MASTG Android Security Checklist

139 tests across 8 MASVS categories. Each test mapped to our agent phases (static/dynamic/exploit).
Source: [OWASP MASTG](https://github.com/OWASP/mastg/tree/master/knowledge/android)

## How to Use This Checklist

The orchestrator should ensure all applicable tests are covered across agent phases:
- **S** = Static agent (code review, scanner)
- **D** = Dynamic agent (runtime, ADB, Frida/Medusa)
- **E** = Exploit validator (PoC app, verification)
- **N** = Native fuzzer (binary analysis)

---

## MASVS-STORAGE (Data Storage) - 12 beta + 8 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | Sensitive data in SharedPreferences (MASTG-TEST-0287) | S+D | `grep -r "putString.*token\|password\|key" + adb shell cat shared_prefs/*.xml` |
| 2 | Sensitive data in SQLite (MASTG-TEST-0304) | S+D | `grep -r "execSQL\|rawQuery" + adb shell sqlite3 databases/*.db .dump` |
| 3 | Sensitive data in DataStore (MASTG-TEST-0305) | S+D | Search for `DataStore` / `dataStore` usage, check proto/preferences files |
| 4 | Sensitive data in Room DB (MASTG-TEST-0306) | S+D | Search for `@Database` annotations, check Room DB files on device |
| 5 | Unencrypted data in app sandbox (MASTG-TEST-0207) | D | `adb shell su -c "grep -rl 'password\|token' /data/data/<pkg>/"` |
| 6 | Files on external storage (MASTG-TEST-0200/0201/0202) | S+D | Search for `getExternalFilesDir\|getExternalStorageDirectory` + check /sdcard/ |
| 7 | Sensitive data in logs (MASTG-TEST-0203/0231) | S+D | `grep -r "Log\.\(d\|i\|v\|e\).*token\|password" + pidcat <pkg>` |
| 8 | Backup includes sensitive data (MASTG-TEST-0216/0262) | S+D | Check `allowBackup` flag + `adb backup <pkg>` and inspect |
| 9 | Keyboard cache on sensitive fields (MASTG-TEST-0258) | S | Check `android:inputType="textNoSuggestions"` on password/sensitive fields |
| 10 | Clipboard data exposure | S+D | Search for `ClipboardManager` usage, Frida hook clipboard |
| 11 | Sensitive data in process memory (legacy MASTG-TEST-0011) | D | fridump / Medusa `memory_dump/dump_dex` |
| 12 | Third-party SDK data sharing (legacy MASTG-TEST-0004) | S | Check for analytics SDKs (Firebase, Amplitude, Mixpanel) sending PII |

---

## MASVS-CRYPTO (Cryptography) - 11 beta + 4 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | Insecure random (MASTG-TEST-0204/0205) | S | `grep -r "java\.util\.Random\|Math\.random" (should be SecureRandom)` |
| 2 | Insufficient key size (MASTG-TEST-0208) | S | Check key sizes: AES<128, RSA<2048, EC<224 |
| 3 | Hardcoded crypto keys (MASTG-TEST-0212) | S | `grep -r "SecretKeySpec.*getBytes\|new IvParameterSpec"` |
| 4 | Broken algorithms (MASTG-TEST-0221) | S+D | `grep -r "DES\|RC4\|Blowfish" + Medusa encryption/cipher_1` |
| 5 | Broken modes - ECB (MASTG-TEST-0232) | S+D | `grep -r "ECB\|NoPadding" + Medusa encryption/cipher_1` |
| 6 | Reused IVs (MASTG-TEST-0309/0310) | S+D | Check for static IV values, Frida hook IvParameterSpec |
| 7 | Key pair multipurpose (MASTG-TEST-0307/0308) | S+D | Same key used for both signing and encryption |
| 8 | Explicit security provider (MASTG-TEST-0312) | S | Check for hardcoded provider in `Cipher.getInstance("AES", "BC")` |
| 9 | Key generation params (legacy) | D | `tracer-keygenparameterspec.js` - audit StrongBox, auth, validity |
| 10 | PBKDF params (legacy) | D | `tracer-secretkeyfactory.js` - check iterations (>=600k), salt entropy |

---

## MASVS-AUTH (Authentication) - 5 beta + 2 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | Biometric fallback to non-biometric (MASTG-TEST-0326) | S | Check for `setAllowedAuthenticators` with `DEVICE_CREDENTIAL` fallback |
| 2 | Event-bound biometric auth (MASTG-TEST-0327) | S | Check for `CryptoObject` usage in `BiometricPrompt.authenticate()` |
| 3 | Biometric enrollment change detection (MASTG-TEST-0328) | S | Check `setInvalidatedByBiometricEnrollment(true)` |
| 4 | Auth without explicit user action (MASTG-TEST-0329) | S | Check for `setConfirmationRequired(true)` |
| 5 | Extended key validity (MASTG-TEST-0330) | S | Check `setUserAuthenticationValidityDurationSeconds` (should be -1 for per-use) |
| 6 | Biometric bypass attempt (legacy) | D+E | `fingerprint-bypass.js` / `fingerprint-bypass-crypto.js` |
| 7 | Device credential bypass (legacy) | D | `keyguard-credential-intent.js` |

---

## MASVS-NETWORK (Network Communication) - 18 beta + 5 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | Cleartext traffic allowed (MASTG-TEST-0235/0237) | S | Check `usesCleartextTraffic`, `network_security_config.xml` |
| 2 | Cleartext traffic observed (MASTG-TEST-0236/0238) | D | Medusa `http_communications/uri_logger` + proxy |
| 3 | Hardcoded HTTP URLs (MASTG-TEST-0233) | S | `grep -r "http://" (not https)` |
| 4 | Insecure TLS versions (MASTG-TEST-0217/0218) | S+D | Check for TLSv1.0/1.1, SSLv3 in code + network capture |
| 5 | Missing hostname verification (MASTG-TEST-0234/0283) | S | `grep -r "ALLOW_ALL_HOSTNAME_VERIFIER\|verify.*return true"` |
| 6 | Unsafe custom trust (MASTG-TEST-0282) | S | `grep -r "checkServerTrusted.*\{\s*\}\|X509TrustManager"` |
| 7 | SSL error handler in WebView (MASTG-TEST-0284) | S | `grep -r "onReceivedSslError.*proceed"` |
| 8 | User CAs trusted (MASTG-TEST-0285/0286) | S | Check `targetSdkVersion < 24` or `trust-anchors` in NSC |
| 9 | Missing cert pinning (MASTG-TEST-0242/0243/0244) | S+D | Check NSC for `<pin-set>`, test with proxy |
| 10 | Low-level socket APIs (MASTG-TEST-0239) | S | `grep -r "new Socket\|SSLSocket"` |
| 11 | GMS security provider (MASTG-TEST-0295) | S | Check for `ProviderInstaller.installIfNeeded` |
| 12 | SSL pinning bypass test (legacy) | D | Medusa `v3_multiple_unpinner` or `frida-ssl-bypass.js` |

---

## MASVS-PLATFORM (Platform Interaction) - 14 beta + 12 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | WebView content provider access (MASTG-TEST-0250/0251) | S+D | Check `setAllowContentAccess` + Medusa `webviews/hook_webviews` |
| 2 | WebView local file access (MASTG-TEST-0252/0253) | S+D | Check `setAllowFileAccess\|setAllowUniversalAccessFromFileURLs` |
| 3 | Native code via WebView (MASTG-TEST-0334) | S | `grep -r "addJavascriptInterface"` + check exposed methods |
| 4 | WebView cleanup (MASTG-TEST-0320) | D | Check if WebView clears cache/cookies on navigation away |
| 5 | Screenshot prevention (MASTG-TEST-0289/0291/0292/0293/0294) | S+D | Check `FLAG_SECURE`, `setRecentsScreenshotEnabled`, `SecureOn` |
| 6 | Sensitive data in notifications (MASTG-TEST-0315) | S+D | Medusa `services/notification_listener` |
| 7 | Keyboard cache on auth fields (MASTG-TEST-0316) | S | Check `inputType` on login fields |
| 8 | Deep link validation (legacy MASTG-TEST-0028) | S+E | Test all registered schemes, create PoC hijack app |
| 9 | IPC exposure (legacy MASTG-TEST-0029) | S+E | Test exported components, create PoC intent sender |
| 10 | PendingIntent vulnerability (legacy MASTG-TEST-0030) | S | Check for `FLAG_MUTABLE` + implicit base intent |
| 11 | JS execution in WebView (legacy MASTG-TEST-0031) | S+D | Check `setJavaScriptEnabled` + URL validation |
| 12 | WebView protocol handlers (legacy MASTG-TEST-0032) | S | Check `shouldOverrideUrlLoading` + scheme handling |
| 13 | Java objects via WebView (legacy MASTG-TEST-0033) | S+E | `@JavascriptInterface` methods - create PoC HTML |
| 14 | Overlay attacks (legacy MASTG-TEST-0035) | S+E | Check `filterTouchesWhenObscured` on sensitive activities |
| 15 | Implicit intent data leak (legacy MASTG-TEST-0026) | S+E | Check `startActivity` with implicit intents carrying sensitive data |
| 16 | App permissions (legacy MASTG-TEST-0024) | S | Review requested permissions vs functionality |

---

## MASVS-CODE (Code Quality) - 6 beta + 9 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | PIC not enabled (MASTG-TEST-0222) | N | `readelf -h <lib>.so \| grep Type` (DYN=PIE) |
| 2 | Stack canaries missing (MASTG-TEST-0223) | N | `readelf -s <lib>.so \| grep __stack_chk` |
| 3 | Platform version APIs (MASTG-TEST-0245) | S | Check `Build.VERSION.SDK_INT` usage for security decisions |
| 4 | Known vulnerable dependencies (MASTG-TEST-0272/0274) | S | Check `build.gradle` deps against CVE databases |
| 5 | Unsafe deserialization (MASTG-TEST-0337) | S | `grep -r "ObjectInputStream\|readObject\|Parcelable"` |
| 6 | Input validation / injection (legacy MASTG-TEST-0025) | S+D | SQL injection in providers, command injection, path traversal |
| 7 | URL loading in WebViews (legacy MASTG-TEST-0027) | S+E | Check URL validation before `loadUrl()` |
| 8 | Object persistence (legacy MASTG-TEST-0034) | S | Check serialization of sensitive objects |
| 9 | Third-party libraries (legacy MASTG-TEST-0042) | S | Audit dependencies for known vulns |
| 10 | Memory corruption (legacy MASTG-TEST-0043) | N | Buffer overflow, format string, use-after-free in native code |
| 11 | Security features enabled (legacy MASTG-TEST-0044) | N | PIE, stack canaries, NX, RELRO on native libs |

---

## MASVS-RESILIENCE (Reverse Engineering) - 12 beta + 11 legacy tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | APK signature version (MASTG-TEST-0224) | S | Check for v2/v3 signing (v1 only is weak) |
| 2 | Signature key size (MASTG-TEST-0225) | S | RSA >= 2048, EC >= 256 |
| 3 | Debuggable flag (MASTG-TEST-0226) | S | `android:debuggable="true"` in manifest |
| 4 | WebView debugging (MASTG-TEST-0227) | S | `WebView.setWebContentsDebuggingEnabled(true)` |
| 5 | Debugging symbols in native (MASTG-TEST-0288) | N | `readelf -S <lib>.so \| grep debug` |
| 6 | StrictMode enabled (MASTG-TEST-0263/0264/0265) | S+D | Check if StrictMode leaks info in production |
| 7 | Root detection (MASTG-TEST-0324/0325) | S+D | Check for root detection + test bypass with Frida |
| 8 | Secure screen lock detection (MASTG-TEST-0247/0249) | S+D | Check if app verifies device has secure lock |
| 9 | Anti-debugging (legacy) | D | Check for ptrace, debug port checks |
| 10 | File integrity (legacy) | S | Check for APK/DEX integrity verification |
| 11 | RE tool detection (legacy) | D | Check for Frida/Xposed/Magisk detection |
| 12 | Emulator detection (legacy) | D | Check for emulator detection + test bypass |
| 13 | Obfuscation (legacy) | S | Check ProGuard/R8 usage, string encryption |

---

## MASVS-PRIVACY (Privacy) - 7 beta tests

| # | Test | Agent | Check |
|---|------|-------|-------|
| 1 | PII in network traffic (MASTG-TEST-0206) | D | Proxy capture + search for email, phone, name, location |
| 2 | Dangerous permissions (MASTG-TEST-0254) | S | List all dangerous perms, assess necessity |
| 3 | Permission minimization (MASTG-TEST-0255) | S | Are all requested permissions actually used? |
| 4 | Missing permission rationale (MASTG-TEST-0256) | S | Check for `shouldShowRequestPermissionRationale` |
| 5 | Unused permission reset (MASTG-TEST-0257) | S | Check for stale permissions not revoked |
| 6 | Sensitive SDK APIs (MASTG-TEST-0318/0319) | S+D | Check for location, contacts, camera, microphone SDK usage |

---

## Quick Coverage Summary for Orchestrator

When spawning agents, ensure these categories are covered:

### Static Agent Must Check:
- [ ] STORAGE: SharedPrefs, SQLite, external storage, logs, backup config
- [ ] CRYPTO: Random, key size, hardcoded keys, algorithms, modes, IVs
- [ ] AUTH: Biometric implementation params
- [ ] NETWORK: Cleartext config, TLS version, hostname verify, trust manager, cert pinning, SSL error
- [ ] PLATFORM: WebView settings (file access, JS, JS interface), PendingIntent, deep links, implicit intents, overlay protection
- [ ] CODE: PIE/canary (defer to native), dependencies, deserialization, input validation
- [ ] RESILIENCE: Debuggable, signature, WebView debug, obfuscation
- [ ] PRIVACY: Permissions, SDK usage

### Dynamic Agent Must Check:
- [ ] STORAGE: Actual data in SharedPrefs/DBs/files, logs via pidcat, backup extraction
- [ ] CRYPTO: Runtime cipher/key usage via Medusa/Frida tracers
- [ ] AUTH: Biometric bypass attempt
- [ ] NETWORK: SSL pinning bypass, cleartext traffic capture, proxy interception
- [ ] PLATFORM: WebView runtime behavior, screenshot capture, notification content
- [ ] RESILIENCE: Root/emulator/Frida detection bypass, StrictMode leaks

### Exploit Validator Must Check:
- [ ] PLATFORM: PoC apps for intent redirection, deep link hijack, broadcast theft, provider access, WebView exploitation, overlay attack
- [ ] AUTH: Biometric bypass PoC
- [ ] STORAGE: External storage data theft PoC

### Native Fuzzer Must Check:
- [ ] CODE: PIE, stack canaries, NX, RELRO on all .so files
- [ ] CODE: Dangerous functions (strcpy, sprintf, system)
- [ ] RESILIENCE: Debug symbols stripped
