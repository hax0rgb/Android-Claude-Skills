---
name: android-dynamic
description: Run dynamic security analysis on a connected Android device - component testing, storage analysis, Frida hooking, logcat monitoring
argument-hint: <apk_path> <device_id> [instructions...]
context: fork
agent: android-dynamic
model: opus
---

# Android Dynamic Analysis

Perform runtime security testing on a connected Android device.

## Arguments
- `$ARGUMENTS[0]` - Path to the target APK file (required)
- `$ARGUMENTS[1]` - Device identifier: IP:port (e.g., `192.168.1.16:5555`) OR USB serial (e.g., `2cf4fc4d`) (required)
- `$ARGUMENTS[2+]` - Additional instructions (optional): credentials, focus areas, package name, scope limits

**Device connection:** If device ID contains `:`, use `adb connect <id>`. Otherwise treat as USB serial: `adb -s <id>`. All subsequent ADB commands must use `adb -s <device_id>`.

## Prerequisites
- ADB installed and in PATH
- Device/emulator accessible at the provided IP
- For full testing: rooted device with Frida server running
- For network interception: mitmproxy (optional)

## What It Does

### Device Setup
- Connect via ADB, verify root access
- Install target APK, launch app

### Component Testing
- Test all exported activities, services, receivers, providers
- Attempt intent injection, SQL injection via content providers
- Test deep link handlers with malicious payloads

### Storage Analysis (Root)
- Inspect SharedPreferences, databases, files
- Check file permissions and encryption

### Runtime Hooking (Root + Frida)
- SSL pinning bypass
- Crypto function hooking (capture keys/plaintext)
- SharedPreferences monitoring
- File operation monitoring

### Logcat Analysis
- Monitor for leaked credentials, tokens, debug info

### Output
- `dynamic_findings.json` - Structured findings with evidence
- `dynamic_report.md` - Human-readable report
- `logcat.txt` - Captured app logs
- Evidence files (screenshots, captured data)

## Reference Files
- [ADB Commands](reference/adb-commands.md) - ADB command reference for testing
- [Frida Scripts](reference/frida-scripts.md) - Common Frida hooks and patterns
- [Frida Advanced](reference/frida-advanced.md) - Advanced Frida: memory scanning, DCL tracing, native hooks, class enumeration
- [Dynamic Checks](reference/dynamic-checks.md) - Runtime security check methodology
- [Device Setup](reference/device-setup.md) - Device/emulator configuration guide
- [Medusa Reference](reference/medusa-reference.md) - Medusa framework: 100+ modules for SSL bypass, intent monitoring, crypto, storage, WebView hooking
- [UI Navigation](reference/ui-navigation.md) - Observe-act loop for autonomous app navigation (ui.py + ADB input)
- [Biometric & KeyStore Bypass](reference/biometric-keystore-bypass.md) - 7 Frida scripts for biometric bypass, KeyStore audit, cipher tracing, PBKDF analysis
- [Android Security Evolution](../android-static/reference/android-security-evolution.md) - What attacks work on which Android versions, SSL/intent pentesting by API level
