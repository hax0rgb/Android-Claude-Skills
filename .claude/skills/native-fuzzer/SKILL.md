---
name: native-fuzzer
description: Analyze and fuzz native libraries (.so) in Android APKs - extract JNI functions, check binary protections, and fuzz via Frida
argument-hint: <apk_path> [device] [instructions...]
context: fork
agent: native-fuzzer
model: opus
---

# Native Library Fuzzer

Analyze and fuzz native libraries (.so files) in Android APKs.

## Arguments
- `$ARGUMENTS[0]` - Path to the target APK (required)
- `$ARGUMENTS[1]` - Device identifier: IP:port or USB serial (optional, needed for on-device fuzzing)
- `$ARGUMENTS[2+]` - Additional instructions (optional): focus areas, scope limits, etc.

**Device connection:** If device ID contains `:`, use `adb connect <id>`. Otherwise use `adb -s <id>`.

## What It Does

### Binary Analysis (Offline)
- Extract .so files from APK
- Identify JNI function exports
- Check binary protections (stack canary, NX, PIE, RELRO)
- Detect dangerous C function usage (strcpy, sprintf, system, etc.)
- Extract and analyze embedded strings

### Fuzz Testing (Requires Device)
- Generate Frida scripts to hook JNI functions
- Send malformed inputs (null, long strings, path traversal, format strings)
- Monitor for crashes via logcat and tombstones

### Output
- `native_analysis.json` - Library analysis and fuzz results
- Crash logs and tombstones as evidence

## Reference Files
- [Native Analysis](reference/native-analysis.md) - JNI analysis and fuzzing methodology
