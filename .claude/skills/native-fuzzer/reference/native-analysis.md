# Native Library Analysis & Fuzzing Methodology

## Phase 1: Extraction

```bash
# Extract libs from APK
unzip -o <apk> "lib/*" -d <output>/

# List architectures
ls <output>/lib/
# Common: armeabi-v7a, arm64-v8a, x86, x86_64

# List all native libraries
find <output>/lib/ -name "*.so"
```

## Phase 2: Binary Analysis

### JNI Entry Points
JNI functions follow the naming convention: `Java_<package>_<class>_<method>`

```bash
# Dynamic symbols (exported functions)
nm -D <lib>.so | grep "Java_"

# If stripped, use readelf
readelf -Ws <lib>.so | grep "Java_"

# All exported functions
nm -D <lib>.so | grep " T "
readelf -Ws <lib>.so | grep -E "FUNC.*GLOBAL"
```

### Binary Protections

| Protection | Check Command | Secure Value |
|---|---|---|
| Stack Canary | `readelf -s <lib>.so \| grep __stack_chk` | Present |
| NX (No-Execute) | `readelf -l <lib>.so \| grep GNU_STACK` | `RW` (not `RWE`) |
| PIE | `readelf -h <lib>.so \| grep Type` | `DYN` (not `EXEC`) |
| RELRO | `readelf -l <lib>.so \| grep GNU_RELRO` | Present |
| Full RELRO | `readelf -d <lib>.so \| grep BIND_NOW` | Present (with RELRO) |
| RPATH | `readelf -d <lib>.so \| grep RPATH` | Absent |

### Dangerous Function Detection

```bash
# Memory unsafe functions
nm -D <lib>.so | grep -E "\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf)\b"

# Format string risks
nm -D <lib>.so | grep -E "\b(printf|fprintf|snprintf|syslog)\b"

# Command execution
nm -D <lib>.so | grep -E "\b(system|popen|exec|execve|execvp)\b"

# Dynamic loading (potential for injection)
nm -D <lib>.so | grep -E "\b(dlopen|dlsym)\b"

# Memory allocation (heap issues)
nm -D <lib>.so | grep -E "\b(malloc|calloc|realloc|free)\b"
```

### String Analysis

```bash
# Interesting strings
strings <lib>.so | grep -iE "http|https|api|key|secret|password|token|encrypt|decrypt"

# Hardcoded paths
strings <lib>.so | grep -E "^/"

# Format strings (format string vuln indicators)
strings <lib>.so | grep -E "%[0-9]*[sdxnp]"

# Error messages (info disclosure)
strings <lib>.so | grep -iE "error|fail|invalid|exception"

# SQL queries
strings <lib>.so | grep -iE "select|insert|update|delete|from|where"
```

## Phase 3: Vulnerability Assessment

### Risk Matrix

| Finding | Missing Protection | Risk |
|---|---|---|
| strcpy + no canary | Stack buffer overflow, exploitable | Critical |
| sprintf + user input | Format string / buffer overflow | High |
| system() / popen() | Command injection if input controlled | Critical |
| No PIE + known vuln | Easier exploitation (fixed addresses) | Medium (amplifier) |
| No NX | Shellcode execution possible | Medium (amplifier) |
| dlopen with user path | Library injection | High |
| Hardcoded crypto keys | Key extraction from binary | High |

### JNI Attack Surface Assessment

For each JNI function:
1. **Parameter types**: String inputs are highest risk (buffer overflows)
2. **Caller context**: Is it called from exported components? (reachable by attacker)
3. **Data flow**: Does Java-side sanitize input before passing to native?

## Phase 4: Fuzz Testing

### Frida-based JNI Fuzzing

Template for fuzzing a JNI function that takes a String parameter:

```javascript
Java.perform(function() {
    var targetClass = Java.use('<fully.qualified.ClassName>');

    // Save original implementation
    var original = targetClass.<nativeMethod>;

    // SAFE fuzz cases - max 512 bytes, no format string writes, gradual escalation
    targetClass.<nativeMethod>.implementation = function(input) {
        var fuzzCases = [
            // Tier 1: Edge cases (always safe)
            null,
            "",
            "A",

            // Tier 2: Gradual size escalation (max 512 bytes)
            "A".repeat(64),
            "A".repeat(128),
            "A".repeat(256),
            "A".repeat(512),           // MAX SAFE SIZE - do not exceed

            // Tier 3: Logic payloads (no memory corruption risk)
            "../../../../etc/passwd",
            "\x00\x01\x02\x03",       // Short binary
            "'; DROP TABLE test;--",
            String.fromCharCode(0) + "AAAA",

            // BANNED - DO NOT USE (can reboot device):
            // "A".repeat(10000+)      -- kernel buffer overflow
            // "%n".repeat(N)          -- writes to memory via printf
            // "%x".repeat(100)        -- can crash printf internals
            // "%s".repeat(50)         -- dereferences random pointers
        ];

        for (var i = 0; i < fuzzCases.length; i++) {
            try {
                console.log("[FUZZ " + i + "] Input length: " + (fuzzCases[i] ? fuzzCases[i].length : "null"));
                var result = original.call(this, fuzzCases[i]);
                console.log("[FUZZ " + i + "] OK - Result: " + result);
            } catch(e) {
                console.log("[FUZZ " + i + "] EXCEPTION: " + e.message);
                // Stop on native crash signals
                if (e.message && (e.message.indexOf("abort") >= 0 || e.message.indexOf("signal") >= 0)) {
                    console.log("[FUZZ] STOPPING - crash detected");
                    break;
                }
            }
            // Delay between cases to prevent rapid-fire crashes
            Thread.sleep(0.5);
        }

        return original.call(this, input);
    };
});
```

### SAFETY RULES FOR FUZZING

**These prevent device reboots:**
1. **Max payload size: 512 bytes.** Larger buffers can overflow kernel-side allocations.
2. **No format string writes** (`%n`, `%s` repeated). These dereference/write to arbitrary memory.
3. **500ms delay between cases.** Rapid crashes overwhelm the process/kernel.
4. **Stop on first crash.** Collect the tombstone, report the finding, move on.
5. **Never fuzz system processes.** Check UID first - if system (1000) or root (0), skip.
6. **Never fuzz in a loop.** One pass through the test cases is enough.

### Pre-Fuzz Check
```bash
# Verify target app is NOT a system process
adb shell ps | grep <pkg>
# UID must be u0_aXXX (app user), NOT system or root

# Record tombstones before fuzzing
adb shell su -c "ls -lt /data/tombstones/" > tombstones_before.txt
```

### Crash Monitoring (start BEFORE fuzzing)
```bash
adb logcat -b crash -v time &
# If SIGABRT or SIGSEGV appears: stop fuzzing, collect evidence

# After fuzzing, diff tombstones
adb shell su -c "ls -lt /data/tombstones/" > tombstones_after.txt
diff tombstones_before.txt tombstones_after.txt

# Parse crash info
# Key fields: signal (SIGSEGV=segfault, SIGABRT=abort), fault addr, backtrace
```

### Integer Overflow Fuzzing (for numeric JNI params)

```javascript
Java.perform(function() {
    var targetClass = Java.use('<ClassName>');
    targetClass.<nativeMethod>.implementation = function(num) {
        var intFuzz = [
            0, -1, 1,
            2147483647,     // INT_MAX
            -2147483648,    // INT_MIN
            2147483648,     // INT_MAX + 1
            0x7FFFFFFF,
            0xFFFFFFFF,
            0x80000000,
        ];
        for (var i = 0; i < intFuzz.length; i++) {
            try {
                console.log("[FUZZ] int=" + intFuzz[i]);
                original.call(this, intFuzz[i]);
                console.log("[FUZZ] OK");
            } catch(e) {
                console.log("[FUZZ] CRASH: " + e);
            }
        }
        return original.call(this, num);
    };
});
```

## Reporting

For each native finding:
- Library name and architecture
- Function name (JNI or internal)
- Vulnerability type (buffer overflow, format string, command injection, etc.)
- Binary protection status (missing protections amplify severity)
- Proof: crash log, tombstone, or observed behavior
- Exploitability assessment: is the function reachable from an attacker-controlled input?
