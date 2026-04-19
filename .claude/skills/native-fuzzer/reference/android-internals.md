# Android Internals for Native Security Testing

Key Android architecture knowledge needed for native library analysis, fuzzing, and exploitation.

## Android Process Architecture

```
┌─────────────────────────────────────────────┐
│                Applications                  │
├─────────────────────────────────────────────┤
│            Java API Framework                │
│    (Activity Manager, Content Providers,     │
│     Package Manager, Window Manager)         │
├─────────────────────────────────────────────┤
│   Native C/C++ Libraries  │  Android Runtime │
│   (libc, libssl, libmedia │  (ART, core      │
│    OpenGL, SQLite, WebKit) │   libraries)     │
├─────────────────────────────────────────────┤
│       Hardware Abstraction Layer (HAL)        │
├─────────────────────────────────────────────┤
│              Linux Kernel                     │
│   (Binder IPC, Display, Camera, Bluetooth,   │
│    USB, Audio, Power Management)              │
└─────────────────────────────────────────────┘
```

### Zygote Process
- Parent process for ALL Android app processes
- Pre-loads system libraries (optimization via copy-on-write on fork)
- Each app process = fork of Zygote
- Injecting code into Zygote = access to ALL spawned app processes

### ART (Android Runtime)
- Replaced Dalvik VM
- Uses AOT (Ahead-Of-Time) + JIT (Just-In-Time) + profile-guided compilation
- DEX bytecode compiled to native code
- `.oat` files contain compiled native code from DEX

## Binder IPC

Android's primary inter-process communication mechanism.

```
App Process A                    App Process B
     │                                │
     │  ┌──────────────────────┐      │
     └──┤   Binder Driver      ├──────┘
        │  /dev/binder         │
        │  (kernel module)     │
        └──────────────────────┘
```

**Key concepts:**
- All system service calls go through Binder
- Transaction buffer limit: ~1MB shared across all active transactions
- Each transaction copies data to kernel space then to target process
- **Fuzzing implication:** Large payloads (>512 bytes) sent through JNI can exhaust the Binder buffer and destabilize the system

**Binder commands for analysis:**
```bash
# List registered Binder services
adb shell service list

# Check Binder stats
adb shell cat /sys/kernel/debug/binder/stats

# Trace Binder transactions
adb shell cat /sys/kernel/debug/binder/transactions
```

## SELinux on Android

Mandatory Access Control (MAC) - default-deny policy.

```bash
# Check SELinux status
adb shell getenforce
# Enforcing = active, Permissive = logging only

# Pull SELinux policy for analysis
adb pull /sys/fs/selinux/policy
# Analyze with sesearch
sesearch -A policy | grep untrusted_app

# Check app's SELinux context
adb shell ps -Z | grep <pkg>
# Output: u:r:untrusted_app:s0:c123,c256,c512,c768

# Set permissive (root required, temporary)
adb shell su -c setenforce 0
```

**App domain types:**
| Domain | Description |
|---|---|
| `untrusted_app` | Third-party apps |
| `platform_app` | System apps signed with platform key |
| `system_app` | Apps in /system/app |
| `priv_app` | Privileged system apps |
| `isolated_app` | Isolated process (WebView renderer) |

**Fuzzing implication:** SELinux restricts what files/devices an app can access. A crash that writes to a file may be blocked by SELinux even if the code is vulnerable. Check SELinux context before fuzzing.

## Native Library Loading

### How Android Loads .so Files

```
Java: System.loadLibrary("native-lib")
  │
  ├── Searches: /data/app/<pkg>/lib/<abi>/libnative-lib.so
  ├── Falls back: /system/lib64/libnative-lib.so
  │
  └── dlopen() → linker maps .so into process memory
       │
       ├── Runs .init_array constructors
       ├── Resolves symbols (PLT/GOT)
       └── JNI_OnLoad() called if present
```

### Key Paths
```bash
# App's native libraries
/data/app/<pkg>/lib/<abi>/

# System libraries
/system/lib64/     # 64-bit
/system/lib/       # 32-bit

# Vendor libraries
/vendor/lib64/
/vendor/lib/

# Runtime-extracted split APK libs
/data/app/<pkg>/split_*.apk
```

### Library Load Order (attack surface)
```bash
# Check what an app loads
adb shell cat /proc/$(adb shell pidof <pkg>)/maps | grep "\.so" | awk '{print $6}' | sort -u
```

## ARM Architecture Quick Reference

Android devices are primarily ARM (arm64-v8a for modern, armeabi-v7a for older).

### Registers (AArch64)
| Register | Purpose |
|---|---|
| x0-x7 | Function arguments + return value (x0) |
| x8 | Indirect result / syscall number |
| x9-x15 | Temporary / caller-saved |
| x16-x17 | Intra-procedure call scratch |
| x18 | Platform register (TLS on Android) |
| x19-x28 | Callee-saved |
| x29 (fp) | Frame pointer |
| x30 (lr) | Link register (return address) |
| sp | Stack pointer |
| pc | Program counter |

### Key for Crash Analysis
When analyzing tombstones/crash logs:
- **x0** = first argument / return value (often the pointer that caused SIGSEGV)
- **x30 (lr)** = where the function was called from
- **pc** = instruction that crashed
- **sp** = stack pointer (check for stack overflow if near bottom of mapping)

### QEMU for ARM Analysis
```bash
# Run ARM64 binary on x86 host
qemu-aarch64 ./binary

# With GDB debugging
qemu-aarch64 -g 5045 ./binary
gdb-multiarch ./binary
(gdb) target remote :5045
(gdb) break *0x400080
(gdb) continue
```

## Verified Boot & DM-Verity

**Verified Boot:** Cryptographic chain of trust from bootloader to system partition.
**DM-Verity:** Block-level integrity checking for read-only partitions.

**Implication for testing:** System partition modifications (like installing system CA certs) require:
1. Unlocked bootloader (disables verified boot)
2. OR Magisk systemless modifications
3. OR bind-mount overlays

## App Sandbox Model

Each app runs in its own sandbox:
```
App A (UID 10123)                    App B (UID 10456)
┌──────────────────┐                 ┌──────────────────┐
│ /data/data/a/    │  ← private      │ /data/data/b/    │
│ /data/user/0/a/  │                 │ /data/user/0/b/  │
│ Process A        │                 │ Process B        │
│ SELinux: u:r:    │                 │ SELinux: u:r:    │
│  untrusted_app   │                 │  untrusted_app   │
└──────────────────┘                 └──────────────────┘
         │                                    │
         └──────── Binder IPC ────────────────┘
         └──────── ContentProvider ────────────┘
         └──────── Intents ───────────────────┘
```

**Cross-sandbox access only via:**
- Exported components (Activities, Services, Receivers, Providers)
- ContentProvider with `grantUriPermissions`
- Binder IPC
- Shared files on external storage (pre-Android 11)
- Intents (explicit or implicit)

## Frida Internals on Android

```bash
# Frida injects frida-agent into target process via ptrace
# On rooted device: frida-server runs as root, attaches to any process
# On non-rooted: frida-gadget embedded in APK (via objection patchapk)

# Frida-server setup
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"

# Frida uses V8/QuickJS JavaScript engine inside target process
# Java.perform() bridges JS -> ART runtime via JNI
# Interceptor.attach() patches function prologue with trampoline

# Objection (Frida-based, no root needed)
objection patchapk --source target.apk
# Produces patched APK with embedded frida-gadget
adb install patched.apk
objection explore  # Auto-connects to gadget
```

## Python Frida Automation

```python
import frida
import time

# Connect to USB device
device = frida.get_usb_device()

# Spawn app (fresh process)
pid = device.spawn(["com.target.app"])
device.resume(pid)
time.sleep(1)

# Attach to running process
session = device.attach(pid)

# Load Frida script
with open("hook.js", "r") as f:
    script = session.create_script(f.read())

# Handle messages from script
def on_message(message, data):
    if message["type"] == "send":
        print(f"[*] {message['payload']}")
    elif message["type"] == "error":
        print(f"[!] {message['stack']}")

script.on("message", on_message)
script.load()

# Keep alive
input("[*] Press Enter to exit...")
```

## Tombstone Crash Analysis (Real Examples)

### Reading Tombstone Files
```bash
# List tombstones (root required)
adb shell su -c "ls -lt /data/tombstones/"

# Pull specific tombstone
adb shell su -c "cat /data/tombstones/tombstone_00"

# Key fields to look for:
# signal: SIGSEGV (11) = segfault, SIGABRT (6) = abort, SIGBUS (7) = bus error
# code: SEGV_MAPERR = unmapped memory, SEGV_ACCERR = permission denied
# fault addr: the address that caused the crash
# registers: x0-x30, sp, pc values at crash time
# backtrace: call stack showing where crash happened
```

### Example 1: Null Pointer Dereference (Not Exploitable)
```
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000000
x0  0x0000000000000000  ← null pointer
backtrace:
  #0  __strlen_aarch64 (libc.so)
  #1  Java_com_app_MainActivity_doThings+44 (libgetkey.so)
```
Root cause: JNI function returned null, passed to C++ string constructor → `strlen(nullptr)` → SIGSEGV. **DoS only.**

### Example 2: Controlled Crash (EXPLOITABLE)
```
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x4141414141414141
x0  0x4141414141414141  ← attacker-controlled data ("AAAA...")
backtrace:
  #0  _JNIEnv::NewStringUTF+16 (libart.so)
  #1  Java_com_app_MainActivity_nativeCrash2+56 (libbuggycrash.so)
```
Fault addr `0x4141414141414141` = buffer overflow with "A" pattern. **Attacker controls the pointer in x0.** This is exploitable for arbitrary code execution.

### Triage Quick Check
| Fault Address Pattern | Meaning | Severity |
|---|---|---|
| `0x0000000000000000` | Null pointer | Low (DoS) |
| `0x4141414141414141` | Buffer overflow (ASCII "AAAA") | Critical (RCE) |
| `0xdeadbeef` / similar | Sentinel/canary value | Medium |
| Near valid heap range | Heap corruption | High |
| Near stack range | Stack overflow | Critical |

## CVE-2023-26083: Mali GPU Kernel Pointer Leak

Leaks kernel addresses from userspace via Mali GPU driver timeline stream. Zero permissions needed (any app can open `/dev/mali0`).

### Attack Flow
```
1. open("/dev/mali0")
2. KBASE_IOCTL_VERSION_CHECK (handshake)
3. KBASE_IOCTL_SET_FLAGS
4. KBASE_IOCTL_TLSTREAM_ACQUIRE with BASE_TLSTREAM_ENABLE_CSF_TRACEPOINTS
5. KBASE_IOCTL_GET_CONTEXT_ID
6. KBASE_IOCTL_KCPU_QUEUE_CREATE
7. Read stream → find KBASE_TL_KBASE_NEW_KCPUQUEUE (msg_id=59)
8. Extract kcpu_queue kernel address from message at offset 24-12=12
```

### Key Code
```c
// Open Mali GPU device (no permissions needed!)
int fd = open("/dev/mali0", O_RDWR);

// Acquire timeline stream with CSF tracepoints enabled
int streamfd = ioctl(fd, KBASE_IOCTL_TLSTREAM_ACQUIRE,
    &(struct kbase_ioctl_tlstream_acquire){ .flags = BASE_TLSTREAM_ENABLE_CSF_TRACEPOINTS });

// Read stream messages to find leaked kernel address
char buf[0x1000];
ssize_t rb = read(streamfd, buf, sizeof(buf));
// Parse for msg_id == 59 (KBASE_TL_KBASE_NEW_KCPUQUEUE)
// Kernel address of kcpu_queue at offset 12 in the message
__u64 kcpu_queue_kaddr = *(__u64 *)(p + 12);
```

**Impact:** KASLR bypass - leaked kernel address enables calculation of kernel base for further exploitation.

## JNI Analysis Tools

### JNINinja.py (APK JNI Discovery)
```bash
# Comprehensive JNI analysis of an APK
python3 JNINinja.py target.apk

# Show only JNI bridge functions (exclude framework)
python3 JNINinja.py -j -s target.apk

# Filter by architecture
python3 JNINinja.py --target-arch arm64 target.apk

# Include checksec (binary protection analysis)
python3 JNINinja.py --show-checksec target.apk
```

### RegisterNatives Frida Hook
Apps that use `RegisterNatives` instead of standard `Java_*` naming hide their JNI bindings. Hook ART to reveal them:

```javascript
// Hook art::JNI::RegisterNatives to log all dynamic JNI registrations
var symbols = Module.enumerateSymbolsSync("libart.so");
for (var i = 0; i < symbols.length; i++) {
    if (symbols[i].name.indexOf("art") >= 0 &&
        symbols[i].name.indexOf("JNI") >= 0 &&
        symbols[i].name.indexOf("RegisterNatives") >= 0 &&
        symbols[i].name.indexOf("CheckJNI") < 0) {

        Interceptor.attach(symbols[i].address, {
            onEnter: function(args) {
                var env = args[0];
                var clazz = args[1];
                var methods = args[2];
                var nMethods = args[3].toInt32();

                var className = Java.vm.tryGetEnv().getClassName(clazz);
                console.log("[RegisterNatives] Class: " + className);

                for (var j = 0; j < nMethods; j++) {
                    var namePtr = methods.add(j * Process.pointerSize * 3).readPointer();
                    var sigPtr = methods.add(j * Process.pointerSize * 3 + Process.pointerSize).readPointer();
                    var fnPtr = methods.add(j * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();

                    var methodName = namePtr.readUtf8String();
                    var signature = sigPtr.readUtf8String();
                    var module = Process.findModuleByAddress(fnPtr);

                    console.log("  Method: " + methodName + " " + signature);
                    console.log("  -> " + module.name + "!0x" + fnPtr.sub(module.base).toString(16));
                }
            }
        });
    }
}
```

## AFL++ Frida Mode for Android

Build and run AFL++ with Frida persistent mode on Android device.

### afl.js Configuration (Persistent Mode)
```javascript
// Whitelist only target modules (exclude everything else)
const module_whitelist = ["harness", "libtarget.so"];
Afl.setInstrumentLibraries();  // Only instrument whitelisted libs

// Persistent hook on fuzz_one_input function
var fuzz_one_input = DebugSymbol.fromName("fuzz_one_input").address;
Afl.setPersistentAddress(fuzz_one_input);
Afl.setPersistentCount(10000);  // 10k iterations per fork
Afl.setInMemoryFuzzing();       // No file I/O, buffer in memory

// CModule for ARM64 persistent hook
const cm = new CModule(`
    extern void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
                                     uint32_t input_buf_len) {
        regs->x[0] = (uint64_t)input_buf;   // Set arg0 = fuzz buffer
        regs->x[1] = (uint64_t)input_buf_len; // Set arg1 = length
    }
`, { afl_persistent_hook: Afl.jsApiGetFunction("afl_persistent_hook") });

Afl.setPersistentHook(cm.afl_persistent_hook);
Afl.setMaxLen(4096);
Afl.done();
```

### Run on Android Device
```bash
# Push AFL++ binaries and harness to device
adb push afl-fuzz /data/local/tmp/
adb push harness /data/local/tmp/
adb push libtarget.so /data/local/tmp/

# Create corpus directory
adb shell mkdir -p /data/local/tmp/corpus
echo "seed" | adb shell tee /data/local/tmp/corpus/seed

# Run fuzzer
adb shell "cd /data/local/tmp && AFL_FRIDA_PERSISTENT_HOOK=afl.js \
    ./afl-fuzz -i corpus -o output -O -- ./harness"
```

## LD_PRELOAD Hooking on Android

Inject shared library to intercept libc calls.

### Hook Template
```c
// libhook.c - Compile with NDK
#include <stdio.h>
#include <dlfcn.h>

typedef int (*orig_open_t)(const char *pathname, int flags);

// Runs when library is loaded
void __attribute__((constructor)) on_load() {
    printf("[HOOK] Library loaded, PID: %d\n", getpid());
}

// Intercept open() syscall
int open(const char *pathname, int flags, ...) {
    printf("[HOOK] open(\"%s\")\n", pathname);
    orig_open_t orig = (orig_open_t)dlsym(RTLD_NEXT, "open");
    return orig(pathname, flags);
}
```

```bash
# Compile
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android30-clang \
    -shared -fPIC -o libhook.so libhook.c -llog

# Use on device (root)
adb push libhook.so /data/local/tmp/
adb shell su -c "LD_PRELOAD=/data/local/tmp/libhook.so /system/bin/app_process ..."
```

## Exploiting run-as (CVE-2024-0044)

`run-as` allows accessing debuggable app sandboxes without root:
```bash
# If app has android:debuggable="true"
adb shell run-as <package_name> ls files/
adb shell run-as <package_name> cat shared_prefs/auth.xml
adb shell run-as <package_name> cat databases/secret.db
```

CVE-2024-0044: Privilege escalation via `run-as` allowing access to non-debuggable app data on certain Android versions.

## Boot Sequence & Partitions

```bash
# View partition table
adb shell cat /proc/partitions

# View partition name mapping
adb shell ls -la /dev/block/platform/*/by-name/

# Key partitions:
# boot     - kernel + ramdisk
# system   - Android framework (read-only, dm-verity protected)
# vendor   - OEM-specific HAL + drivers (Treble)
# data     - User data (encrypted with FBE)
# recovery - Recovery mode OS
# vbmeta   - Verified boot metadata
```

## Filesystem Monitoring (FSMon)

```bash
# Install NowSecure's fsmon
adb push fsmon /data/local/tmp/fsmon
adb shell chmod +x /data/local/tmp/fsmon

# Monitor all file activity under /data
adb shell su -c "/data/local/tmp/fsmon /data"

# Monitor specific app's data directory
adb shell su -c "/data/local/tmp/fsmon /data/data/<pkg>"

# Useful for: finding where app stores secrets, what files it reads at startup,
# what databases it writes to, detecting file-based IPC
```
