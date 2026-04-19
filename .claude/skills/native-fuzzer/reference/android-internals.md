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
