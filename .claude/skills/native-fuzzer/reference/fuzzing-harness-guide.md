# Fuzzing Harness Construction Guide

How to build fuzzing harnesses for Android native libraries. Covers LibFuzzer, sanitizers, protobuf-aware fuzzing, and real-world CVE examples.

Source: Android Userland Fuzzing training material.

## Fuzzing Types

| Type | Description | When to Use |
|---|---|---|
| Coverage-guided | Uses code coverage feedback to evolve inputs | Default choice for native libs |
| Structure-aware | Understands input format (protobuf, JSON, XML) | Structured input formats |
| Dumb/random | Purely random bytes | Quick first pass, unknown formats |
| Black-box | No source access, random inputs | Closed-source .so files |

## LibFuzzer Harness Template

The harness is the bridge between the fuzzer engine and the target function.

### Basic Harness
```c
// harness.c
#include <stdint.h>
#include <stddef.h>

// Include the target library header
#include "libtarget.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Don't process empty or too-large inputs
    if (Size == 0 || Size > 4096) return 0;
    
    // Call the target function with fuzz data
    target_process_input((const char *)Data, Size);
    
    return 0;
}
```

### Compilation
```bash
# Compile target library with instrumentation
clang -v -g -O1 -fsanitize=fuzzer,address -fPIC -c libtarget.c -o libtarget.o

# Build harness linked with fuzzer runtime + sanitizers
clang -v -g -O1 -fsanitize=fuzzer,address harness.c -o harness libtarget.o -lm

# Run the fuzzer
./harness -max_len=4096 corpus/

# With dictionary (improves coverage for text formats)
./harness -dict=xml.dict -max_len=10000 corpus/
```

### Cross-Compile for ARM (Android target libs)
```bash
# For aarch64 Android libraries
aarch64-linux-gnu-gcc -g -O1 -fsanitize=fuzzer,address -fPIC -c libtarget.c
aarch64-linux-gnu-gcc -g -O1 -fsanitize=fuzzer,address harness.c -o harness libtarget.o

# Execute via QEMU
qemu-aarch64 ./harness corpus/

# Debug crashes with GDB
qemu-aarch64 -g 5045 ./harness crash-input
gdb-multiarch ./harness
# (gdb) target remote :5045
```

## Sanitizers

Always compile with at least AddressSanitizer. Stack the ones relevant to your target.

| Sanitizer | Flag | Detects |
|---|---|---|
| AddressSanitizer (ASan) | `-fsanitize=address` | Buffer overflow, use-after-free, double-free, memory leaks |
| UndefinedBehaviorSanitizer (UBSan) | `-fsanitize=undefined` | Integer overflow, division by zero, null pointer deref |
| MemorySanitizer (MSan) | `-fsanitize=memory` | Uninitialized memory reads |
| ThreadSanitizer (TSan) | `-fsanitize=thread` | Data races, deadlocks |

**Recommended combo:**
```bash
clang -fsanitize=fuzzer,address,undefined -O1 -g harness.c -o harness libtarget.o
```

## Protobuf Structure-Aware Fuzzing

For libraries that parse structured input (JSON, XML, protobuf, etc.), use libprotobuf-mutator for intelligent mutations.

### Step 1: Define Input Structure
```protobuf
// animation.proto
syntax = "proto2";

message LottieAnimation {
    optional string name = 1;
    optional int32 width = 2;
    optional int32 height = 3;
    optional int32 frame_rate = 4;
    repeated Layer layers = 5;
}

message Layer {
    optional string type = 1;
    optional int32 start_frame = 2;
    optional int32 end_frame = 3;
    optional bytes data = 4;
}
```

### Step 2: Build Converter + Harness
```cpp
// harness.cpp
#include "animation.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "libtarget.h"

// Convert protobuf to the format the library expects (e.g., JSON)
std::string ProtoToJson(const LottieAnimation& proto) {
    // ... conversion logic
}

DEFINE_PROTO_FUZZER(const LottieAnimation& proto) {
    std::string json = ProtoToJson(proto);
    target_parse_animation(json.c_str(), json.size());
}
```

### Step 3: Compile
```bash
# Generate protobuf C++ code
protoc --cpp_out=. animation.proto

# Compile protobuf object
clang++ animation.pb.cc -g -c -I /usr/local/include/libprotobuf-mutator -fsanitize=fuzzer

# Build harness
clang++ harness.cpp -o fuzz animation.pb.o \
    -lprotobuf -lprotobuf-mutator -lprotobuf-mutator-libfuzzer \
    -fsanitize=fuzzer,address

# Run
./fuzz corpus/
```

## Real-World CVE Examples

### CVE-2015-7498: libxml2 Heap Buffer Overflow

**Target function:** `xmlReadMemory()` - parses XML from memory buffer.

**Harness:**
```c
#include <libxml/parser.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    xmlDocPtr doc = xmlReadMemory((const char *)Data, Size, "noname.xml", NULL, 0);
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    return 0;
}
```

**Compile:**
```bash
clang -g -O1 -fsanitize=fuzzer-no-link,address,undefined -c harness.c -I/usr/include/libxml2
clang -g -O1 -fsanitize=fuzzer,address,undefined harness.o -o fuzzer -lxml2

# Run with XML dictionary for better coverage
./fuzzer -dict=xml.dict -max_len=10000 corpus/
```

### RLottie (Telegram Animation Library)

**Target:** `rlottie::Animation::loadFromData()` - parses Lottie JSON animations.

**Harness approach:** Protobuf -> JSON -> rlottie render. Tests both parsing and rendering.

```cpp
DEFINE_PROTO_FUZZER(const LottieAnimation& proto) {
    std::string json = ProtoToJson(proto);
    auto animation = rlottie::Animation::loadFromData(json, "", "", false);
    if (animation) {
        size_t width = 100, height = 100;
        auto buffer = std::unique_ptr<uint32_t[]>(new uint32_t[width * height]);
        auto surface = rlottie::Surface(buffer.get(), width, height, width * 4);
        animation->renderSync(0, surface);  // Render first frame
    }
}
```

### WhatsApp GIF Drawable (Double-Free)

**Target:** GIF rendering library - `DGifSlurp()`.
**Vulnerability:** Double-free on 0-sized GIF images.
**Key:** Compile with ARM NEON support: `-mfpu=neon`

## Finding Functions to Fuzz

### From Decompiled APK
```bash
# Find JNI entry points
nm -D libtarget.so | grep "Java_"

# Find functions that parse external data
strings libtarget.so | grep -iE "parse|decode|read|load|deserialize|process|handle"

# Find functions that take size/length parameters (overflow targets)
readelf -Ws libtarget.so | grep -E "FUNC.*GLOBAL" | grep -iE "parse|read|process"
```

### Using Ghidra
1. Open .so in Ghidra, auto-analyze
2. Go to **Symbol Tree > Exports** to find public functions
3. Look for functions that:
   - Take `char*` or `void*` + `size_t` parameters (fuzzing targets)
   - Call `malloc`/`memcpy`/`strcpy` (potential overflow)
   - Process file formats (XML, JSON, image, media)
4. **Function Graph** shows control flow - look for missing bounds checks
5. **Cross-references** show which JNI functions call internal parsers

### Using Frida (Runtime Discovery)
```bash
# Trace all calls to the target library
frida-trace -U -f com.app.name -i "Java_*"

# List all exports at runtime
frida -U -f com.app.name -e '
    var mod = Process.getModuleByName("libtarget.so");
    mod.enumerateExports().forEach(function(exp) {
        if (exp.type === "function") console.log(exp.name);
    });
'
```

## Crash Analysis

### ASAN Output Interpretation
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 1 at 0x602000000014 thread T0
    #0 0x5555555551a3 in target_parse harness.c:15
    #1 0x555555555120 in LLVMFuzzerTestOneInput harness.c:8
```

Key fields:
- **Error type:** `heap-buffer-overflow`, `stack-buffer-overflow`, `use-after-free`, `double-free`
- **Access type:** `READ` or `WRITE`
- **Size:** How many bytes were accessed out of bounds
- **Stack trace:** Where the crash happened
- **Shadow memory:** Shows allocated vs accessed regions

### Reproduce Crash
```bash
# Run with the crashing input
./harness crash-input-file

# Debug with GDB
gdb ./harness
(gdb) run crash-input-file
(gdb) bt       # backtrace
(gdb) info reg # registers
```

### Triage Severity

| Error Type | Severity | Exploitable? |
|---|---|---|
| Heap buffer overflow (write) | Critical | Yes - arbitrary write |
| Heap buffer overflow (read) | High | Info leak, may chain |
| Stack buffer overflow | Critical | Yes - ROP/shellcode |
| Use-after-free | Critical | Yes - function pointer hijack |
| Double-free | High | Yes - heap manipulation |
| Null pointer dereference | Low | DoS only (usually) |
| Integer overflow | Medium | Depends on usage |
| Uninitialized read | Medium | Info leak |

## AFL++ Frida Mode for Android (On-Device JNI Fuzzing)

Complete pipeline for fuzzing JNI functions on-device using AFL++ with Frida persistent mode.

### Step 1: Build AFL++ for Android

Use the CMakeLists.txt from the training material to cross-compile AFL++ + frida-trace for ARM64:

```bash
# Download AFL++
wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v4.32c.zip
unzip v4.32c.zip && cd AFLplusplus-4.32c

# Copy custom CMakeLists.txt (builds afl-fuzz + afl-frida-trace.so)
# See: .claude/skills/native-fuzzer/reference/ for full CMakeLists.txt

# Build with NDK
mkdir build && cd build
cmake .. \
  -DANDROID_PLATFORM=31 \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_HOME/ndk/27.0.11902837/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a
make

# Verify: file afl-fuzz → ELF 64-bit ARM aarch64
```

### Step 2: Build JENV (JNI Environment for Standalone Fuzzing)

JENV solves the core fuzzing problem: JNI functions need a valid `JNIEnv*` which normally only exists inside Android Runtime. JENV creates a minimal JVM on-device using `libandroid_runtime.so`.

```c
// jenv creates: Real JVM + Real JNIEnv + No full Android boot
// Source: https://github.com/quarkslab/android-fuzzing/blob/main/jenv/jenv.c

// Key API:
JavaCTX ctx;
init_java_env(&ctx, NULL, 0);  // Creates JVM + JNIEnv
// ctx.env is now a valid JNIEnv* for JNI calls
// ctx.vm is a valid JavaVM*
```

Compile JENV as shared library:
```bash
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android35-clang \
  -shared -fPIC -o libjenv.so jenv.c -llog -ldl
```

### Step 3: Write JNI Fuzzing Harness

**For simple String input:**
```c
#include <jni.h>
#include "jenv.h"
#define BUFFER_SIZE 256

static JavaCTX ctx;

// Declare the target JNI function
extern jstring Java_com_target_MainActivity_processInput(JNIEnv*, jobject, jstring);

void fuzz_one_input(const uint8_t *buffer, size_t length) {
    char tmp[BUFFER_SIZE + 1];
    if (length > BUFFER_SIZE) length = BUFFER_SIZE;
    memcpy(tmp, buffer, length);
    tmp[length] = '\0';

    jstring jInput = (*ctx.env)->NewStringUTF(ctx.env, tmp);
    Java_com_target_MainActivity_processInput(ctx.env, NULL, jInput);
    (*ctx.env)->DeleteLocalRef(ctx.env, jInput);
}

int main() {
    init_java_env(&ctx, NULL, 0);
    uint8_t buffer[BUFFER_SIZE];
    size_t len = fread(buffer, 1, BUFFER_SIZE, stdin);
    fuzz_one_input(buffer, len);
    return 0;
}
```

**For custom Java object input (e.g., VulnerableDataProcessor):**
```c
void fuzz_one_input(const uint8_t *buffer, size_t length) {
    // Create byte array from fuzz data
    jbyteArray jBuffer = (*ctx.env)->NewByteArray(ctx.env, length);
    (*ctx.env)->SetByteArrayRegion(ctx.env, jBuffer, 0, length, (const jbyte*)buffer);

    // Find custom class and create instance
    jclass procClass = (*ctx.env)->FindClass(ctx.env, "com/target/VulnerableDataProcessor");
    jmethodID ctor = (*ctx.env)->GetMethodID(ctx.env, procClass, "<init>", "([B)V");
    jobject processor = (*ctx.env)->NewObject(ctx.env, procClass, ctor, jBuffer);

    // Call target function with custom object
    jstring result = Java_com_target_MainActivity_testJNI(ctx.env, NULL, processor);

    // Cleanup
    if (result) (*ctx.env)->DeleteLocalRef(ctx.env, result);
    (*ctx.env)->DeleteLocalRef(ctx.env, processor);
    (*ctx.env)->DeleteLocalRef(ctx.env, jBuffer);
}

int main() {
    // Pass APK or DEX as classpath so FindClass works
    char *opts[] = {"-Djava.class.path=/data/local/tmp/classes.dex"};
    init_java_env(&ctx, opts, 1);
    // ... read stdin and call fuzz_one_input
}
```

**DEX shim trick:** Instead of passing the full APK (slow, may have Thread.sleep), compile a minimal DEX with just the custom class:
```bash
javac -release 8 VulnerableDataProcessor.java  # Remove Thread.sleep first
d8 VulnerableDataProcessor.class               # Produces classes.dex
adb push classes.dex /data/local/tmp/
```

### Step 4: Cross-Compile Harness

```bash
aarch64-linux-android35-clang \
  harness.c libtarget.so libjenv.so -o harness
```

### Step 5: Deploy to Device

```bash
adb push harness afl-fuzz afl-frida-trace.so /data/local/tmp/
adb push libtarget.so libjenv.so libc++_shared.so /data/local/tmp/
adb push afl.js /data/local/tmp/

# Verify harness works
echo -n "test" | adb shell "cd /data/local/tmp && LD_LIBRARY_PATH=. ./harness"
```

### Step 6: Configure AFL Frida Agent (afl.js)

```javascript
// Only instrument target modules
const MODULE_WHITELIST = ["harness", "libtarget.so"];
Afl.setInstrumentLibraries();

// Persistent mode on fuzz_one_input
var fuzz_addr = DebugSymbol.fromName("fuzz_one_input").address;
Afl.setPersistentAddress(fuzz_addr);
Afl.setPersistentCount(10000);  // 10k iterations per fork

// ARM64 persistent hook - copies AFL buffer to registers
const cm = new CModule(`
extern void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
                                 uint32_t input_buf_len) {
    uint32_t length = (input_buf_len > 256) ? 256 : input_buf_len;
    memcpy((void *)regs->x[0], input_buf, length);
    regs->x[1] = (uint64_t)length;
}
`, { afl_persistent_hook: Afl.jsApiGetFunction("afl_persistent_hook") });

Afl.setPersistentHook(cm.afl_persistent_hook);
Afl.setInMemoryFuzzing();
Afl.setMaxLen(256);
Afl.done();
```

**Optional: Bypass Thread.sleep for speed:**
```javascript
// Add to afl.js after Afl.done()
Java.perform(function() {
    var Thread = Java.use("java.lang.Thread");
    Thread.sleep.overload("long").implementation = function(ms) {
        // Skip sleep during fuzzing
    };
});
```

### Step 7: Run AFL++

```bash
adb shell
cd /data/local/tmp
su
mkdir in out
echo "AAA" > in/seed.txt
export LD_LIBRARY_PATH=/data/local/tmp
./afl-fuzz -O -i in -o out -- ./harness
# -O = Frida mode (FRIDA_MODE)
# AFL_DEBUG=1 for verbose output
```

### Step 8: Validate Crashes

```bash
# Check crash files
ls out/default/crashes/
xxd out/default/crashes/id:000000*  # View raw payload

# Replay crash
LD_LIBRARY_PATH=/data/local/tmp ./harness < out/default/crashes/id:000000*
# Expected: Aborted / SIGSEGV

# Check tombstone
cat /data/tombstones/tombstone_00

# Root cause in Ghidra: find strcpy/memcpy without bounds check
```

### Crash Validation Checklist
| Step | Action | Evidence |
|------|--------|---------|
| 1 | Run AFL++ | Crash files in `out/crashes/` |
| 2 | Inspect payload | `xxd crash_file` - look for patterns |
| 3 | Replay | Confirm crash reproduces |
| 4 | Tombstone | Signal type, fault addr, backtrace |
| 5 | Ghidra | Root cause (strcpy, memcpy, etc.) |
| 6 | Report | Vulnerability type, exploitability, PoC |

## JNI Reversing Quick Reference

### Discovery Order
```
1. nm --dynamic --demangle lib.so | grep Java_     # Static bindings
2. If no Java_ symbols → search for JNI_OnLoad     # Dynamic bindings
3. Inside JNI_OnLoad → find RegisterNatives call
4. Parse JNINativeMethod array: {name, sig, fnPtr}
5. Follow fnPtr to actual implementation
```

### Frida RegisterNatives Hook
```bash
frida -U -l printregisternative.js -f com.target.app
# Output: method name, signature, library, offset
```

### JNINinja
```bash
python3 JNINinja.py target.apk -j -s --show-checksec
# Shows: JNI methods, signatures, arg types, binary protections
```

### Ghidra Setup for JNI
1. Import `jni_all.gdt` (Window → Data Type Manager → Open File Archive)
2. Set Image Base to 0x0 (for Frida offset alignment)
3. Retype params: `undefined8` → `JNIEnv*`, `jobject`, `jstring`
4. Rename: param_1 → env, param_2 → obj, param_3 → input

## Integration with Our Native Fuzzer Agent

The native-fuzzer agent should:

1. **Phase 1 (Offline):** Extract .so files, identify JNI exports via `nm`/JNINinja/Ghidra
2. **Phase 2 (Offline):** If possible, build harness + compile with sanitizers for host-side fuzzing
3. **Phase 3 (On-device - SAFE):** Use Frida-based safe fuzzing (max 512 bytes) for quick validation
4. **Phase 4 (On-device - DEEP):** If AFL++ is available, use AFL++ Frida mode with JENV for coverage-guided fuzzing
5. **Phase 5 (Analysis):** Validate crashes via replay + tombstone + Ghidra root cause

**When to use which:**
| Method | When | Speed | Depth |
|---|---|---|---|
| Frida hooks (safe) | Quick validation, no build tools | Fast setup | Shallow |
| AFL++ Frida mode | Deep fuzzing with coverage guidance | Build required | Deep |
| LibFuzzer (host) | Have source, want sanitizers | Fastest | Deepest |
