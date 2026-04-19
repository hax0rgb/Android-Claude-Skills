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

## Integration with Our Native Fuzzer Agent

The native-fuzzer agent should:

1. **Phase 1 (Offline):** Extract .so files, identify JNI exports and parsers via `nm`/`readelf`/`strings`
2. **Phase 2 (Offline):** If possible, build harness + compile with sanitizers for host-side fuzzing
3. **Phase 3 (On-device):** Use Frida-based safe fuzzing (max 512 bytes) for functions reachable from exported components
4. **Phase 4 (Analysis):** Analyze any crashes found, triage severity, write PoC

**When to use host-side harness fuzzing vs Frida on-device:**
- Host-side (LibFuzzer): When you have source or can link against the .so, deeper coverage, faster, no device needed
- On-device (Frida): When testing through the JNI layer, app-specific context needed, or source unavailable
