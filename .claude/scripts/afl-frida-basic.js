Afl.print(`[*] Starting FRIDA config for PID: ${Process.id}`);

/* Only fuzz our harness + JNI library */
const MODULE_WHITELIST = [
  "harness",
  "libjnisys-lib.so",   // your compiled JNI lib
];

/* Persistent hook:
 * For fuzz_one_input(const uint8_t *buffer, size_t length),
 * x0 = buffer pointer, x1 = length on ARM64.
 */
const hook_module = new CModule(`
  #include <string.h>
  #include <gum/gumdefs.h>

  void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
    uint32_t input_buf_len) {

    // Cap to a reasonable max (to avoid AFL sending 100KB+ blobs)
    const uint32_t MAX_LEN = 4096;

    uint32_t length = (input_buf_len > MAX_LEN) ? MAX_LEN : input_buf_len;

    // Copy AFL input into harness buffer
    memcpy((void *) regs->x[0], input_buf, length);

    // Tell harness the actual length
    regs->x[1] = length;
  }
  `,
  {
    memcpy: Module.getExportByName(null, "memcpy")
  }
);

/* Our persistent function is fuzz_one_input */
const pPersistentAddr = DebugSymbol.fromName("fuzz_one_input").address;

/* Exclude non-target modules */
Module.load("libandroid_runtime.so");
new ModuleMap().values().forEach(m => {
  if (!MODULE_WHITELIST.includes(m.name)) {
    Afl.print(`Exclude: ${m.base}-${m.base.add(m.size)} ${m.name}`);
    Afl.addExcludedRange(m.base, m.size);
  }
});


/* Configure AFL persistent mode */
Afl.setEntryPoint(pPersistentAddr);
Afl.setPersistentHook(hook_module.afl_persistent_hook);
Afl.setPersistentAddress(pPersistentAddr);
Afl.setPersistentCount(10000);
Afl.setInMemoryFuzzing();
Afl.setInstrumentLibraries();

Afl.done();
Afl.print("[*] All done!");
