/**
 * Frida script to hook JNI RegisterNatives.
 * It logs the Java class, native methods, and the library base/offset where each method is registered.
 */

function hookJNINativeRegistration() {
    console.log("[*] Scanning libart.so for JNI RegisterNatives exports...");

    const artSymbols = Module.enumerateSymbolsSync("libart.so");
    let foundAny = false;

    for (const sym of artSymbols) {
        if (sym.name.includes("art") &&
            sym.name.includes("JNI") &&
            sym.name.includes("RegisterNatives") &&
            !sym.name.includes("CheckJNI")) {
            
            foundAny = true;
            console.log(`[+] Found RegisterNatives: ${sym.address} (${sym.name})`);
            attachRegisterNativesHook(sym.address);
        }
    }

    if (!foundAny) {
        console.error("[-] No RegisterNatives symbols found in libart.so");
    }
}

function attachRegisterNativesHook(address) {
    Interceptor.attach(address, {
        onEnter: function (args) {
            const jclassHandle = args[1];
            const jniMethodsArray = args[2];
            const jniMethodCount = args[3].toInt32();

            if (jniMethodCount === 0) {
                return;
            }

            const env = Java.vm.tryGetEnv();
            const javaClassName = env.getClassName(jclassHandle);
            const callerInfo = DebugSymbol.fromAddress(this.returnAddress);

            console.log(
                `\n[+] RegisterNatives intercepted for class: ${javaClassName}` +
                ` (methods: ${jniMethodCount})`
            );
            console.log(`    Invoked from: ${callerInfo}`);

            for (let i = 0; i < jniMethodCount; i++) {
                const entrySize = Process.pointerSize * 3;
                const entry = jniMethodsArray.add(i * entrySize);

                const namePtr = entry.readPointer();
                const sigPtr = entry.add(Process.pointerSize).readPointer();
                const fnPtr = entry.add(Process.pointerSize * 2).readPointer();

                const methodName = namePtr.readCString();
                const methodSig = sigPtr.readCString();

                const module = Process.findModuleByAddress(fnPtr);

                let moduleName = "Unknown";
                let moduleBase = ptr(0);
                let offset = ptr(0);

                if (module) {
                    moduleName = module.name;
                    moduleBase = module.base;
                    offset = fnPtr.sub(moduleBase);
                }

                console.log(
                    `  [${i}] ${methodName}${methodSig}\n` +
                    `       ↳ Library: ${moduleName} (Base: ${moduleBase})\n` +
                    `       ↳ Address: ${fnPtr} (Offset: ${offset})`
                );
            }
        }
    });
}

Java.perform(function () {
    console.log("[*] Frida script initialized...");
    hookJNINativeRegistration();
});
