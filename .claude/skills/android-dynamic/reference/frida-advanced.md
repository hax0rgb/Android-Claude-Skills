# Advanced Frida Techniques from Writeups

## Root Detection Bypass Patterns

### Generic Boolean Method Bypass
Automatically bypass all boolean methods in root detection classes:
```javascript
Java.perform(function() {
    var checkers = [
        'com.scottyab.rootbeer.RootBeer',
        'com.scottyab.rootbeer.util.QComSocInfo',
    ];
    checkers.forEach(function(cls) {
        try {
            var c = Java.use(cls);
            c.class.getDeclaredMethods().forEach(function(m) {
                if (m.getReturnType().getName() === 'boolean') {
                    c[m.getName()].implementation = function() { return false; };
                }
            });
        } catch(e) {}
    });
});
```

### System.exit() Block (Universal)
```javascript
Java.use("java.lang.System").exit.implementation = function(code) {
    console.log("[*] System.exit(" + code + ") blocked");
};
```

### Flutter/Obfuscated Root Check
```javascript
// When class/method names are obfuscated
Java.use("B.a")["g"].implementation = function(a, b) {
    console.log("[*] Root check bypassed (obfuscated)");
};
```

## Memory Scanning for Hidden Data

### Find Flags/Secrets in Native Libraries
```javascript
Java.perform(function() {
    var mod = Process.getModuleByName("libflag.so");
    // Scan for known prefix (e.g., "FLAG{", "MHL{", "CTF{")
    var results = Memory.scanSync(mod.base, mod.size, "4d 48 4c 7b");  // "MHL{"
    results.forEach(function(match) {
        console.log("[*] Found at " + match.address + ":");
        console.log(hexdump(match.address, { length: 64 }));
    });
});
```

### Full Memory Dump (Alternative: fridump)
```bash
# Install fridump
pip install fridump3
# Dump all memory
fridump3 -U -s <package_name> -o dump/
# Search dumps
grep -r "password\|token\|secret" dump/
```

## DexClassLoader Tracing

### Catch Dynamically Loaded Code
```javascript
Java.perform(function() {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
        console.log('[DCL] Loading DEX: ' + dexPath);
        console.log('[DCL] Opt dir: ' + optDir);
        console.log('[DCL] Lib path: ' + libPath);
        this.$init(dexPath, optDir, libPath, parent);
    };

    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(path, parent) {
        console.log('[PCL] Loading: ' + path);
        this.$init(path, parent);
    };
});
```

## Native Function Hooking Patterns

### Hook strncmp to Extract Comparison Strings
```javascript
// Useful when native code compares input against secret
var strncmpAddr = Module.getExportByName('libc.so', 'strncmp');
var callCount = 0;
Interceptor.attach(strncmpAddr, {
    onEnter(args) {
        callCount++;
        var a = Memory.readUtf8String(args[0]);
        var b = Memory.readUtf8String(args[1]);
        // Filter by known input to reduce noise (strncmp called thousands of times)
        if (a && a.indexOf("my_input") >= 0) {
            console.log("[strncmp #" + callCount + "] '" + a + "' vs '" + b + "'");
        }
    }
});
```

### Hook system() to Monitor Command Execution
```javascript
Interceptor.attach(Module.getExportByName('libc.so', 'system'), {
    onEnter(args) {
        console.log("[system] " + Memory.readUtf8String(args[0]));
    },
    onLeave(retval) {
        console.log("[system] returned: " + retval);
    }
});
```

### Hook dlopen to Monitor Library Loading
```javascript
Interceptor.attach(Module.getExportByName(null, 'dlopen'), {
    onEnter(args) {
        console.log("[dlopen] " + Memory.readUtf8String(args[0]));
    }
});
Interceptor.attach(Module.getExportByName(null, 'android_dlopen_ext'), {
    onEnter(args) {
        console.log("[android_dlopen_ext] " + Memory.readUtf8String(args[0]));
    }
});
```

## Overloaded Method Hooking

When a method has multiple overloads, specify the parameter types:
```javascript
Java.perform(function() {
    var cls = Java.use("com.example.Crypto");

    // Hook specific overload
    cls.decrypt.overload('java.lang.String').implementation = function(input) {
        console.log("[decrypt(String)] " + input);
        var result = this.decrypt(input);
        console.log("[decrypt] -> " + result);
        return result;
    };

    // Hook another overload
    cls.decrypt.overload('[B', 'java.lang.String').implementation = function(data, key) {
        console.log("[decrypt(byte[],String)] key=" + key);
        return this.decrypt(data, key);
    };
});
```

## Java.choose() for Live Instance Access

Call methods on already-created objects (not class-level):
```javascript
Java.perform(function() {
    Java.choose("com.example.MainActivity", {
        onMatch: function(instance) {
            console.log("[*] Found instance: " + instance);
            // Call instance method
            instance.KLOW();  // Trigger SharedPrefs creation
            // Read instance field
            console.log("Token: " + instance.authToken.value);
        },
        onComplete: function() {
            console.log("[*] Search complete");
        }
    });
});
```

## AES Key/IV/Ciphertext Extraction

### Complete Crypto Monitoring
```javascript
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[KEY] ' + algo + ': ' + arrToHex(key) + ' ("' + arrToStr(key) + '")');
        return this.$init(key, algo);
    };

    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log('[IV] ' + arrToHex(iv) + ' ("' + arrToStr(iv) + '")');
        return this.$init(iv);
    };

    Cipher.doFinal.overload('[B').implementation = function(data) {
        var result = this.doFinal(data);
        console.log('[CIPHER] Input:  ' + arrToHex(data));
        console.log('[CIPHER] Output: ' + arrToHex(result));
        try { console.log('[CIPHER] Output (text): ' + arrToStr(result)); } catch(e) {}
        return result;
    };
});

function arrToHex(arr) {
    var h = '';
    for (var i = 0; i < arr.length; i++) h += ('0' + (arr[i] & 0xFF).toString(16)).slice(-2);
    return h;
}
function arrToStr(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i] & 0xFF);
    return s;
}
```

## Class and Method Enumeration

### Find Classes Matching Pattern
```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.indexOf("com.target") >= 0) {
                console.log("[CLASS] " + name);
            }
        },
        onComplete: function() {}
    });
});
```

### List All Methods of a Class
```javascript
Java.perform(function() {
    var cls = Java.use("com.target.SomeClass");
    cls.class.getDeclaredMethods().forEach(function(m) {
        console.log("[METHOD] " + m.getName() + " -> " + m.toGenericString());
    });
});
```

### List All Fields of a Class
```javascript
Java.perform(function() {
    var cls = Java.use("com.target.SomeClass");
    cls.class.getDeclaredFields().forEach(function(f) {
        f.setAccessible(true);
        console.log("[FIELD] " + f.getName() + " : " + f.getType().getName());
    });
});
```

## Multi-Hook Script Template

```javascript
// Comprehensive monitoring script template
setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Multi-hook script loaded for <package_name>");

        // 1. Block root detection
        try {
            Java.use("java.lang.System").exit.implementation = function(c) {
                console.log("[ROOT] System.exit blocked");
            };
        } catch(e) {}

        // 2. SSL pinning bypass
        try {
            Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String', 'java.util.List')
                .implementation = function(h, c) { console.log("[SSL] Bypass: " + h); };
        } catch(e) {}

        // 3. Monitor crypto
        try {
            Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String')
                .implementation = function(k, a) {
                    console.log("[CRYPTO] Key(" + a + "): " + arrToHex(k));
                    return this.$init(k, a);
                };
        } catch(e) {}

        // 4. Monitor SharedPrefs writes
        try {
            Java.use('android.app.SharedPreferencesImpl$EditorImpl').putString
                .implementation = function(k, v) {
                    console.log("[PREFS] " + k + " = " + v);
                    return this.putString(k, v);
                };
        } catch(e) {}

        // 5. Monitor intents
        try {
            Java.use('android.app.Activity').startActivity.overload('android.content.Intent')
                .implementation = function(i) {
                    console.log("[INTENT] " + i.toString());
                    this.startActivity(i);
                };
        } catch(e) {}

        console.log("[*] All hooks installed");
    });
}, 1000);

function arrToHex(a) {
    var h=''; for(var i=0;i<a.length;i++) h+=('0'+(a[i]&0xFF).toString(16)).slice(-2); return h;
}
```
