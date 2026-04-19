# Frida Scripts Reference

## Setup & Usage

```bash
# Start frida-server on device (root required)
adb shell su -c "/data/local/tmp/frida-server &"

# Spawn and attach
frida -U -f <package_name> -l script.js --no-pause

# Attach to running process
frida -U -n <process_name> -l script.js

# Remote device
frida -H <ip>:<port> -f <package_name> -l script.js --no-pause

# List processes
frida-ps -U
frida-ps -U | grep <keyword>
```

## SSL Pinning Bypass

```javascript
// Universal SSL pinning bypass - covers most implementations
Java.perform(function() {
    // TrustManagerImpl (Android default)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassing TrustManagerImpl: ' + host);
            return untrustedChain;
        };
    } catch(e) { console.log('[-] TrustManagerImpl not found'); }

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassing OkHttp3 pinner: ' + hostname);
        };
    } catch(e) { console.log('[-] OkHttp3 CertificatePinner not found'); }

    // X509TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.frida.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) { console.log('[-] Custom TrustManager registration failed'); }

    // HostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var Verifier = Java.registerClass({
            name: 'com.frida.HostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log('[+] Bypassing hostname verification: ' + hostname);
                    return true;
                }
            }
        });
    } catch(e) { console.log('[-] HostnameVerifier bypass failed'); }

    // SSLContext
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            console.log('[+] Bypassing SSLContext.init');
            this.init(km, tm, sr);
        };
    } catch(e) { console.log('[-] SSLContext bypass failed'); }
});
```

## Crypto Monitoring

```javascript
Java.perform(function() {
    // Monitor Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        console.log('[Cipher] Algorithm: ' + transformation);
        return this.getInstance(transformation);
    };

    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        var modeStr = mode == 1 ? 'ENCRYPT' : 'DECRYPT';
        console.log('[Cipher] Mode: ' + modeStr);
        console.log('[Cipher] Key: ' + bytesToHex(key.getEncoded()));
        this.init(mode, key);
    };

    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Cipher] Input (' + input.length + ' bytes): ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[Cipher] Output (' + result.length + ' bytes): ' + bytesToHex(result));
        return result;
    };

    // Monitor MessageDigest (hashing)
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log('[Hash] Algorithm: ' + algo);
        return this.getInstance(algo);
    };

    // Monitor SecretKeySpec creation
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[Key] Algorithm: ' + algo + ', Key: ' + bytesToHex(key));
        this.$init(key, algo);
    };
});

function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}
```

## SharedPreferences Monitoring

```javascript
Java.perform(function() {
    var SharedPrefsEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

    SharedPrefsEditor.putString.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT String: ' + key + ' = ' + value);
        return this.putString(key, value);
    };

    SharedPrefsEditor.putInt.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT Int: ' + key + ' = ' + value);
        return this.putInt(key, value);
    };

    SharedPrefsEditor.putBoolean.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT Boolean: ' + key + ' = ' + value);
        return this.putBoolean(key, value);
    };

    var SharedPrefsImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPrefsImpl.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log('[SharedPrefs] GET String: ' + key + ' = ' + result);
        return result;
    };
});
```

## File I/O Monitoring

```javascript
Java.perform(function() {
    // Monitor file opens
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function(path) {
        console.log('[File] Path: ' + path);
        this.$init(path);
    };

    // Monitor FileOutputStream (writes)
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log('[FileWrite] ' + file.getAbsolutePath());
        this.$init(file);
    };

    // Monitor FileInputStream (reads)
    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log('[FileRead] ' + file.getAbsolutePath());
        this.$init(file);
    };
});
```

## Intent Monitoring

```javascript
Java.perform(function() {
    var Intent = Java.use('android.content.Intent');

    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
        console.log('[Intent] putExtra: ' + key + ' = ' + value);
        return this.putExtra(key, value);
    };

    var Activity = Java.use('android.app.Activity');
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Activity] startActivity: ' + intent.toString());
        if (intent.getExtras()) {
            var keys = intent.getExtras().keySet().iterator();
            while (keys.hasNext()) {
                var key = keys.next();
                console.log('  Extra: ' + key + ' = ' + intent.getExtras().get(key));
            }
        }
        this.startActivity(intent);
    };
});
```

## WebView Monitoring

```javascript
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WebView] loadUrl: ' + url);
        this.loadUrl(url);
    };

    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
        console.log('[WebView] loadUrl (headers): ' + url);
        this.loadUrl(url, headers);
    };

    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView] addJavascriptInterface: ' + name + ' (' + obj.getClass().getName() + ')');
        this.addJavascriptInterface(obj, name);
    };
});
```

## Root Detection Bypass

```javascript
Java.perform(function() {
    // Common root detection bypasses

    // File.exists() for su binary
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') >= 0 || path.indexOf('Superuser') >= 0 ||
            path.indexOf('magisk') >= 0 || path.indexOf('busybox') >= 0) {
            console.log('[RootBypass] Hiding: ' + path);
            return false;
        }
        return this.exists();
    };

    // Runtime.exec() for which su
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('which') >= 0) {
            console.log('[RootBypass] Blocking exec: ' + cmd);
            throw Java.use('java.io.IOException').$new('Command not found');
        }
        return this.exec(cmd);
    };

    // Build.TAGS check
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    console.log('[RootBypass] Build.TAGS set to release-keys');
});
```

## Clipboard Monitoring

```javascript
Java.perform(function() {
    var ClipboardManager = Java.use('android.content.ClipboardManager');

    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var text = clip.getItemAt(0).getText();
        console.log('[Clipboard] SET: ' + text);
        this.setPrimaryClip(clip);
    };

    ClipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        if (clip != null && clip.getItemCount() > 0) {
            console.log('[Clipboard] GET: ' + clip.getItemAt(0).getText());
        }
        return clip;
    };
});
```

## Utility: Enumerate Classes and Methods

```javascript
// List all loaded classes matching a pattern
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf('<package_keyword>') >= 0) {
                console.log('[Class] ' + className);
            }
        },
        onComplete: function() {
            console.log('[*] Class enumeration complete');
        }
    });
});

// List methods of a class
Java.perform(function() {
    var cls = Java.use('<fully.qualified.ClassName>');
    var methods = cls.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
        console.log('[Method] ' + methods[i].getName() + ' -> ' + methods[i].toGenericString());
    }
});
```
