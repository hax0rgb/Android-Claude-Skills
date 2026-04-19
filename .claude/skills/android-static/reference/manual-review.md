# Manual Code Review Patterns

Code review checklist for vulnerabilities the automated scanner may miss.

## Component Security

### Intent Handling
```java
// VULN: Trusting intent extras without validation
String url = getIntent().getStringExtra("url");
webView.loadUrl(url);  // Arbitrary URL loading

// VULN: Using intent data in file operations
String path = getIntent().getData().getPath();
File f = new File(getFilesDir(), path);  // Path traversal
```

**Search patterns:**
```
getIntent().getStringExtra
getIntent().getData()
getIntent().getParcelableExtra
getIntent().getSerializableExtra
```

### PendingIntent
```java
// VULN: Mutable PendingIntent with implicit base intent
Intent base = new Intent();  // No component set
PendingIntent pi = PendingIntent.getActivity(ctx, 0, base, PendingIntent.FLAG_MUTABLE);

// VULN: Wrapping PendingIntent in a broadcast
sendBroadcast(new Intent("ACTION").putExtra("pending", pi));
```

**Search patterns:**
```
PendingIntent.getActivity
PendingIntent.getService
PendingIntent.getBroadcast
FLAG_MUTABLE
```

### Content Provider File Access
```java
// VULN: Path traversal in openFile
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
    // No validation of ".." in path
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
}
```

**Search patterns:**
```
openFile.*Uri
ParcelFileDescriptor
getLastPathSegment
```

## Data Security

### Hardcoded Secrets
**Search patterns (regex):**
```
(api[_-]?key|apikey|secret|password|token|auth)\s*[:=]\s*["'][^"']{8,}
-----BEGIN (RSA |EC )?PRIVATE KEY-----
AIza[0-9A-Za-z_-]{35}          # Google API key
AKIA[0-9A-Z]{16}               # AWS access key
sk-[a-zA-Z0-9]{20,}            # Stripe/OpenAI keys
ghp_[a-zA-Z0-9]{36}            # GitHub PAT
```

### Insecure Storage
```java
// VULN: World-readable SharedPreferences (deprecated but still found)
getSharedPreferences("prefs", MODE_WORLD_READABLE);

// VULN: Storing sensitive data in plain SharedPreferences
editor.putString("auth_token", token);
editor.putString("password", password);

// VULN: External storage (world-readable)
File f = new File(Environment.getExternalStorageDirectory(), "sensitive.txt");
```

**Search patterns:**
```
MODE_WORLD_READABLE
MODE_WORLD_WRITEABLE
getExternalStorageDirectory
getExternalFilesDir
putString.*token
putString.*password
putString.*key
```

### Log Leaks
```java
// VULN: Sensitive data in logs
Log.d(TAG, "User token: " + token);
Log.i(TAG, "API response: " + response.body());
```

**Search patterns:**
```
Log\.(d|i|v|w|e)\(.*token
Log\.(d|i|v|w|e)\(.*password
Log\.(d|i|v|w|e)\(.*secret
Log\.(d|i|v|w|e)\(.*key
Log\.(d|i|v|w|e)\(.*response
```

## Crypto

### Weak Algorithms
```java
// VULN: ECB mode
Cipher.getInstance("AES/ECB/PKCS5Padding");

// VULN: DES
Cipher.getInstance("DES");
SecretKeyFactory.getInstance("DES");

// VULN: MD5 for security
MessageDigest.getInstance("MD5");

// VULN: Weak random
new java.util.Random();  // Should be SecureRandom
```

**Search patterns:**
```
Cipher.getInstance.*ECB
Cipher.getInstance.*DES
MessageDigest.getInstance.*MD5
MessageDigest.getInstance.*SHA-1
new Random\(
java.util.Random
```

### Hardcoded Keys
```java
// VULN: Hardcoded encryption key
byte[] key = "mysecretkey12345".getBytes();
SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

// VULN: Hardcoded IV
byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
IvParameterSpec ivSpec = new IvParameterSpec(iv);
```

**Search patterns:**
```
SecretKeySpec.*getBytes
new IvParameterSpec
"AES".*getBytes
```

## WebView

### JavaScript Bridge
```java
// VULN: JS interface on WebView loading untrusted content
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new JsBridge(), "bridge");
webView.loadUrl(untrustedUrl);

// VULN: File access with universal access
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

**Search patterns:**
```
setJavaScriptEnabled.*true
addJavascriptInterface
setAllowFileAccess.*true
setAllowUniversalAccessFromFileURLs.*true
setAllowFileAccessFromFileURLs.*true
@JavascriptInterface
```

## Network

### Certificate Validation
```java
// VULN: Trust all certificates
public void checkServerTrusted(X509Certificate[] chain, String authType) {
    // Empty implementation - accepts everything
}

// VULN: Accept all hostnames
HostnameVerifier allHostsValid = (hostname, session) -> true;
```

**Search patterns:**
```
checkServerTrusted.*\{\s*\}
checkServerTrusted.*return
X509TrustManager
HostnameVerifier.*true
ALLOW_ALL_HOSTNAME_VERIFIER
```

## Deep Links

### URI Handler Vulnerabilities
```java
// VULN: No host/path validation
Uri data = getIntent().getData();
String path = data.getPath();
loadContent(path);  // Attacker controls path

// VULN: WebView loads deep link URL
String url = getIntent().getData().toString();
webView.loadUrl(url);  // XSS via deep link
```

**Search patterns in AndroidManifest.xml:**
```
<data android:scheme=
intent-filter.*VIEW
android:pathPattern
android:pathPrefix
```

**Search patterns in Java:**
```
getIntent\(\)\.getData\(\)
intent\.getData\(\)
\.getPath\(\)
\.getHost\(\)
\.getQueryParameter\(
```
