# Android Security Evolution by Version

What attacks work on which Android versions. Critical for assessing exploitability based on target's `minSdkVersion` and `targetSdkVersion`.

Source: [AndroidSecurityEvolution](https://github.com/balazsgerlei/AndroidSecurityEvolution)

## Quick Attack Feasibility Matrix

| Attack | Works Up To | Mitigated In | Bypass |
|---|---|---|---|
| MITM (user CA trusted) | API 23 (Android 6) | API 24 (Android 7) | Root + system cert install, or Frida SSL bypass |
| Cleartext HTTP sniffing | API 27 (Android 8) | API 28 (Android 9) | App opts in via `cleartextTrafficPermitted` |
| StrandHogg 2.0 (task hijack) | API 28 (Android 9) | API 29 (Android 10) | N/A (patched, backported to 8/8.1/9) |
| StrandHogg 1.0 (task hijack) | API 29 (Android 10) | API 30 (Android 11) | N/A |
| Global "unknown sources" sideload | API 25 (Android 7.1) | API 26 (Android 8) | Per-app install permission |
| Package visibility (query any app) | API 29 (Android 10) | API 30 (Android 11) | `<queries>` tag in manifest |
| Scoped storage opt-out | API 29 (Android 10) | API 31 (Android 12) | `requestLegacyExternalStorage` only on 10 |
| Implicit export (no flag needed) | API 30 (Android 11) | API 31 (Android 12) | Must declare `android:exported` explicitly |
| Custom toast overlay (tapjacking) | API 29 (Android 10) | API 30 (Android 11) | `setView` deprecated, 2-line limit in 12 |
| Overlay touch passthrough (tapjack) | API 30 (Android 11) | API 31 (Android 12) | Touches blocked when overlay obscures |
| Intent filter mismatch | API 32 (Android 12L) | API 33 (Android 13) | Non-matching intents blocked |
| FDE (full disk encryption) | API 32 (Android 12L) | API 33 (Android 13) | FDE removed, only FBE |
| Unrestricted sideload perms | API 32 (Android 12L) | API 33 (Android 13) | Accessibility/NotifListener blocked for sideloaded |
| targetSdk < 23 apps installable | API 33 (Android 13) | API 34 (Android 14) | Cannot install apps targeting below API 23 |
| Mutable DCL files | API 33 (Android 13) | API 34 (Android 14) | DCL files must be read-only |
| targetSdk < 24 apps installable | API 34 (Android 14) | API 35 (Android 15) | Cannot install apps targeting below API 24 |
| Intent redirection (generic) | API 35 (Android 15) | API 36 (Android 16) | Default protection against launching received intents |
| WebView file access default on | API 28 (Android 9) | API 29 (Android 10) | `setAllowFileAccess(false)` is new default |

## Version-by-Version Security Features

### Android 5.0 (API 21) - Lollipop
- Full Disk Encryption (FDE) by default (OEM can opt out)
- SELinux fully enforced
- WebView is separate updatable package

### Android 6 (API 23) - Marshmallow
- **Runtime permissions** introduced (dangerous perms need user grant)
- Keystore API extended: AES, HMAC, hardware-backed keys
- TEE required on all devices
- `isInsideSecureHardware()` API for checking key storage location

### Android 7 (API 24) - Nougat
- **User CAs no longer trusted by default** (apps targeting 24+ only trust system CAs)
- **Network Security Config** introduced: custom trust anchors, cert pinning, cleartext opt-out
- File Based Encryption (FBE) introduced
- Key Attestation (prove key is in secure hardware)
- Mediaserver split into sandboxed processes (Stagefright mitigation)

**Pentest impact:** MITM requires root for system cert install, or Frida/objection SSL bypass. Apps targeting <24 still trust user CAs.

### Android 8 (API 26) - Oreo
- **WebView JS runs in separate process** (can't access app memory)
- WebView respects Network Security Config
- Safe Browsing API in WebView
- Sideloading requires per-app explicit permission (no global toggle)
- Project Treble: vendor/framework separation for faster updates

**Pentest impact:** WebView exploitation harder (separate process). Sideloading PoC apps requires user to enable per-source.

### Android 9 (API 28) - Pie
- **Cleartext HTTP disabled by default** (must opt in via `cleartextTrafficPermitted`)
- BiometricPrompt replaces FingerprintManager
- Disk encryption mandatory for all new devices
- BouncyCastle partially replaced by Conscrypt

**Pentest impact:** Network sniffing requires app to explicitly allow cleartext, or use Frida to hook network layer.

### Android 10 (API 29) - Q
- **WebView file access disabled by default** (`setAllowFileAccess(false)`)
- TLS 1.3 default, SHA-1 certs untrusted
- **Background apps cannot launch activities** (breaks background intent attacks)
- StrandHogg 2.0 (CVE-2020-0096) patched
- Only default IME can access clipboard from background
- Project Mainline: core components updatable via Play Store

**Pentest impact:** file:// attacks on WebView need explicit `setAllowFileAccess(true)`. Background activity launches blocked.

### Android 11 (API 30) - R
- **StrandHogg 1.0 task hijacking patched**
- **Package visibility filtering**: apps can't enumerate installed apps without `<queries>` declaration
- Runtime permissions auto-reset for unused apps
- Scoped Storage (apps can still opt out via `requestLegacyExternalStorage`)
- Custom-view Toasts blocked from background (tapjacking mitigation)

**Pentest impact:** Task hijacking dead. PoC apps need `<queries>` tag. Toast-based tapjacking blocked.

### Android 12 (API 31) - S
- **`android:exported` must be explicitly set** for components with intent-filters
- Generic web intents go to default browser (app link verification required)
- **Overlay touch blocking**: touches blocked when app obscured by overlay
- Scoped Storage enforced (no opt-out)
- Clipboard access notification shown to user
- Approximate location option
- Privacy indicators (camera/mic usage shown in status bar)
- Rust language support in platform

**Pentest impact:** Implicitly exported components eliminated. Tapjacking via overlay much harder. Clipboard monitoring visible to user.

### Android 13 (API 33) - T
- **Non-matching intents blocked** by intent filters
- FDE removed entirely (only FBE)
- Shared UIDs deprecated
- `POST_NOTIFICATIONS` runtime permission required
- **Restricted Settings**: sideloaded apps blocked from Accessibility and Notification Listener
  - Bypass: install via session-based installer (not direct APK install)
- APK signature scheme v3.1

**Pentest impact:** Intent filter matching enforced. Sideloaded PoC apps can't get Accessibility/NotifListener (need session-based install to bypass).

### Android 14 (API 34) - U
- **Minimum targetSdk = 23**: apps targeting below API 23 cannot be installed
- **Dynamic code loading files must be read-only** (DexClassLoader from writable paths blocked)
- Root certificates updatable via Play Store (no OTA needed)
- Null-cipher cellular connections rejected

**Pentest impact:** DCL exploitation harder (loaded files must be read-only). Very old apps can't be installed.

### Android 15 (API 35) - V
- **Minimum targetSdk = 24**: apps targeting below API 24 cannot be installed
- Further StrandHogg mitigations (task finish behavior, background launch blocking)
- **PendingIntent creators block background activity launches by default**
- Non-visible windows blocked from background activity launches
- Safer Intents (StrictMode): intents must match target's filter specs
- Play Protect: biometric/credential required for sideloading apps targeting API <=29
- BiometricPrompt: 5 failed attempts locks device

**Pentest impact:** PendingIntent exploitation harder. Sideloading old-target apps requires biometric confirmation.

### Android 16 (API 36) - Baklava
- **Default protection against intent redirection** (blocking launching intents received from other apps)
- Safer Intents: apps can opt-in to strict intent resolution
- KeyMint 4.0: APEX module integrity in attestation

**Pentest impact:** Intent redirection attacks blocked by default. This is the biggest single change for app-level exploitation.

## Pentest Strategy by Target SDK

### Target API < 24 (Android < 7)
**Goldmine.** User CAs trusted, cleartext HTTP, no scoped storage, no export requirements, full external storage access.

### Target API 24-28 (Android 7-9)
User CAs untrusted (need Frida bypass for MITM). Cleartext HTTP may still work (API < 28). Most intent/component attacks work. StrandHogg still possible.

### Target API 29-30 (Android 10-11)
WebView file access off by default. Background activity launches blocked. StrandHogg patched. Scoped storage active (but opt-out possible on 10). Package visibility filtered on 11.

### Target API 31-33 (Android 12-13)
Exported flag required. Overlay tapjacking mitigated. Intent filter matching enforced. Sideloaded app restrictions. Focus on: content provider attacks, JS bridges, deep link handlers, custom permission abuse.

### Target API 34+ (Android 14+)
DCL files must be read-only. Minimum targetSdk enforcement. Focus on: logic flaws, content provider injection, JS bridge abuse, intent redirection (until API 36 default protection), WebView misconfigurations, server-side issues via Frida interception.

## Key Dates for SSL/TLS Pentesting

| Scenario | Approach |
|---|---|
| App targets API < 24 | Install user CA cert, traffic visible |
| App targets API 24+ (no pinning) | Root device + install system CA cert, OR Frida SSL bypass |
| App targets API 24+ (with pinning) | Frida SSL pinning bypass script (hook TrustManager/CertificatePinner) |
| Flutter app (any API) | ProxyDroid/iptables + Frida NVISO bypass + Burp invisible proxy |
| React Native (any API) | Same as native - Frida SSL bypass |

## Key Dates for Intent/Component Pentesting

| Feature | Enforcement Start |
|---|---|
| Runtime permissions | API 23 (Android 6) |
| Per-app sideload permission | API 26 (Android 8) |
| Background activity launch blocked | API 29 (Android 10) |
| Package visibility filtering | API 30 (Android 11) |
| Explicit exported flag required | API 31 (Android 12) |
| Intent filter matching enforced | API 33 (Android 13) |
| DCL files read-only | API 34 (Android 14) |
| Safer intents (StrictMode) | API 35 (Android 15) |
| Intent redirection default protection | API 36 (Android 16) |
