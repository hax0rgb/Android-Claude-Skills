# Medusa Framework Reference

[Medusa](https://github.com/Ch0pin/medusa) is a Frida-based modular instrumentation framework with 100+ pre-built modules. Use it instead of writing custom Frida scripts from scratch.

## Setup

```bash
git clone https://github.com/Ch0pin/medusa.git
cd medusa && pip3 install -r requirements.txt
# Ensure frida-server is running on device
python3 medusa.py
```

## Quick Workflow

```bash
# 1. Select device
medusa> loaddevice

# 2. Find and stash modules
medusa> search ssl
medusa> use http_communications/v3_multiple_unpinner
medusa> use intents/outgoing_intents
medusa> use encryption/cipher_1
medusa> use file_system/shared_preferences

# 3. Compile into single agent
medusa> compile

# 4. Spawn and attach
medusa> run -f com.target.app
```

## Module Selection Guide (by Pentest Phase)

### SSL/Network Interception
| Module | Use When |
|---|---|
| `http_communications/v3_multiple_unpinner` | Universal SSL bypass (try first) |
| `http_communications/universal_SSL_pinning_bypass` | Alternative universal bypass |
| `http_communications/tiktok_ssl_pinning_bypass` | TikTok-specific |
| `http_communications/facebook_ssl_pinning_bypass` | Facebook/Meta apps |
| `http_communications/instagram_ssl_pinning_bypass` | Instagram |
| `http_communications/flutter_disable_tls_verification` | Flutter apps |
| `http_communications/okhttp3_retrofit` | Monitor OkHttp/Retrofit requests |
| `http_communications/volley_request` | Monitor Volley requests |
| `http_communications/uri_logger` | Log all URI accesses |
| `http_communications/dns_logger` | Log DNS resolutions |
| `http_communications/intercept_json_objects` | Capture JSON request/response bodies |

### Intent Monitoring
| Module | What It Captures |
|---|---|
| `intents/incoming_intents` | All intents received by the app |
| `intents/outgoing_intents` | All intents sent by the app |
| `intents/broadcasts` | Broadcast intents (sent and received) |
| `intents/intent_creation_monitor` | Intent object construction |
| `intents/pending_intents` | PendingIntent creation and usage |

### Crypto Inspection
| Module | What It Captures |
|---|---|
| `encryption/cipher_1` | Cipher.init/doFinal with key/IV/plaintext |
| `encryption/cipher_2` | Extended cipher monitoring |
| `encryption/cipher_3` | Additional cipher patterns |
| `encryption/hash_operations` | MessageDigest operations (MD5, SHA, etc.) |
| `helpers/keystore_extract` | Extract keys from Android KeyStore |

### Storage Monitoring
| Module | What It Captures |
|---|---|
| `file_system/shared_preferences` | SharedPreferences read/write |
| `file_system/file_monitor_and_dump` | All file I/O with content dump |
| `file_system/file_input_stream` | File read operations |
| `file_system/file_output_stream` | File write operations |
| `file_system/file_exists` | File existence checks |
| `db_queries/sqlite_monitor` | SQLite queries |
| `db_queries/SQLiteDatabase` | Database operations |

### Component Analysis
| Module | What It Captures |
|---|---|
| `webviews/hook_webviews` | WebView URL loading, JS execution |
| `webviews/chrome_custom_tabs` | Chrome Custom Tabs navigation |
| `content_providers/content_provider_query` | ContentProvider queries |
| `content_providers/file_provider_implemetation` | FileProvider operations |
| `fragments/nav_graphs` | Navigation graph transitions |
| `services/notification_listener` | Notification service activity |
| `services/accessibility_nod` | Accessibility service hooks |

### Security Bypass
| Module | What It Does |
|---|---|
| `root_detection/anti_root` | Generic root detection bypass |
| `root_detection/anti_root_beer` | RootBeer library bypass |
| `root_detection/anti_root_jailMonkey_rn` | React Native JailMonkey bypass |
| `helpers/cancel_system_exit` | Block System.exit() |
| `helpers/device_cloaking` | Fake device properties |
| `helpers/enable_screencap` | Bypass FLAG_SECURE |

### Cloud/Firebase
| Module | What It Captures |
|---|---|
| `firebase/database_reference` | Firebase Realtime Database operations |
| `firebase/firebase_authentication` | Auth events |
| `firebase/firebase_firestore` | Firestore queries |
| `firebase/firebase_messaging` | FCM messages |
| `exploits/amazon_aws_key_extraction` | Extract AWS keys |

### Native/JNI
| Module | What It Captures |
|---|---|
| `JNICalls/FindClass` | JNI class lookups |
| `JNICalls/GetMethodID` | JNI method resolution |
| `JNICalls/CallObjectMethod` | JNI method calls |
| `JNICalls/NewStringUTF` | JNI string creation |
| `JNICalls/RegisterNatives` | Native method registration |
| `code_loading/dynamic_code_loading` | DexClassLoader usage |
| `code_loading/native_libs` | Native library loading |
| `memory_dump/dump_dex` | Dump loaded DEX files |

## Key Commands During Session

```bash
# Hook all methods of a class
medusa> hook -a com.target.app.SecretClass

# Interactive method hooking
medusa> hook -f

# Trace a specific method
medusa> jtrace com.target.app.Auth.verifyToken

# Get field value from live object
medusa> get com.target.app com.target.app.Config.API_KEY

# List loaded native libraries
medusa> libs -j

# Enumerate exports from native lib
medusa> enumerate com.target.app libnative.so

# Dump DEX files (for packed apps)
medusa> dump com.target.app

# Force load DEX
medusa> dexload /sdcard/evil.dex

# Memory exploration
medusa> memmap com.target.app
medusa> memops com.target.app libnative.so

# Device shell
medusa> shell
medusa> cc ls /data/data/com.target.app/
```

## Mango (Companion Static Tool)

```bash
python3 mango.py target_db

# Import and analyze APK
mango> import /path/to/target.apk
# Or pull from device
mango> pull com.target.app

# Show attack surface
mango> show -e          # Exported components
mango> show exposure    # Deep links + exported components
mango> show manifest    # Full manifest
mango> show strings     # Resource strings

# Interact with components
mango> start com.target.app/.SecretActivity
mango> deeplink myapp://test?param=value

# Setup proxy
mango> installBurpCert
mango> proxy set 192.168.1.100:8080

# Trace
mango> trace -j com.target.app.Crypto
```

## Non-Interactive Mode (Automation)

```bash
# Run pre-configured recipe for 60 seconds
python3 medusa.py --not-interactive \
  -p com.target.app \
  -t 60 \
  -s output.log \
  -m recipe.txt \
  -d <device-id>
```

Recipe file (`recipe.txt`):
```
MODULE http_communications/v3_multiple_unpinner
MODULE intents/outgoing_intents
MODULE encryption/cipher_1
MODULE file_system/shared_preferences
MODULE webviews/hook_webviews
```

## Recommended Module Combos

### Initial Recon
```
use http_communications/v3_multiple_unpinner
use intents/outgoing_intents
use intents/incoming_intents
use file_system/shared_preferences
use webviews/hook_webviews
use helpers/cancel_system_exit
```

### Crypto Analysis
```
use encryption/cipher_1
use encryption/hash_operations
use helpers/keystore_extract
use http_communications/openssl_boringssl_key_capture
```

### Full Monitoring
```
use http_communications/v3_multiple_unpinner
use intents/outgoing_intents
use intents/incoming_intents
use intents/pending_intents
use encryption/cipher_1
use file_system/shared_preferences
use file_system/file_monitor_and_dump
use db_queries/sqlite_monitor
use webviews/hook_webviews
use content_providers/content_provider_query
```
