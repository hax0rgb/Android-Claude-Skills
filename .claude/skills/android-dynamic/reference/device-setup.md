# Device/Emulator Setup Guide

## Emulator Setup (Recommended for Testing)

### Android Studio Emulator
```bash
# List available AVDs
emulator -list-avds

# Start with writable system (for root)
emulator -avd <avd_name> -writable-system -no-snapshot

# With proxy for traffic interception
emulator -avd <avd_name> -http-proxy http://<host_ip>:8080
```

### Genymotion
- Create device with root enabled
- Enable ADB bridge in settings
- Connect: `adb connect <genymotion_ip>:5555`

## Root Setup

### Magisk (Physical Device)
1. Unlock bootloader
2. Install Magisk via custom recovery
3. Verify: `adb shell su -c id` returns `uid=0`

### rootAVD (Emulator)
```bash
# Clone rootAVD
git clone https://github.com/newbit1/rootAVD.git
cd rootAVD

# List system images
./rootAVD.sh ListAllAVDs

# Root the emulator
./rootAVD.sh <system-image-path>/ramdisk.img
```

## Frida Server Setup

```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi
# Output: arm64-v8a, armeabi-v7a, x86, x86_64

# Download matching frida-server from:
# https://github.com/frida/frida/releases
# Example: frida-server-16.x.x-android-arm64

# Push to device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server
adb shell su -c "/data/local/tmp/frida-server &"

# Verify
frida-ps -U
```

## Certificate Installation (for HTTPS Interception)

### User Certificate (Android < 7)
```bash
# Push cert to device
adb push burp-cert.der /sdcard/
# Install via Settings > Security > Install from storage
```

### System Certificate (Android 7+, Root Required)

```bash
# Convert cert to PEM format
openssl x509 -inform DER -in burp-cert.der -out burp-cert.pem

# Get hash for filename
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp-cert.pem | head -1)

# Rename to hash.0
cp burp-cert.pem ${HASH}.0

# Push to system cert store
adb push ${HASH}.0 /sdcard/
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "mv /sdcard/${HASH}.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/${HASH}.0"
adb shell su -c "reboot"
```

### AlwaysTrustUserCerts (Magisk Module)
Simpler alternative - install the Magisk module that auto-trusts user certificates as system certificates.

## Proxy Setup (mitmproxy)

```bash
# Start mitmproxy on host
mitmproxy --listen-port 8080

# Set proxy on device
adb shell settings put global http_proxy <host_ip>:8080

# Remove proxy when done
adb shell settings put global http_proxy :0
```

## Pre-Test Checklist

- [ ] Device connected: `adb devices` shows device
- [ ] Root verified: `adb shell su -c id` returns uid=0
- [ ] Frida running: `frida-ps -U` returns process list
- [ ] Target APK installed: `adb shell pm list packages | grep <pkg>`
- [ ] (Optional) Proxy configured and cert trusted
- [ ] (Optional) Screen recording started for evidence
