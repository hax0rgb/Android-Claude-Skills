#!/bin/bash
# Device pre-flight check script
# Usage: ./device-check.sh <device_ip:port>

set -e

DEVICE_IP="$1"

if [ -z "$DEVICE_IP" ]; then
    echo "Usage: $0 <device_ip:port>"
    exit 1
fi

echo "=== Device Pre-flight Check ==="
echo ""

# Connect
echo "[1/7] Connecting to device..."
adb connect "$DEVICE_IP" 2>&1
echo ""

# Verify connection
echo "[2/7] Verifying connection..."
DEVICE_STATUS=$(adb -s "$DEVICE_IP" get-state 2>&1 || echo "offline")
if [ "$DEVICE_STATUS" != "device" ]; then
    echo "FAIL: Device not connected (status: $DEVICE_STATUS)"
    exit 1
fi
echo "OK: Device connected"
echo ""

# Device info
echo "[3/7] Device info..."
ANDROID_VER=$(adb -s "$DEVICE_IP" shell getprop ro.build.version.release 2>/dev/null || echo "unknown")
API_LEVEL=$(adb -s "$DEVICE_IP" shell getprop ro.build.version.sdk 2>/dev/null || echo "unknown")
MODEL=$(adb -s "$DEVICE_IP" shell getprop ro.product.model 2>/dev/null || echo "unknown")
ABI=$(adb -s "$DEVICE_IP" shell getprop ro.product.cpu.abi 2>/dev/null || echo "unknown")
echo "  Android: $ANDROID_VER (API $API_LEVEL)"
echo "  Model: $MODEL"
echo "  Architecture: $ABI"
echo ""

# Root check
echo "[4/7] Checking root access..."
ROOT_CHECK=$(adb -s "$DEVICE_IP" shell su -c id 2>&1 || echo "no root")
if echo "$ROOT_CHECK" | grep -q "uid=0"; then
    echo "OK: Root access available"
    ROOTED="true"
else
    echo "WARN: No root access detected"
    echo "  Many dynamic checks will be skipped (storage analysis, Frida, internal file access)"
    ROOTED="false"
fi
echo ""

# SELinux
echo "[5/7] SELinux status..."
SELINUX=$(adb -s "$DEVICE_IP" shell getenforce 2>/dev/null || echo "unknown")
echo "  SELinux: $SELINUX"
echo ""

# Frida check
echo "[6/7] Checking Frida server..."
if [ "$ROOTED" = "true" ]; then
    FRIDA_BIN=$(adb -s "$DEVICE_IP" shell su -c "ls /data/local/tmp/frida-server* 2>/dev/null" || echo "")
    if [ -n "$FRIDA_BIN" ]; then
        echo "OK: Frida server found at $FRIDA_BIN"
        # Check if running
        FRIDA_PID=$(adb -s "$DEVICE_IP" shell su -c "pidof frida-server" 2>/dev/null || echo "")
        if [ -n "$FRIDA_PID" ]; then
            echo "OK: Frida server running (PID: $FRIDA_PID)"
        else
            echo "WARN: Frida server not running. Start with:"
            echo "  adb -s $DEVICE_IP shell su -c '/data/local/tmp/frida-server &'"
        fi
    else
        echo "WARN: Frida server not found on device"
        echo "  Download from https://github.com/frida/frida/releases"
        echo "  Push with: adb push frida-server-<version>-android-$ABI /data/local/tmp/"
    fi
else
    echo "SKIP: Requires root"
fi
echo ""

# Host tools
echo "[7/7] Checking host tools..."
for tool in adb frida frida-ps; do
    if command -v "$tool" &>/dev/null; then
        echo "  OK: $tool found"
    else
        echo "  WARN: $tool not found in PATH"
    fi
done
echo ""

echo "=== Summary ==="
echo "Device: $MODEL ($ANDROID_VER, API $API_LEVEL, $ABI)"
echo "Root: $ROOTED"
echo "SELinux: $SELINUX"
echo "Ready for: $([ "$ROOTED" = "true" ] && echo "full testing" || echo "limited testing (no root)")"
