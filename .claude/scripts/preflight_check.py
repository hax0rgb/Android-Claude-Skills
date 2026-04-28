#!/usr/bin/env python3
"""
Preflight tool check for Android Pentest Agent.
Verifies all required and optional tools are installed and functional.
Run this BEFORE any agent execution.

Usage:
    python3 preflight_check.py                    # Check all tools
    python3 preflight_check.py --phase static     # Check tools for static phase only
    python3 preflight_check.py --phase dynamic    # Check tools for dynamic phase only
    python3 preflight_check.py --phase native     # Check tools for native fuzzing
    python3 preflight_check.py --phase secrets    # Check tools for secret scanning
    python3 preflight_check.py --phase exploit    # Check tools for exploit validation
    python3 preflight_check.py --device 2cf4fc4d  # Also verify device connectivity
    python3 preflight_check.py --json             # Output as JSON (for agent parsing)
"""

import subprocess
import shutil
import sys
import os
import json
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# Tool Registry: every tool the framework uses
# ═══════════════════════════════════════════════════════════════

TOOLS = {
    # ── Core (required for any phase) ──
    "adb": {
        "check": "adb version",
        "required": True,
        "phases": ["all"],
        "install": "brew install android-platform-tools OR install Android SDK",
        "purpose": "Device communication",
    },
    "python3": {
        "check": "python3 --version",
        "required": True,
        "phases": ["all"],
        "install": "brew install python@3.12",
        "purpose": "Script execution",
    },

    # ── Static Analysis ──
    "jadx": {
        "check": "jadx --version",
        "required": True,
        "phases": ["static"],
        "install": "brew install jadx",
        "purpose": "Java decompilation",
    },
    "apktool": {
        "check": "apktool --version",
        "required": True,
        "phases": ["static"],
        "install": "brew install apktool",
        "purpose": "APK decompilation (smali + resources)",
    },
    "aapt": {
        "check": "aapt version",
        "required": True,
        "phases": ["static"],
        "install": "Install via Android SDK build-tools",
        "purpose": "APK metadata extraction",
        "paths": ["~/Library/Android/sdk/build-tools/*/aapt"],
    },
    "d8": {
        "check": "d8 --version",
        "required": False,
        "phases": ["static", "exploit"],
        "install": "Install via Android SDK build-tools",
        "purpose": "DEX compilation for PoC apps",
        "paths": ["~/Library/Android/sdk/build-tools/*/d8"],
    },

    # ── Secret Scanning ──
    "semgrep": {
        "check": "semgrep --version",
        "required": True,
        "phases": ["secrets"],
        "install": "brew install semgrep",
        "purpose": "Pattern-based secret detection",
    },
    "trufflehog": {
        "check": "trufflehog --version",
        "required": True,
        "phases": ["secrets"],
        "install": "brew install trufflehog OR go install github.com/trufflesecurity/trufflehog/v3@latest",
        "purpose": "Entropy-based secret detection",
    },
    "nuclei": {
        "check": "nuclei --version",
        "required": True,
        "phases": ["secrets"],
        "install": "brew install nuclei OR go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "purpose": "Template-based secret detection",
    },

    # ── Dynamic Analysis ──
    "frida": {
        "check": "frida --version",
        "required": True,
        "phases": ["dynamic"],
        "install": "pip3 install frida-tools",
        "purpose": "Runtime instrumentation",
    },
    "frida-ps": {
        "check": "frida-ps --version",
        "required": True,
        "phases": ["dynamic"],
        "install": "pip3 install frida-tools",
        "purpose": "Process listing on device",
    },
    "objection": {
        "check": "objection version",
        "required": False,
        "phases": ["dynamic"],
        "install": "pip3 install objection",
        "purpose": "Frida-based exploration (non-root)",
    },
    "pidcat": {
        "check": "pidcat --version",
        "required": False,
        "phases": ["dynamic"],
        "install": "pip3 install pidcat",
        "purpose": "Filtered logcat output",
    },
    "medusa": {
        "check": "medusa --help",
        "required": False,
        "phases": ["dynamic"],
        "install": "git clone https://github.com/Ch0pin/medusa.git && pip3 install -r requirements.txt",
        "purpose": "Modular Frida framework (100+ modules)",
    },

    # ── Reverse Engineering ──
    "ghidra": {
        "check": "ghidraRun --help",
        "required": False,
        "phases": ["native", "static"],
        "install": "brew install ghidra",
        "purpose": "Binary reverse engineering",
        "alt_check": "ls /opt/homebrew/Cellar/ghidra/*/libexec/support/analyzeHeadless",
    },

    # ── Native Fuzzing ──
    "nm": {
        "check": "nm --version",
        "required": True,
        "phases": ["native"],
        "install": "Included with Xcode Command Line Tools",
        "purpose": "Symbol listing for .so files",
    },
    "strings": {
        "check": "strings --version",
        "required": True,
        "phases": ["native"],
        "install": "Included with Xcode Command Line Tools",
        "purpose": "String extraction from binaries",
    },
    "objdump": {
        "check": "objdump --version",
        "required": False,
        "phases": ["native"],
        "install": "Included with Xcode Command Line Tools",
        "purpose": "Binary disassembly",
    },
    "readelf": {
        "check": "greadelf --version",
        "required": False,
        "phases": ["native"],
        "install": "brew install binutils (provides greadelf)",
        "purpose": "ELF binary analysis",
        "alt_names": ["greadelf", "readelf"],
    },
    "ndk-clang": {
        "check": "ls ~/Library/Android/sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang",
        "required": False,
        "phases": ["native"],
        "install": "Install Android NDK via SDK Manager",
        "purpose": "Cross-compilation for ARM64 harnesses",
        "shell_check": True,
    },

    # ── Network / Proxy ──
    "mitmproxy": {
        "check": "mitmproxy --version",
        "required": False,
        "phases": ["dynamic"],
        "install": "brew install mitmproxy",
        "purpose": "HTTPS traffic interception",
    },

    # ── Reporting ──
    "pandoc": {
        "check": "pandoc --version",
        "required": False,
        "phases": ["reporting"],
        "install": "brew install pandoc",
        "purpose": "Markdown to DOCX conversion",
    },
    "sqlite3": {
        "check": "sqlite3 --version",
        "required": False,
        "phases": ["dynamic"],
        "install": "Included with Android SDK platform-tools",
        "purpose": "Database analysis",
    },

    # ── Textual dashboard ──
    "textual": {
        "check": "python3 -c 'import textual'",
        "required": False,
        "phases": ["reporting"],
        "install": "pip3 install textual",
        "purpose": "Live TUI dashboard",
        "shell_check": True,
    },
}

# ═══════════════════════════════════════════════════════════════
# On-device tools (checked via adb)
# ═══════════════════════════════════════════════════════════════

DEVICE_TOOLS = {
    "frida-server": {
        "check": "su -c 'ls /data/local/tmp/frida-server*'",
        "required": True,
        "phases": ["dynamic"],
        "purpose": "Frida server on device",
    },
    "afl-fuzz": {
        "check": "ls /data/local/tmp/afl-fuzz",
        "required": False,
        "phases": ["native"],
        "purpose": "AFL++ fuzzer on device",
    },
    "afl-frida-trace": {
        "check": "ls /data/local/tmp/afl-frida-trace.so",
        "required": False,
        "phases": ["native"],
        "purpose": "AFL++ Frida mode library on device",
    },
}

# ═══════════════════════════════════════════════════════════════
# Custom scanner check
# ═══════════════════════════════════════════════════════════════

SCANNER_PATH = os.path.expanduser(
    "~/Documents/android-security-scanner/backend/scanner.py"
)
SCANNER_VENV = os.path.expanduser(
    "~/Documents/android-security-scanner/backend/venv/bin/python3"
)


def check_tool(name, info):
    """Check if a host tool is available."""
    # Try alternate names first
    for alt in info.get("alt_names", []):
        if shutil.which(alt):
            return True, alt

    # Try PATH lookup
    if not info.get("shell_check") and not info.get("paths"):
        binary = name
        if shutil.which(binary):
            return True, shutil.which(binary)

    # Try shell check (for complex paths or python imports)
    check_cmd = info["check"]
    if info.get("shell_check"):
        try:
            result = subprocess.run(
                check_cmd, shell=True, capture_output=True, timeout=10
            )
            return result.returncode == 0, check_cmd
        except:
            return False, None

    # Try glob paths
    for pattern in info.get("paths", []):
        import glob
        expanded = glob.glob(os.path.expanduser(pattern))
        if expanded:
            return True, expanded[0]

    # Try running the check command
    try:
        result = subprocess.run(
            check_cmd.split(), capture_output=True, timeout=10
        )
        return True, shutil.which(check_cmd.split()[0]) or check_cmd
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, None


def check_device_tool(device_id, name, info):
    """Check if a tool exists on the connected Android device."""
    try:
        cmd = ["adb", "-s", device_id, "shell", info["check"]]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except:
        return False


def check_device_connectivity(device_id):
    """Check if device is connected and responsive."""
    try:
        # Connect if IP:port
        if ":" in device_id:
            subprocess.run(
                ["adb", "connect", device_id],
                capture_output=True, timeout=10
            )

        result = subprocess.run(
            ["adb", "-s", device_id, "get-state"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() == "device"
    except:
        return False


def check_root(device_id):
    """Check if device is rooted."""
    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "su", "-c", "id"],
            capture_output=True, text=True, timeout=10,
        )
        return "uid=0" in result.stdout
    except:
        return False


def main():
    args = sys.argv[1:]
    phase_filter = None
    device_id = None
    output_json = False

    i = 0
    while i < len(args):
        if args[i] == "--phase" and i + 1 < len(args):
            phase_filter = args[i + 1]
            i += 2
        elif args[i] == "--device" and i + 1 < len(args):
            device_id = args[i + 1]
            i += 2
        elif args[i] == "--json":
            output_json = True
            i += 1
        else:
            i += 1

    results = {
        "host_tools": {},
        "device_tools": {},
        "scanner": {},
        "device": {},
        "summary": {},
    }

    # ── Check host tools ──
    if not output_json:
        print("=" * 60)
        print("  Android Pentest Agent — Preflight Check")
        print("=" * 60)
        print()

    passed = 0
    failed_required = 0
    failed_optional = 0
    total = 0

    for name, info in sorted(TOOLS.items()):
        phases = info["phases"]
        if phase_filter and phase_filter not in phases and "all" not in phases:
            continue

        total += 1
        available, path = check_tool(name, info)
        required = info["required"]
        status = "OK" if available else ("MISSING" if required else "optional, missing")

        results["host_tools"][name] = {
            "available": available,
            "required": required,
            "path": path,
            "purpose": info["purpose"],
            "phases": phases,
        }

        if available:
            passed += 1
            if not output_json:
                print(f"  [+] {name:<16} {path or 'found'}")
        elif required:
            failed_required += 1
            if not output_json:
                print(f"  [!] {name:<16} MISSING (required) — {info['install']}")
        else:
            failed_optional += 1
            if not output_json:
                print(f"  [-] {name:<16} missing (optional) — {info['install']}")

    # ── Check custom scanner ──
    if not output_json:
        print()
        print("— Custom Scanner —")

    scanner_ok = os.path.exists(SCANNER_PATH) and os.path.exists(SCANNER_VENV)
    results["scanner"] = {
        "available": scanner_ok,
        "path": SCANNER_PATH if scanner_ok else None,
        "venv": SCANNER_VENV if scanner_ok else None,
    }

    if not output_json:
        if scanner_ok:
            print(f"  [+] scanner.py      {SCANNER_PATH}")
            print(f"  [+] scanner venv    {SCANNER_VENV}")
        else:
            print(f"  [!] scanner         MISSING at {SCANNER_PATH}")

    # ── Check device ──
    if device_id:
        if not output_json:
            print()
            print(f"— Device: {device_id} —")

        connected = check_device_connectivity(device_id)
        rooted = check_root(device_id) if connected else False

        results["device"] = {
            "id": device_id,
            "connected": connected,
            "rooted": rooted,
        }

        if not output_json:
            print(f"  {'[+]' if connected else '[!]'} Connected: {connected}")
            print(f"  {'[+]' if rooted else '[-]'} Rooted: {rooted}")

        if connected:
            if not output_json:
                print()
                print("— On-Device Tools —")

            for name, info in DEVICE_TOOLS.items():
                phases = info["phases"]
                if phase_filter and phase_filter not in phases:
                    continue

                available = check_device_tool(device_id, name, info)
                results["device_tools"][name] = {
                    "available": available,
                    "required": info["required"],
                    "purpose": info["purpose"],
                }

                if not output_json:
                    if available:
                        print(f"  [+] {name:<20} found on device")
                    elif info["required"]:
                        print(f"  [!] {name:<20} MISSING on device")
                    else:
                        print(f"  [-] {name:<20} missing on device (optional)")

    # ── Summary ──
    ready = failed_required == 0 and scanner_ok
    results["summary"] = {
        "total_checked": total,
        "passed": passed,
        "failed_required": failed_required,
        "failed_optional": failed_optional,
        "scanner_available": scanner_ok,
        "ready": ready,
    }

    if output_json:
        print(json.dumps(results, indent=2))
    else:
        print()
        print("=" * 60)
        print(f"  Passed: {passed}/{total}  |  Required missing: {failed_required}  |  Optional missing: {failed_optional}")
        if ready:
            print("  Status: READY")
        else:
            print("  Status: NOT READY — install required tools above")
        print("=" * 60)

    sys.exit(0 if ready else 1)


if __name__ == "__main__":
    main()
