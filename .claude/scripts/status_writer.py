#!/usr/bin/env python3
"""
Status writer for Android Pentest Agent dashboard.
CLI tool that agents call to update the shared status.json file.

Usage:
    python3 status_writer.py --status-file <path> --init <package> <version> <device> <model> <android_ver> <rooted>
    python3 status_writer.py --status-file <path> --set-status "dynamic analysis"
    python3 status_writer.py --status-file <path> --set-stage static running "scanning with 4 engines"
    python3 status_writer.py --status-file <path> --add-finding CRITICAL "Intent redirection" confirmed
    python3 status_writer.py --status-file <path> --add-activity "Exported activity launched"
    python3 status_writer.py --status-file <path> --add-note "Crash confirmed - SIGSEGV"
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

STAGE_NAMES = [
    "Static Analysis",
    "Dynamic Analysis",
    "Native Fuzzing",
    "Exploit Validation",
    "Reporting",
]

STAGE_KEYS = ["static", "dynamic", "native", "exploit", "reporting"]


def now_str():
    return datetime.now().strftime("%I:%M %p")


def load_status(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {
        "target": {},
        "status": "initializing",
        "stages": [
            {"name": n, "state": "queued", "detail": ""}
            for n in STAGE_NAMES
        ],
        "findings": [],
        "activity": [],
        "notes": [],
        "stats": {
            "total_findings": 0,
            "confirmed": 0,
            "validating": 0,
            "rejected": 0,
        },
    }


def save_status(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def cmd_init(status, args):
    status["target"] = {
        "package": args[0],
        "version": args[1] if len(args) > 1 else "",
        "device_id": args[2] if len(args) > 2 else "",
        "device_model": args[3] if len(args) > 3 else "",
        "android_version": args[4] if len(args) > 4 else "",
        "rooted": args[5].lower() in ("true", "yes", "1") if len(args) > 5 else False,
    }
    status["status"] = "initialized"
    status["activity"].append(
        {"time": now_str(), "message": f"Pentest initialized for {args[0]}"}
    )


def cmd_set_status(status, args):
    status["status"] = " ".join(args)


def cmd_set_stage(status, args):
    key = args[0].lower()
    state = args[1] if len(args) > 1 else "running"
    detail = " ".join(args[2:]) if len(args) > 2 else ""

    if key in STAGE_KEYS:
        idx = STAGE_KEYS.index(key)
    else:
        for i, s in enumerate(status["stages"]):
            if key in s["name"].lower():
                idx = i
                break
        else:
            print(f"Unknown stage: {key}", file=sys.stderr)
            return

    status["stages"][idx]["state"] = state
    status["stages"][idx]["detail"] = detail

    name = status["stages"][idx]["name"]
    status["activity"].append(
        {"time": now_str(), "message": f"{name}: {state} - {detail}" if detail else f"{name}: {state}"}
    )


def cmd_add_finding(status, args):
    severity = args[0].upper()
    title = args[1] if len(args) > 1 else ""
    finding_status = args[2] if len(args) > 2 else "candidate"

    status["findings"].append({
        "severity": severity,
        "title": title,
        "status": finding_status,
        "timestamp": now_str(),
    })

    stats = status["stats"]
    stats["total_findings"] = len(status["findings"])
    stats["confirmed"] = sum(1 for f in status["findings"] if f["status"] == "confirmed")
    stats["validating"] = sum(1 for f in status["findings"] if f["status"] == "validating")
    stats["rejected"] = sum(1 for f in status["findings"] if f["status"] == "rejected")


def cmd_update_finding(status, args):
    title_fragment = args[0]
    new_status = args[1] if len(args) > 1 else "confirmed"

    for f in status["findings"]:
        if title_fragment.lower() in f["title"].lower():
            f["status"] = new_status
            break

    stats = status["stats"]
    stats["confirmed"] = sum(1 for f in status["findings"] if f["status"] == "confirmed")
    stats["validating"] = sum(1 for f in status["findings"] if f["status"] == "validating")
    stats["rejected"] = sum(1 for f in status["findings"] if f["status"] == "rejected")


def cmd_add_activity(status, args):
    status["activity"].append({
        "time": now_str(),
        "message": " ".join(args),
    })
    # Keep last 50 entries
    if len(status["activity"]) > 50:
        status["activity"] = status["activity"][-50:]


def cmd_add_note(status, args):
    status["notes"].append({
        "time": now_str(),
        "message": " ".join(args),
    })
    if len(status["notes"]) > 20:
        status["notes"] = status["notes"][-20:]


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)

    status_file = None
    i = 0
    while i < len(args):
        if args[i] == "--status-file":
            status_file = args[i + 1]
            args = args[:i] + args[i + 2:]
            break
        i += 1

    if not status_file:
        print("Error: --status-file required", file=sys.stderr)
        sys.exit(1)

    status = load_status(status_file)

    i = 0
    while i < len(args):
        cmd = args[i]
        # Collect args until next --flag
        cmd_args = []
        j = i + 1
        while j < len(args) and not args[j].startswith("--"):
            cmd_args.append(args[j])
            j += 1

        if cmd == "--init":
            cmd_init(status, cmd_args)
        elif cmd == "--set-status":
            cmd_set_status(status, cmd_args)
        elif cmd == "--set-stage":
            cmd_set_stage(status, cmd_args)
        elif cmd == "--add-finding":
            cmd_add_finding(status, cmd_args)
        elif cmd == "--update-finding":
            cmd_update_finding(status, cmd_args)
        elif cmd == "--add-activity":
            cmd_add_activity(status, cmd_args)
        elif cmd == "--add-note":
            cmd_add_note(status, cmd_args)
        else:
            print(f"Unknown command: {cmd}", file=sys.stderr)

        i = j

    save_status(status_file, status)


if __name__ == "__main__":
    main()
