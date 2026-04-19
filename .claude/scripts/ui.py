#!/usr/bin/env python3
"""
Android UI hierarchy parser for autonomous agent interaction.
Dumps the accessibility tree via uiautomator, parses it into a flat
numbered list of interactive elements that an LLM can reason about.

Usage:
    python3 ui.py                    # dump current screen
    python3 ui.py -s <serial>        # specify device serial
    python3 ui.py --screenshot       # also capture screenshot

Output format:
    screen_size=1080x2340
    package=com.example.app
    activity=com.example.app/.MainActivity
    elements=12
    [1] "Sign In" btn @ (540,1200) bounds=[380,1150][700,1250] clickable
    [2] "Username" input @ (540,800) bounds=[100,750][980,850] focusable
    ...

The agent picks [N] and taps the center coordinates.
"""

import subprocess
import sys
import re
import xml.etree.ElementTree as ET
from collections import namedtuple

Element = namedtuple("Element", ["index", "label", "etype", "cx", "cy", "bounds", "flags", "resource_id", "class_name"])

TYPE_MAP = {
    "Button": "btn",
    "ImageButton": "btn",
    "FloatingActionButton": "btn",
    "MaterialButton": "btn",
    "AppCompatButton": "btn",
    "EditText": "input",
    "AutoCompleteTextView": "input",
    "TextInputEditText": "input",
    "AppCompatEditText": "input",
    "SearchView": "input",
    "TextView": "text",
    "AppCompatTextView": "text",
    "ImageView": "img",
    "AppCompatImageView": "img",
    "Switch": "switch",
    "SwitchCompat": "switch",
    "ToggleButton": "switch",
    "CheckBox": "check",
    "AppCompatCheckBox": "check",
    "RadioButton": "radio",
    "Spinner": "dropdown",
    "RecyclerView": "list",
    "ListView": "list",
    "ScrollView": "scroll",
    "ViewPager": "pager",
    "TabLayout": "tabs",
    "TabView": "tab",
    "NavigationBarView": "nav",
    "BottomNavigationView": "nav",
    "Toolbar": "toolbar",
    "WebView": "webview",
    "ProgressBar": "progress",
    "SeekBar": "slider",
}

def run_adb(cmd, serial=None):
    prefix = ["adb"]
    if serial:
        prefix += ["-s", serial]
    result = subprocess.run(prefix + cmd, capture_output=True, text=True, timeout=15)
    return result.stdout.strip()

def get_screen_info(serial=None):
    size = run_adb(["shell", "wm", "size"], serial)
    match = re.search(r"(\d+x\d+)", size)
    screen_size = match.group(1) if match else "unknown"

    activity_info = run_adb(["shell", "dumpsys", "activity", "activities"], serial)
    package = "unknown"
    activity = "unknown"
    for line in activity_info.split("\n"):
        if "mResumedActivity" in line or "topResumedActivity" in line:
            match = re.search(r"u0 ([^\s/]+)/([^\s}]+)", line)
            if match:
                package = match.group(1)
                activity = match.group(2)
            break
    return screen_size, package, activity

def dump_hierarchy(serial=None):
    run_adb(["shell", "uiautomator", "dump", "/sdcard/window_dump.xml"], serial)
    xml_str = run_adb(["shell", "cat", "/sdcard/window_dump.xml"], serial)
    # Fix malformed XML (bare & characters)
    xml_str = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", xml_str)
    return xml_str

def parse_bounds(bounds_str):
    match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
    if not match:
        return None
    x1, y1, x2, y2 = int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))
    cx = (x1 + x2) // 2
    cy = (y1 + y2) // 2
    return x1, y1, x2, y2, cx, cy

def get_short_class(class_name):
    if not class_name:
        return "view"
    short = class_name.split(".")[-1]
    return TYPE_MAP.get(short, short.lower()[:12])

def get_label(node):
    text = node.get("text", "").strip()
    if text:
        return text[:60]
    desc = node.get("content-desc", "").strip()
    if desc:
        return desc[:60]
    rid = node.get("resource-id", "")
    if rid:
        return rid.split("/")[-1][:40]
    return get_short_class(node.get("class", ""))

def extract_elements(xml_str):
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return []

    elements = []
    seen_positions = set()

    # Pass 1: clickable elements
    for node in root.iter("node"):
        if node.get("clickable") != "true":
            continue
        bounds_str = node.get("bounds", "")
        parsed = parse_bounds(bounds_str)
        if not parsed:
            continue
        x1, y1, x2, y2, cx, cy = parsed
        # Skip tiny elements (likely invisible)
        if (x2 - x1) < 10 or (y2 - y1) < 10:
            continue
        # Spatial dedup (30px threshold)
        key = (cx // 30, cy // 30)
        if key in seen_positions:
            continue
        seen_positions.add(key)

        label = get_label(node)
        etype = get_short_class(node.get("class", ""))
        rid = node.get("resource-id", "")
        elements.append({
            "label": label, "type": etype,
            "cx": cx, "cy": cy, "bounds": bounds_str,
            "flags": "clickable", "resource_id": rid,
            "class": node.get("class", ""),
        })

    # Pass 2: focusable elements not already captured
    for node in root.iter("node"):
        if node.get("focusable") != "true" or node.get("clickable") == "true":
            continue
        bounds_str = node.get("bounds", "")
        parsed = parse_bounds(bounds_str)
        if not parsed:
            continue
        x1, y1, x2, y2, cx, cy = parsed
        if (x2 - x1) < 10 or (y2 - y1) < 10:
            continue
        key = (cx // 30, cy // 30)
        if key in seen_positions:
            continue
        seen_positions.add(key)

        label = get_label(node)
        etype = get_short_class(node.get("class", ""))
        rid = node.get("resource-id", "")
        elements.append({
            "label": label, "type": etype,
            "cx": cx, "cy": cy, "bounds": bounds_str,
            "flags": "focusable", "resource_id": rid,
            "class": node.get("class", ""),
        })

    return elements

def main():
    serial = None
    do_screenshot = False
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "-s" and i < len(sys.argv) - 1:
            serial = sys.argv[i + 1]
        elif arg == "--screenshot":
            do_screenshot = True

    screen_size, package, activity = get_screen_info(serial)
    xml_str = dump_hierarchy(serial)
    elements = extract_elements(xml_str)

    print(f"screen_size={screen_size}")
    print(f"package={package}")
    print(f"activity={activity}")
    print(f"elements={len(elements)}")

    for i, el in enumerate(elements, 1):
        print(f'[{i}] "{el["label"]}" {el["type"]} @ ({el["cx"]},{el["cy"]}) bounds={el["bounds"]} {el["flags"]}')

    if do_screenshot:
        run_adb(["shell", "screencap", "-p", "/sdcard/ui_screen.png"], serial)
        run_adb(["pull", "/sdcard/ui_screen.png", "."], serial)
        print("screenshot=ui_screen.png")

if __name__ == "__main__":
    main()
