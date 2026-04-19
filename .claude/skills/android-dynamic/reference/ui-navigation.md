# UI Navigation for Autonomous Testing

How the agent navigates Android app screens during dynamic analysis.

## Architecture: Observe-Act Loop

```
┌─────────┐     ┌──────────┐     ┌─────────┐
│ OBSERVE  │────>│  DECIDE  │────>│   ACT   │
│ ui.py    │     │  (agent) │     │  adb    │
│ screen   │     │          │     │  input  │
└─────────┘     └──────────┘     └─────────┘
      ^                                │
      └────────────────────────────────┘
```

Each cycle: dump UI -> parse elements -> agent picks action -> execute via ADB -> repeat.

## Step 1: Observe (Screen State)

### UI Hierarchy Dump
```bash
# Run the ui.py parser
python3 .claude/scripts/ui.py -s <device_serial>
```

Output:
```
screen_size=1080x2340
package=com.example.app
activity=com.example.app/.LoginActivity
elements=8
[1] "Username" input @ (540,600) bounds=[100,550][980,650] focusable
[2] "Password" input @ (540,750) bounds=[100,700][980,800] focusable
[3] "Sign In" btn @ (540,900) bounds=[300,860][780,940] clickable
[4] "Forgot Password?" text @ (540,1000) bounds=[350,980][730,1020] clickable
[5] "Sign Up" text @ (540,1100) bounds=[400,1080][680,1120] clickable
[6] "settings" img @ (980,100) bounds=[940,60][1020,140] clickable
```

### Screenshot Fallback (for non-standard UIs)
```bash
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png
# Agent analyzes screenshot visually
```

Use screenshot when:
- WebView content (not in accessibility tree)
- Flutter/Unity/game apps
- Custom-rendered UI
- ui.py returns `elements=0`

### Get Current Activity
```bash
adb shell dumpsys activity activities | grep "mResumedActivity"
# Or
adb shell dumpsys window | grep mCurrentFocus
```

## Step 2: Act (ADB Input Commands)

### Tap Element
```bash
# Tap element [3] at coordinates (540,900)
adb shell input tap 540 900
```

### Enter Text
```bash
# First tap the input field, then type
adb shell input tap 540 600
adb shell input text "username"

# For passwords (mask in logs)
adb shell input tap 540 750
adb shell input text "password123"
```

### Special Characters in Text
```bash
# Spaces: use %s
adb shell input text "hello%sworld"

# Special chars: use keyevents
adb shell input keyevent 74  # @
```

### Navigation Keys
```bash
adb shell input keyevent 4    # BACK
adb shell input keyevent 3    # HOME
adb shell input keyevent 187  # APP_SWITCH (recents)
adb shell input keyevent 66   # ENTER
adb shell input keyevent 61   # TAB
adb shell input keyevent 111  # ESCAPE
adb shell input keyevent 82   # MENU
```

### Scrolling
```bash
# Scroll down
adb shell input swipe 540 1500 540 500 300

# Scroll up
adb shell input swipe 540 500 540 1500 300

# Scroll left (next page)
adb shell input swipe 800 1000 200 1000 300

# Scroll right (previous page)
adb shell input swipe 200 1000 800 1000 300
```

### Long Press
```bash
# Long press at coordinates (hold for 1000ms)
adb shell input swipe 540 900 540 900 1000
```

## Step 3: Common Workflows

### Login Flow
```bash
# 1. Observe current screen
python3 .claude/scripts/ui.py

# 2. If login screen detected:
# Tap username field
adb shell input tap <username_cx> <username_cy>
adb shell input text "testuser"

# Tap password field
adb shell input tap <password_cx> <password_cy>
adb shell input text "testpass123"

# Tap sign in button
adb shell input tap <signin_cx> <signin_cy>

# 3. Wait for transition
sleep 2

# 4. Observe new screen
python3 .claude/scripts/ui.py
```

### Navigate to Specific Screen
```bash
# Option 1: Via UI interaction (follow menu path)
# Option 2: Direct activity launch (faster, for exported activities)
adb shell am start -n <pkg>/<activity>

# Option 3: Via deep link (if available)
adb shell am start -a android.intent.action.VIEW -d "myapp://settings"
```

### Handle Dialogs/Popups
```bash
# Observe to detect dialog
python3 .claude/scripts/ui.py

# Common dismiss patterns:
adb shell input keyevent 4                    # BACK to dismiss
adb shell input tap <ok_cx> <ok_cy>          # Tap OK/Allow
adb shell input tap <deny_cx> <deny_cy>      # Tap Deny/Cancel

# Permission dialogs
adb shell input tap 540 1400  # "Allow" is usually bottom-center
```

### Explore App Screens Systematically
```bash
# 1. Launch app
adb shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1
sleep 3

# 2. Dump initial screen
python3 .claude/scripts/ui.py

# 3. For each clickable element, tap and record the new screen
# This maps the app's navigation graph

# 4. Go back and try next element
adb shell input keyevent 4  # BACK
```

## Tips for the Agent

### Timing
- Wait 1-2 seconds after tapping before observing (animations, network calls)
- Use `sleep 2` between act and observe
- For slow screens (loading data), wait 3-5 seconds

### State Tracking
- Record which screens you've visited (activity names)
- Track which elements you've tested on each screen
- Note if BACK returns to the expected previous screen

### When UI Dump Fails
1. Try screenshot + vision analysis
2. Try direct activity launch via ADB
3. Try deep links if known from static analysis
4. Check if app has a WebView (WebView content won't appear in accessibility tree)

### Handling WebViews
```bash
# Enable WebView debugging (if app allows)
# Then use chrome://inspect in Chrome
# Or use Frida to hook WebView methods:
# webviews/hook_webviews Medusa module captures all loadUrl calls
```

### Coordinating with Medusa
Run Medusa in parallel while navigating:
1. Start Medusa with intent/network/storage modules
2. Navigate the app via ui.py + ADB
3. Medusa captures all background activity (intents, API calls, crypto, file I/O)
4. Correlate UI actions with Medusa output

## Alternative: Direct Component Testing (No UI Needed)

For pentesting, you often don't need to navigate the UI at all:

```bash
# Test exported activities directly
adb shell am start -n <pkg>/<activity> --es "key" "payload"

# Test content providers
adb shell content query --uri content://<authority>/path

# Test broadcast receivers
adb shell am broadcast -a <action> --es "data" "payload"

# Test deep links
adb shell am start -a android.intent.action.VIEW -d "scheme://host/path"

# Test services
adb shell am startservice -n <pkg>/<service>
```

UI navigation is primarily needed for:
- Login/authentication flows
- Reaching screens that require prior state (e.g., complete onboarding first)
- Testing user-facing security features (biometric, PIN)
- Discovering dynamically loaded content
- Capturing runtime behavior during normal app usage
