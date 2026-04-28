#!/bin/bash
# Multi-tool secret scanner for Android APKs
# Runs semgrep + trufflehog + nuclei deterministically
# Claude's job is ONLY AI validation of the combined output
#
# Usage: ./secret_scanner.sh <decompiled_sources_dir> <output_dir> [apk_path]
#
# Output: <output_dir>/secrets_combined.json (merged findings from all tools)

set -euo pipefail

SOURCES_DIR="$1"
OUTPUT_DIR="$2"
APK_PATH="${3:-}"

mkdir -p "$OUTPUT_DIR"

echo "=== Secret Scanner: Multi-Tool Pipeline ==="
echo "Sources: $SOURCES_DIR"
echo "Output: $OUTPUT_DIR"
echo ""

# Track which tools ran successfully
TOOLS_RUN=0
TOOLS_FAILED=0

# ============================================================
# Tool 1: Semgrep (pattern-based)
# ============================================================
echo "[1/4] Running Semgrep..."
if command -v semgrep &>/dev/null; then
    semgrep --config "p/secrets" \
        --json \
        --output "$OUTPUT_DIR/secrets_semgrep.json" \
        --quiet \
        "$SOURCES_DIR" 2>/dev/null || true

    # Also scan resources if they exist
    RESOURCES_DIR="$(dirname "$SOURCES_DIR")/resources"
    if [ -d "$RESOURCES_DIR" ]; then
        semgrep --config "p/secrets" \
            --json \
            --output "$OUTPUT_DIR/secrets_semgrep_resources.json" \
            --quiet \
            "$RESOURCES_DIR" 2>/dev/null || true
    fi

    SEMGREP_COUNT=$(python3 -c "
import json, sys
try:
    with open('$OUTPUT_DIR/secrets_semgrep.json') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except: print(0)
" 2>/dev/null)
    echo "  Semgrep: $SEMGREP_COUNT findings"
    TOOLS_RUN=$((TOOLS_RUN + 1))
else
    echo "  Semgrep: NOT INSTALLED (skipped)"
    TOOLS_FAILED=$((TOOLS_FAILED + 1))
fi

# ============================================================
# Tool 2: TruffleHog (entropy-based)
# ============================================================
echo "[2/4] Running TruffleHog..."
if command -v trufflehog &>/dev/null; then
    trufflehog filesystem "$SOURCES_DIR" \
        --json \
        --no-update \
        > "$OUTPUT_DIR/secrets_trufflehog.json" 2>/dev/null || true

    # Also scan resources
    if [ -d "$RESOURCES_DIR" ]; then
        trufflehog filesystem "$RESOURCES_DIR" \
            --json \
            --no-update \
            >> "$OUTPUT_DIR/secrets_trufflehog.json" 2>/dev/null || true
    fi

    TRUFFLEHOG_COUNT=$(wc -l < "$OUTPUT_DIR/secrets_trufflehog.json" 2>/dev/null | tr -d ' ')
    echo "  TruffleHog: $TRUFFLEHOG_COUNT findings"
    TOOLS_RUN=$((TOOLS_RUN + 1))
else
    echo "  TruffleHog: NOT INSTALLED (skipped)"
    TOOLS_FAILED=$((TOOLS_FAILED + 1))
fi

# ============================================================
# Tool 3: Nuclei (template-based)
# ============================================================
echo "[3/4] Running Nuclei..."
if command -v nuclei &>/dev/null; then
    # Nuclei file scanning with exposure/key templates
    find "$SOURCES_DIR" -type f \( -name "*.java" -o -name "*.xml" -o -name "*.json" -o -name "*.properties" \) \
        > "$OUTPUT_DIR/nuclei_targets.txt" 2>/dev/null

    if [ -s "$OUTPUT_DIR/nuclei_targets.txt" ]; then
        nuclei -l "$OUTPUT_DIR/nuclei_targets.txt" \
            -t http/exposures/ -t file/ \
            -jsonl \
            -output "$OUTPUT_DIR/secrets_nuclei.json" \
            -silent 2>/dev/null || true
    fi

    NUCLEI_COUNT=$(wc -l < "$OUTPUT_DIR/secrets_nuclei.json" 2>/dev/null | tr -d ' ' || echo 0)
    echo "  Nuclei: $NUCLEI_COUNT findings"
    TOOLS_RUN=$((TOOLS_RUN + 1))
else
    echo "  Nuclei: NOT INSTALLED (skipped)"
    TOOLS_FAILED=$((TOOLS_FAILED + 1))
fi

# ============================================================
# Tool 4: Native strings + resource grep (always available)
# ============================================================
echo "[4/4] Scanning native libraries and resources..."

# Scan .so files for embedded secrets
if [ -n "$APK_PATH" ] && [ -f "$APK_PATH" ]; then
    NATIVE_DIR="$OUTPUT_DIR/native_libs"
    mkdir -p "$NATIVE_DIR"
    unzip -o "$APK_PATH" "lib/*.so" -d "$NATIVE_DIR" 2>/dev/null || true

    > "$OUTPUT_DIR/secrets_native.txt"
    find "$NATIVE_DIR" -name "*.so" 2>/dev/null | while read -r so; do
        strings "$so" | grep -inE \
            'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|ghp_[a-zA-Z0-9]{36}|-----BEGIN.*(PRIVATE|RSA|EC).*KEY|api[_-]?key\s*[:=]|secret[_-]?key\s*[:=]|password\s*[:=]' \
            | sed "s|^|[${so}] |" \
            >> "$OUTPUT_DIR/secrets_native.txt" 2>/dev/null || true
    done
    NATIVE_COUNT=$(wc -l < "$OUTPUT_DIR/secrets_native.txt" 2>/dev/null | tr -d ' ')
    echo "  Native strings: $NATIVE_COUNT matches"
else
    NATIVE_COUNT=0
    echo "  Native strings: skipped (no APK path provided)"
fi

# Scan resource files
> "$OUTPUT_DIR/secrets_resources.txt"
for pattern in "res/values/strings.xml" "assets/google-services.json" "assets/config.json" "assets/config.properties"; do
    TARGET="$(dirname "$SOURCES_DIR")/resources/$pattern"
    if [ -f "$TARGET" ]; then
        grep -inE 'api[_-]?key|secret|password|token|AKIA|AIza|sk_live|ghp_|-----BEGIN' "$TARGET" \
            | sed "s|^|[$pattern] |" \
            >> "$OUTPUT_DIR/secrets_resources.txt" 2>/dev/null || true
    fi
done

# BuildConfig
BUILDCONFIG=$(find "$SOURCES_DIR" -name "BuildConfig.java" -path "*/$( basename "$SOURCES_DIR")/*" 2>/dev/null | head -1)
if [ -n "$BUILDCONFIG" ] && [ -f "$BUILDCONFIG" ]; then
    grep -nE 'API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL' "$BUILDCONFIG" \
        | sed "s|^|[BuildConfig] |" \
        >> "$OUTPUT_DIR/secrets_resources.txt" 2>/dev/null || true
fi

# Non-key secrets
grep -rl 'eyJ[a-zA-Z0-9_-]\+\.eyJ[a-zA-Z0-9_-]\+' "$SOURCES_DIR" 2>/dev/null \
    | head -20 \
    | while read -r f; do
        grep -n 'eyJ[a-zA-Z0-9_-]\+\.eyJ[a-zA-Z0-9_-]\+' "$f" \
            | sed "s|^|[JWT:$f] |"
    done >> "$OUTPUT_DIR/secrets_resources.txt" 2>/dev/null || true

find "$(dirname "$SOURCES_DIR")" -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.key" 2>/dev/null \
    | sed 's|^|[PrivateKeyFile] |' \
    >> "$OUTPUT_DIR/secrets_resources.txt" 2>/dev/null || true

RESOURCE_COUNT=$(wc -l < "$OUTPUT_DIR/secrets_resources.txt" 2>/dev/null | tr -d ' ')
echo "  Resources/BuildConfig/JWTs/PrivKeys: $RESOURCE_COUNT matches"
TOOLS_RUN=$((TOOLS_RUN + 1))

# ============================================================
# Summary
# ============================================================
TOTAL=$((${SEMGREP_COUNT:-0} + ${TRUFFLEHOG_COUNT:-0} + ${NUCLEI_COUNT:-0} + ${NATIVE_COUNT:-0} + ${RESOURCE_COUNT:-0}))

echo ""
echo "=== Scan Complete ==="
echo "Tools run: $TOOLS_RUN/4 (failed: $TOOLS_FAILED)"
echo "Total raw findings: $TOTAL"
echo ""
echo "Output files:"
ls -la "$OUTPUT_DIR"/secrets_*.{json,txt} 2>/dev/null
echo ""
echo "Next step: AI validation (Claude reads these files, deduplicates, validates, verifies keys)"
