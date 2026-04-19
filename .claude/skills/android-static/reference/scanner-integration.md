# Scanner Integration Reference

## Invocation

```bash
/Users/gaurangbhatnagar/Documents/android-security-scanner/backend/venv/bin/python3 \
  /Users/gaurangbhatnagar/Documents/android-security-scanner/backend/scanner.py \
  <apk_path> \
  -o <output_path>/scanner_results.json \
  --work-dir <output_path>/work
```

### Options
| Flag | Description |
|---|---|
| `-o, --output FILE` | Output JSON path (default: `<apk>_results.json`) |
| `--html FILE` | HTML report path |
| `--work-dir DIR` | Working directory (preserves decompiled sources) |
| `--resume` | Resume incomplete scan (requires `--work-dir`) |

### Exit Codes
- `0` - Scan successful
- `1` - Analysis failed (required engine failed)
- `2` - Contract violation (abort)

## Output JSON Structure (Contract v0.4.0)

### Top Level
```json
{
  "metadata": { "apk": {...}, "scan": {...}, "versions": {...} },
  "engines": { "manifest": {...}, "pattern": {...}, "heuristic": {...}, "taint": {...} },
  "manifest": { "package_name": "...", "application": {...}, "components": {...} },
  "scanner": { "pipeline": [...], "coverage": {...}, "paths": {...} },
  "summary": { "total_findings": N, "by_severity": {...}, "by_authority": {...} }
}
```

### Key: manifest.components
```json
{
  "activities": [
    { "name": "com.example.MainActivity", "exported": true, "permission": null, "intent_filters": [...] }
  ],
  "services": [...],
  "broadcast_receivers": [...],
  "content_providers": [
    { "name": "com.example.MyProvider", "authority": "com.example.provider", "exported": true, "permission": null }
  ]
}
```

### Key: Finding Structure
```json
{
  "id": "MANIFEST_005",
  "title": "Activity exported without permission",
  "severity": "medium",
  "authority": "structural",
  "confidence": "certain",
  "category": "component_exposure",
  "evidence": { "manifest_path": "...", "declaration": "...", "observed_value": true },
  "remediation": "Set android:exported=\"false\" or add android:permission",
  "references": ["https://..."],
  "engine": "manifest",
  "code_snippets": [
    {
      "file": "com/example/SomeActivity.java",
      "start_line": 20,
      "end_line": 35,
      "lines": [ { "line": 20, "code": "...", "highlighted": true } ]
    }
  ]
}
```

### Key: scanner.paths
```json
{
  "apk": "/path/to/app.apk",
  "work_dir": "/tmp/scanner_xyz",
  "decompiled": "/tmp/scanner_xyz/decompiled",
  "sources": "/tmp/scanner_xyz/decompiled/sources",
  "manifest": "/tmp/scanner_xyz/decompiled/resources/AndroidManifest.xml"
}
```
Use `scanner.paths.sources` to locate decompiled Java source code for manual review.

## 4 Analysis Engines

| Engine | Authority | Required | What It Finds |
|---|---|---|---|
| manifest | structural | Yes | Exported components, dangerous perms, debug/backup flags |
| pattern | pattern | Yes | WebView misconfig, crypto weaknesses, data storage, PendingIntent |
| heuristic | heuristic | Yes | IPC reachability, crypto API misuse, network issues |
| taint | deterministic | No | Source-to-sink flows (SQL injection, data leaks, intent injection) |

## Parsing Tips

1. All findings are at `engines.<name>.output.findings[]`
2. Exported components: `manifest.components.activities/services/receivers/providers` where `exported == true`
3. Package name: `manifest.package_name`
4. Decompiled sources: `scanner.paths.sources` (use `--work-dir` to preserve)
5. Filter library findings: scanner already filters, but double-check `code_snippets[].file` starts with the base package path
