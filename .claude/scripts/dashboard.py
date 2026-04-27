#!/usr/bin/env python3
"""
Live TUI Dashboard for Android Pentest Agent.
Watches a status.json file and renders real-time progress.

Usage:
    python3 dashboard.py <status.json>
    python3 dashboard.py outputs/20260428_com.target.app/status.json

Requires: pip install textual
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static, Header, Footer, RichLog
from textual.reactive import reactive
from textual import on
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Group


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

STATUS_COLORS = {
    "confirmed": "green",
    "validating": "yellow",
    "candidate": "dim white",
    "rejected": "dim red",
}

STAGE_ICONS = {
    "completed": "[green]✓[/]",
    "running": "[yellow]●[/]",
    "queued": "[dim]○[/]",
    "skipped": "[dim]⊘[/]",
    "failed": "[red]✗[/]",
}


class StatusPanel(Static):
    """Top panel showing target info and overall status."""

    def render_status(self, data: dict) -> str:
        target = data.get("target", {})
        pkg = target.get("package", "unknown")
        ver = target.get("version", "")
        device = target.get("device_id", "")
        model = target.get("device_model", "")
        android_ver = target.get("android_version", "")
        rooted = target.get("rooted", False)
        status = data.get("status", "initializing")
        stats = data.get("stats", {})

        root_str = "rooted" if rooted else "not rooted"
        device_str = f"{device} ({model}, Android {android_ver}, {root_str})" if device else "no device"
        findings_str = f"{stats.get('total_findings', 0)} candidate · {stats.get('confirmed', 0)} confirmed"

        lines = [
            f"[bold white]Android Pentest Agent[/]  ·  [bold cyan]{pkg}[/] {ver}",
            f"Status: [bold yellow]● {status}[/]",
            f"Device: [dim]{device_str}[/]",
            f"Findings: {findings_str}",
        ]
        return "\n".join(lines)


class StagesPanel(Static):
    """Shows stage progress."""

    def render_stages(self, data: dict) -> str:
        stages = data.get("stages", [])
        lines = []
        for s in stages:
            icon = STAGE_ICONS.get(s["state"], "○")
            name = s["name"]
            state = s["state"]
            detail = s.get("detail", "")

            if state == "completed":
                style = "green"
            elif state == "running":
                style = "bold yellow"
            elif state == "skipped":
                style = "dim"
            elif state == "failed":
                style = "red"
            else:
                style = "dim white"

            detail_str = f" · {detail}" if detail else ""
            lines.append(f"  {icon} [{style}]{name:<22}[/] {state}{detail_str}")

        return "\n".join(lines) if lines else "  [dim]No stages yet[/]"


class FindingsPanel(Static):
    """Shows recent findings with severity colors."""

    def render_findings(self, data: dict) -> str:
        findings = data.get("findings", [])
        if not findings:
            return "  [dim]No findings yet[/]"

        # Show most recent 15
        recent = findings[-15:]
        lines = []
        for f in reversed(recent):
            sev = f.get("severity", "INFO")
            title = f.get("title", "")
            status = f.get("status", "candidate")
            sev_color = SEVERITY_COLORS.get(sev, "white")
            status_color = STATUS_COLORS.get(status, "dim white")
            lines.append(f"  [{sev_color}]{sev:<10}[/] {title:<55} [{status_color}]{status}[/]")

        return "\n".join(lines)


class ActivityPanel(Static):
    """Shows recent activity log."""

    def render_activity(self, data: dict) -> str:
        activity = data.get("activity", [])
        if not activity:
            return "  [dim]No activity yet[/]"

        recent = activity[-12:]
        lines = []
        for a in recent:
            time = a.get("time", "")
            msg = a.get("message", "")
            lines.append(f"  [dim]{time}[/]  {msg}")

        return "\n".join(lines)


class NotesPanel(Static):
    """Shows agent notes/commentary."""

    def render_notes(self, data: dict) -> str:
        notes = data.get("notes", [])
        if not notes:
            return "  [dim]Waiting for agent activity...[/]"

        recent = notes[-8:]
        lines = []
        for n in recent:
            time = n.get("time", "")
            msg = n.get("message", "")
            lines.append(f"  [dim]{time}[/]  [bold]{msg}[/]")

        return "\n".join(lines)


class PentestDashboard(App):
    """Live TUI Dashboard for Android Pentest Agent."""

    CSS = """
    Screen {
        layout: vertical;
        background: $surface;
    }
    #status-panel {
        height: auto;
        min-height: 5;
        padding: 1 2;
        border: solid $primary;
        margin: 0 1;
    }
    #stages-panel {
        height: auto;
        min-height: 6;
        padding: 1 2;
        border: solid $secondary;
        margin: 0 1;
    }
    #activity-panel {
        height: auto;
        min-height: 8;
        max-height: 14;
        padding: 1 2;
        border: solid $accent;
        margin: 0 1;
    }
    #findings-panel {
        height: auto;
        min-height: 6;
        max-height: 18;
        padding: 1 2;
        border: solid $warning;
        margin: 0 1;
    }
    #notes-panel {
        height: auto;
        min-height: 4;
        max-height: 10;
        padding: 1 2;
        border: solid $success;
        margin: 0 1;
    }
    .section-title {
        text-style: bold;
        color: $text-muted;
        margin-bottom: 1;
    }
    """

    TITLE = "Android Pentest Agent"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, status_file: str):
        super().__init__()
        self.status_file = status_file
        self._data = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static("[bold]— Status —[/]", classes="section-title"),
            StatusPanel(id="status-panel"),
            Static("[bold]— Stages —[/]", classes="section-title"),
            StagesPanel(id="stages-panel"),
            Static("[bold]— Activity —[/]", classes="section-title"),
            ActivityPanel(id="activity-panel"),
            Static("[bold]— Recent Findings —[/]", classes="section-title"),
            FindingsPanel(id="findings-panel"),
            Static("[bold]— Agent Notes —[/]", classes="section-title"),
            NotesPanel(id="notes-panel"),
        )
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(1.0, self._poll_status)
        self._poll_status()

    def _poll_status(self) -> None:
        try:
            if os.path.exists(self.status_file):
                mtime = os.path.getmtime(self.status_file)
                with open(self.status_file, "r") as f:
                    data = json.load(f)
                self._data = data
                self._update_panels(data)
        except (json.JSONDecodeError, IOError):
            pass  # File being written, skip this tick

    def _update_panels(self, data: dict) -> None:
        status_panel = self.query_one("#status-panel", StatusPanel)
        status_panel.update(status_panel.render_status(data))

        stages_panel = self.query_one("#stages-panel", StagesPanel)
        stages_panel.update(stages_panel.render_stages(data))

        activity_panel = self.query_one("#activity-panel", ActivityPanel)
        activity_panel.update(activity_panel.render_activity(data))

        findings_panel = self.query_one("#findings-panel", FindingsPanel)
        findings_panel.update(findings_panel.render_findings(data))

        notes_panel = self.query_one("#notes-panel", NotesPanel)
        notes_panel.update(notes_panel.render_notes(data))

        # Update title with status
        pkg = data.get("target", {}).get("package", "")
        status = data.get("status", "")
        if pkg:
            self.title = f"Android Pentest Agent · {pkg} · {status}"

    def action_refresh(self) -> None:
        self._poll_status()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dashboard.py <status.json>")
        print("       python3 dashboard.py outputs/20260428_com.target.app/status.json")
        sys.exit(1)

    status_file = sys.argv[1]

    if not os.path.exists(status_file):
        # Create empty status file so dashboard can start
        os.makedirs(os.path.dirname(status_file) or ".", exist_ok=True)
        with open(status_file, "w") as f:
            json.dump({
                "target": {},
                "status": "waiting for agent...",
                "stages": [
                    {"name": n, "state": "queued", "detail": ""}
                    for n in ["Static Analysis", "Dynamic Analysis",
                              "Native Fuzzing", "Exploit Validation", "Reporting"]
                ],
                "findings": [],
                "activity": [],
                "notes": [],
                "stats": {"total_findings": 0, "confirmed": 0, "validating": 0, "rejected": 0},
            }, f, indent=2)

    app = PentestDashboard(status_file)
    app.run()


if __name__ == "__main__":
    main()
