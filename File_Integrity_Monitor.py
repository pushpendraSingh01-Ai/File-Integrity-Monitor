"""
File Integrity Monitor (FIM) — Streamlit Web Dashboard
=======================================================
A cybersecurity tool that detects unauthorised changes to files inside a
monitored directory by comparing SHA-256 hashes against a saved baseline.

Features:
  - SHA-256 baseline generation & integrity scanning
  - Scan History Log  (scan_history.json)
  - Bar Chart visualisation of scan results over time
  - Auto-Scan Watch Mode (continuous monitoring)

Run:
    pip install streamlit
    streamlit run File_Integrity_Monitor.py
"""

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

# ─── Constants ────────────────────────────────────────────────────────────────
BASELINE_FILE    = "baseline.json"
HISTORY_FILE     = "scan_history.json"
CHUNK_SIZE       = 65_536   # 64 KB — efficient for large files
HASH_PREVIEW_LEN = 16       # Characters of hash shown in the table
MAX_HISTORY      = 50       # Maximum scan records kept in history


# ─── Core hashing & I/O helpers ───────────────────────────────────────────────

def compute_sha256(filepath: str) -> str | None:
    """
    Compute the SHA-256 hash of a file by reading it in binary chunks.

    Reading in chunks avoids loading the entire file into memory, which is
    important for large files. Returns None if the file cannot be read
    (e.g. permission denied).
    """
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def scan_directory(directory: str) -> dict[str, str]:
    """
    Recursively walk *directory* and return a dict of
    ``{ relative_path_string: sha256_hex }`` for every readable file.

    Relative paths use forward-slashes so the baseline is portable across
    operating systems.
    """
    results: dict[str, str] = {}
    base = Path(directory)

    for path in base.rglob("*"):
        if path.is_file():
            file_hash = compute_sha256(str(path))
            if file_hash is not None:
                # Store relative path with forward slashes for portability
                relative = path.relative_to(base).as_posix()
                results[relative] = file_hash

    return results


def load_baseline(baseline_path: str) -> dict[str, str]:
    """Load the saved baseline from *baseline_path* and return it as a dict.
    Returns an empty dict if the file does not exist or is malformed."""
    try:
        with open(baseline_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_baseline(data: dict[str, str], baseline_path: str) -> None:
    """Serialise *data* to *baseline_path* as pretty-printed JSON."""
    with open(baseline_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def shorten(hash_str: str | None, length: int = HASH_PREVIEW_LEN) -> str:
    """Return the first *length* characters of *hash_str* with an ellipsis,
    or '—' when the value is None / empty."""
    if not hash_str:
        return "—"
    return hash_str[:length] + "…"


# ─── Comparison logic ─────────────────────────────────────────────────────────

def compare_hashes(
    baseline: dict[str, str],
    current: dict[str, str],
) -> list[dict]:
    """
    Compare *current* hashes against the saved *baseline*.

    Returns a list of result-row dicts with keys:
        file        – relative file path
        status      – "Clean" | "Modified" | "Added" | "Deleted"
        orig_hash   – hash stored in baseline (None for Added)
        curr_hash   – hash from latest scan   (None for Deleted)
        timestamp   – datetime string of when the check ran
    """
    rows: list[dict] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    all_files = set(baseline) | set(current)

    for filepath in sorted(all_files):
        orig = baseline.get(filepath)
        curr = current.get(filepath)

        if orig is None:
            status = "Added"
        elif curr is None:
            status = "Deleted"
        elif orig != curr:
            status = "Modified"
        else:
            status = "Clean"

        rows.append(
            {
                "file":      filepath,
                "status":    status,
                "orig_hash": orig,
                "curr_hash": curr,
                "timestamp": now,
            }
        )

    return rows


# ─── Scan History helpers ──────────────────────────────────────────────────────

def load_history(history_path: str) -> list[dict]:
    """Load the scan history list from *history_path*.
    Returns an empty list if the file does not exist or is malformed."""
    try:
        with open(history_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def append_history(results: list[dict], history_path: str, directory: str) -> None:
    """
    Append a summary of the current scan to *history_path*.

    Each history entry stores:
        timestamp  – when the scan ran
        directory  – which folder was scanned
        total      – total files in scope
        clean      – count of clean files
        modified   – count of modified files
        added      – count of added files
        deleted    – count of deleted files
    """
    history = load_history(history_path)

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "directory": directory,
        "total":     len(results),
        "clean":     sum(1 for r in results if r["status"] == "Clean"),
        "modified":  sum(1 for r in results if r["status"] == "Modified"),
        "added":     sum(1 for r in results if r["status"] == "Added"),
        "deleted":   sum(1 for r in results if r["status"] == "Deleted"),
    }

    history.append(entry)

    # Keep only the most recent MAX_HISTORY entries to avoid unbounded growth
    history = history[-MAX_HISTORY:]

    with open(history_path, "w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=2)


# ─── UI helper components ──────────────────────────────────────────────────────

STATUS_ICON = {
    "Clean":    "🟢",
    "Modified": "🔴",
    "Added":    "🟡",
    "Deleted":  "⚪",
}

STATUS_COLOR = {
    "Clean":    "#1a7f37",   # dark green
    "Modified": "#cf222e",   # red
    "Added":    "#9a6700",   # amber
    "Deleted":  "#57606a",   # grey
}

STATUS_BG = {
    "Clean":    "#dafbe1",
    "Modified": "#ffebe9",
    "Added":    "#fff8c5",
    "Deleted":  "#f6f8fa",
}


def render_status_badge(status: str) -> str:
    """Return an HTML badge <span> styled for *status*."""
    icon  = STATUS_ICON.get(status, "❓")
    color = STATUS_COLOR.get(status, "#000")
    bg    = STATUS_BG.get(status, "#eee")
    return (
        f'<span style="background:{bg};color:{color};padding:2px 10px;'
        f'border-radius:12px;font-weight:600;font-size:0.85rem;">'
        f"{icon} {status}</span>"
    )


def render_alert_banner(modified: int, added: int, deleted: int) -> None:
    """Show a prominent alert banner when any anomalies are found."""
    if modified == 0 and added == 0 and deleted == 0:
        st.success(
            "✅ **All files are clean.** No changes detected since baseline.",
            icon=None,
        )
        return

    parts = []
    if modified:
        parts.append(f"**{modified} modified**")
    if added:
        parts.append(f"**{added} added**")
    if deleted:
        parts.append(f"**{deleted} deleted**")

    st.error(
        f"🚨 **Integrity violations detected!** — {', '.join(parts)} file(s) "
        "found. Review the table below for details.",
        icon=None,
    )


def render_bar_chart(results: list[dict]) -> None:
    """
    Render a horizontal bar chart showing the count of each status category
    using Streamlit's native bar_chart.
    """
    clean    = sum(1 for r in results if r["status"] == "Clean")
    modified = sum(1 for r in results if r["status"] == "Modified")
    added    = sum(1 for r in results if r["status"] == "Added")
    deleted  = sum(1 for r in results if r["status"] == "Deleted")

    # Build chart data as a simple dict — Streamlit renders it natively
    chart_data = {
        "Status":  ["🟢 Clean", "🔴 Modified", "🟡 Added", "⚪ Deleted"],
        "Files":   [clean, modified, added, deleted],
    }

    # Use st.bar_chart via a light pandas-style dict
    import pandas as pd
    df = pd.DataFrame(chart_data).set_index("Status")
    st.bar_chart(df, height=220, color="#3b82d4")


def render_history_chart(history: list[dict]) -> None:
    """
    Render a line chart of violation counts (Modified + Added + Deleted)
    over the last N scans so trends are visible at a glance.
    """
    import pandas as pd

    if len(history) < 2:
        st.info("Run at least 2 scans to see the history trend chart.")
        return

    labels     = [h["timestamp"][-8:] for h in history]   # HH:MM:SS only
    modified   = [h["modified"]  for h in history]
    added      = [h["added"]     for h in history]
    deleted    = [h["deleted"]   for h in history]

    df = pd.DataFrame(
        {"Modified": modified, "Added": added, "Deleted": deleted},
        index=labels,
    )
    st.line_chart(df, height=220)


# ─── Sidebar ──────────────────────────────────────────────────────────────────

def render_sidebar(history_path: str) -> dict:
    """
    Render the sidebar containing:
      - Watch Mode toggle + interval slider
      - How-it-works educational content

    Returns a dict with watch-mode settings:
        { "enabled": bool, "interval": int }
    """
    with st.sidebar:
        st.title("🛡️ FIM Controls")

        # ── Watch Mode ────────────────────────────────────────────────────────
        st.markdown("### ⚡ Auto-Scan Watch Mode")
        watch_enabled = st.toggle(
            "Enable Watch Mode",
            value=st.session_state.get("watch_enabled", False),
            help="Automatically re-scan the directory at the chosen interval.",
        )
        st.session_state["watch_enabled"] = watch_enabled

        watch_interval = st.select_slider(
            "Scan interval (seconds)",
            options=[10, 15, 30, 60, 120, 300],
            value=st.session_state.get("watch_interval", 30),
            disabled=not watch_enabled,
        )
        st.session_state["watch_interval"] = watch_interval

        if watch_enabled:
            st.success(f"🔄 Scanning every **{watch_interval}s**")
        else:
            st.caption("Watch Mode is off — use the manual scan button.")

        st.divider()

        # ── Scan History management ───────────────────────────────────────────
        st.markdown("### 🗂️ Scan History")
        history = load_history(history_path)
        st.caption(f"{len(history)} scan(s) recorded in `{history_path}`")

        if history and st.button("🗑️ Clear History", use_container_width=True):
            # Wipe the history file
            with open(history_path, "w", encoding="utf-8") as fh:
                json.dump([], fh)
            st.rerun()

        st.divider()

        # ── How it works ──────────────────────────────────────────────────────
        st.markdown("### 📖 How FIM Works")

        st.markdown(
            """
            **What is a File Integrity Monitor?**
            A FIM detects unauthorised or unexpected changes to files by
            comparing cryptographic fingerprints (hashes) against a known-good
            snapshot called the **baseline**.
            """
        )

        st.markdown("---")
        st.markdown(
            """
            **SHA-256 Hashing**
            - Each file is read in **64 KB chunks** and hashed.
            - The result is a **256-bit (64 hex-char) digest**.
            - Changing even **one bit** produces a completely different
              hash — the **avalanche effect**.
            ```
            hello world  →  b94d27b9...
            Hello world  →  a591a6d4...
            ```
            """
        )

        st.markdown("---")
        st.markdown(
            """
            **Status Legend**
            - 🔴 **Modified** — hash changed
            - 🟡 **Added**    — new file, not in baseline
            - ⚪ **Deleted**  — baseline file is missing
            - 🟢 **Clean**    — hash matches exactly
            """
        )

        st.markdown("---")
        st.markdown(
            """
            **Real-World Use Cases**
            - Malware modifying system binaries
            - Verifying software release packages
            - Compliance (PCI-DSS, HIPAA, SOC 2)
            - Web-server defacement detection
            """
        )

        st.divider()
        st.markdown(
            """
            **How to Run**
            ```bash
            pip install streamlit
            streamlit run File_Integrity_Monitor.py
            ```
            """
        )
        st.caption("File Integrity Monitor · Built with Python & Streamlit")

    return {"enabled": watch_enabled, "interval": watch_interval}


# ─── Scan execution (shared by button click and watch mode) ───────────────────

def run_scan(directory: str, baseline_path: str, history_path: str) -> list[dict] | None:
    """
    Load baseline, scan directory, compare hashes, save to history.
    Returns the result list, or None if no baseline exists.
    """
    baseline = load_baseline(baseline_path)
    if not baseline:
        return None

    current = scan_directory(directory)
    results = compare_hashes(baseline, current)

    # Persist to session state and append to history file
    st.session_state["scan_results"]   = results
    st.session_state["scan_directory"] = directory
    append_history(results, history_path, directory)

    return results


# ─── Results renderer ─────────────────────────────────────────────────────────

def render_results(results: list[dict]) -> None:
    """Render metrics, alert banner, bar chart, filter, table, and CSV export."""

    total    = len(results)
    modified = sum(1 for r in results if r["status"] == "Modified")
    added    = sum(1 for r in results if r["status"] == "Added")
    deleted  = sum(1 for r in results if r["status"] == "Deleted")
    clean    = sum(1 for r in results if r["status"] == "Clean")

    # ── Metric cards ─────────────────────────────────────────────────────────
    st.divider()
    st.subheader("📊 Scan Summary")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("📁 Total Files", f"{total:,}")
    m2.metric("🟢 Clean",       f"{clean:,}")
    m3.metric("🔴 Modified",    f"{modified:,}",
              delta=f"+{modified}" if modified else None, delta_color="inverse")
    m4.metric("🟡 Added",       f"{added:,}",
              delta=f"+{added}"    if added    else None, delta_color="inverse")
    m5.metric("⚪ Deleted",     f"{deleted:,}",
              delta=f"-{deleted}"  if deleted  else None, delta_color="inverse")

    st.divider()

    # ── Alert banner ──────────────────────────────────────────────────────────
    render_alert_banner(modified, added, deleted)

    st.divider()

    # ── Bar chart ─────────────────────────────────────────────────────────────
    st.subheader("📈 Results Breakdown")
    render_bar_chart(results)

    st.divider()

    # ── Filter + Table ────────────────────────────────────────────────────────
    st.subheader("📋 Detailed Results")

    filter_status = st.selectbox(
        "Filter by status",
        ["All", "Modified", "Added", "Deleted", "Clean"],
        index=0,
        label_visibility="collapsed",
    )

    filtered = (
        results
        if filter_status == "All"
        else [r for r in results if r["status"] == filter_status]
    )

    if not filtered:
        st.info("No results match the selected filter.")
    else:
        # Build HTML table rows with coloured status badges
        rows_html = []
        for r in filtered:
            rows_html.append(
                {
                    "Status":        render_status_badge(r["status"]),
                    "File Path":     r["file"],
                    "Original Hash": shorten(r["orig_hash"]),
                    "Current Hash":  shorten(r["curr_hash"]),
                    "Last Checked":  r["timestamp"],
                }
            )

        header_html = "".join(f"<th>{h}</th>" for h in rows_html[0].keys())
        rows_td = "".join(
            "<tr>" + "".join(f"<td>{v}</td>" for v in row.values()) + "</tr>"
            for row in rows_html
        )

        table_html = f"""
        <style>
          .fim-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          }}
          .fim-table th {{
            background: #f0f2f6;
            padding: 8px 12px;
            text-align: left;
            font-weight: 700;
            border-bottom: 2px solid #d0d7de;
            white-space: nowrap;
          }}
          .fim-table td {{
            padding: 7px 12px;
            border-bottom: 1px solid #e8eaed;
            vertical-align: middle;
            word-break: break-all;
          }}
          .fim-table tr:hover td {{ background: #f6f8fa; }}
        </style>
        <table class="fim-table">
          <thead><tr>{header_html}</tr></thead>
          <tbody>{rows_td}</tbody>
        </table>
        """
        st.markdown(table_html, unsafe_allow_html=True)

        # ── CSV export ────────────────────────────────────────────────────────
        st.divider()
        csv_lines = ["Status,File Path,Original Hash,Current Hash,Last Checked"]
        for r in filtered:
            csv_lines.append(
                f'{r["status"]},{r["file"]},'
                f'{r["orig_hash"] or ""},'
                f'{r["curr_hash"] or ""},'
                f'{r["timestamp"]}'
            )
        st.download_button(
            label="⬇️ Export Results as CSV",
            data="\n".join(csv_lines),
            file_name=f"fim_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )


def render_history_section(history_path: str) -> None:
    """
    Render the Scan History section:
      - Trend line chart (violations over time)
      - Expandable table of all past scan summaries
    """
    history = load_history(history_path)
    if not history:
        return

    st.divider()
    st.subheader("🕓 Scan History")

    # ── Trend chart ───────────────────────────────────────────────────────────
    st.caption("Violation trend across the last scans (Modified + Added + Deleted)")
    render_history_chart(history)

    # ── History table ─────────────────────────────────────────────────────────
    with st.expander(f"📄 View all {len(history)} scan record(s)", expanded=False):
        header = ["Timestamp", "Directory", "Total", "🟢 Clean",
                  "🔴 Modified", "🟡 Added", "⚪ Deleted"]
        header_html = "".join(f"<th>{h}</th>" for h in header)

        rows_td = ""
        for h in reversed(history):    # newest first
            violations = h["modified"] + h["added"] + h["deleted"]
            row_style  = ' style="background:#fff8f8;"' if violations else ""
            rows_td += (
                f"<tr{row_style}>"
                f"<td>{h['timestamp']}</td>"
                f"<td style='word-break:break-all'>{h['directory']}</td>"
                f"<td>{h['total']}</td>"
                f"<td>{h['clean']}</td>"
                f"<td>{'🔴 ' + str(h['modified']) if h['modified'] else h['modified']}</td>"
                f"<td>{'🟡 ' + str(h['added'])    if h['added']    else h['added']}</td>"
                f"<td>{'⚪ ' + str(h['deleted'])  if h['deleted']  else h['deleted']}</td>"
                f"</tr>"
            )

        hist_table = f"""
        <style>
          .hist-table {{
            width:100%; border-collapse:collapse;
            font-size:0.85rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          }}
          .hist-table th {{
            background:#f0f2f6; padding:7px 10px; text-align:left;
            font-weight:700; border-bottom:2px solid #d0d7de;
          }}
          .hist-table td {{
            padding:6px 10px; border-bottom:1px solid #e8eaed;
          }}
        </style>
        <table class="hist-table">
          <thead><tr>{header_html}</tr></thead>
          <tbody>{rows_td}</tbody>
        </table>
        """
        st.markdown(hist_table, unsafe_allow_html=True)


# ─── Main dashboard ────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point — renders the full Streamlit dashboard."""

    st.set_page_config(
        page_title="File Integrity Monitor",
        page_icon="🛡️",
        layout="wide",
    )

    # ── Sidebar (returns watch-mode settings) ─────────────────────────────────
    watch = render_sidebar(HISTORY_FILE)

    # ── Header ────────────────────────────────────────────────────────────────
    st.title("🛡️ File Integrity Monitor")

    # Show live watch-mode badge next to the title
    if watch["enabled"]:
        st.caption(
            f"🔄 **Watch Mode active** — auto-scanning every "
            f"**{watch['interval']}s** · "
            "Detect unauthorised modifications, additions, and deletions."
        )
    else:
        st.caption(
            "Detect unauthorised modifications, additions, and deletions using "
            "SHA-256 cryptographic hashing."
        )

    st.divider()

    # ── Directory input ───────────────────────────────────────────────────────
    col_input, col_baseline_path = st.columns([3, 1])

    with col_input:
        directory = st.text_input(
            "📁 Directory to Monitor",
            value=str(Path.cwd()),
            help="Enter the full path of the folder you want to monitor.",
        )

    with col_baseline_path:
        baseline_path = st.text_input(
            "💾 Baseline File",
            value=BASELINE_FILE,
            help="Path where baseline.json will be saved / read from.",
        )

    dir_valid = os.path.isdir(directory)
    if directory and not dir_valid:
        st.warning("⚠️ The path entered is not a valid directory.")

    st.divider()

    # ── Action buttons ────────────────────────────────────────────────────────
    col_gen, col_scan, _ = st.columns([1, 1, 4])

    with col_gen:
        generate_clicked = st.button(
            "⚙️ Generate Baseline",
            disabled=not dir_valid,
            use_container_width=True,
            type="secondary",
            help="Scan the directory and save SHA-256 hashes to baseline.json.",
        )

    with col_scan:
        scan_clicked = st.button(
            "🔍 Run Integrity Scan",
            disabled=not dir_valid or watch["enabled"],
            use_container_width=True,
            type="primary",
            help=(
                "Watch Mode is active — disable it to use manual scan."
                if watch["enabled"]
                else "Compare current file hashes against the saved baseline."
            ),
        )

    # ── Generate Baseline flow ────────────────────────────────────────────────
    if generate_clicked:
        with st.spinner("Scanning directory and computing SHA-256 hashes…"):
            hashes = scan_directory(directory)
            save_baseline(hashes, baseline_path)

        # Clear stale scan results when a new baseline is taken
        st.session_state.pop("scan_results", None)

        st.success(
            f"✅ Baseline saved to `{baseline_path}` — "
            f"**{len(hashes):,}** file(s) recorded."
        )
        with st.expander("📄 View baseline entries", expanded=False):
            st.json(hashes)

    # ── Manual scan flow ──────────────────────────────────────────────────────
    if scan_clicked:
        with st.spinner("Re-scanning directory and comparing hashes…"):
            results = run_scan(directory, baseline_path, HISTORY_FILE)

        if results is None:
            st.warning(
                "⚠️ No baseline found. Please generate a baseline first "
                "using the **⚙️ Generate Baseline** button."
            )
            st.session_state.pop("scan_results", None)

    # ── Auto-Scan Watch Mode ──────────────────────────────────────────────────
    if watch["enabled"] and dir_valid:
        # Show a live countdown placeholder
        countdown_ph = st.empty()
        last_scan_ph = st.empty()

        # Run a scan immediately on first watch-mode activation, then loop
        if "watch_last_scan" not in st.session_state:
            with st.spinner("Watch Mode: running initial scan…"):
                results = run_scan(directory, baseline_path, HISTORY_FILE)
            if results is None:
                st.warning(
                    "⚠️ No baseline found. Generate a baseline first, "
                    "then re-enable Watch Mode."
                )
                st.session_state["watch_enabled"] = False
                st.rerun()
            st.session_state["watch_last_scan"] = time.time()

        # Countdown loop — updates UI every second, triggers rerun at 0
        last = st.session_state.get("watch_last_scan", time.time())
        elapsed   = time.time() - last
        remaining = max(0, watch["interval"] - int(elapsed))

        last_scan_ph.caption(
            f"Last scan: **{st.session_state.get('scan_results', [{}])[0].get('timestamp', '—') if st.session_state.get('scan_results') else '—'}**"
        )

        for secs_left in range(remaining, 0, -1):
            countdown_ph.info(
                f"🔄 Next auto-scan in **{secs_left}s** "
                f"(interval: {watch['interval']}s) — "
                "modify a file to see it detected automatically."
            )
            time.sleep(1)
            # If the user toggled Watch Mode off during the sleep, stop
            if not st.session_state.get("watch_enabled", False):
                break

        # Interval elapsed — run the next scan and rerun the page
        if st.session_state.get("watch_enabled", False):
            countdown_ph.info("🔄 Scanning now…")
            results = run_scan(directory, baseline_path, HISTORY_FILE)
            st.session_state["watch_last_scan"] = time.time()
            st.rerun()

    # ── Render scan results (from session state) ──────────────────────────────
    if "scan_results" in st.session_state:
        render_results(st.session_state["scan_results"])

    # ── Render scan history section ───────────────────────────────────────────
    render_history_section(HISTORY_FILE)


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
