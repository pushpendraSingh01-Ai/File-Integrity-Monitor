# 🛡️ File Integrity Monitor (FIM)

A web-based cybersecurity tool that detects unauthorised changes to files using **SHA-256 cryptographic hashing**. Built with Python and Streamlit.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-red?style=flat-square&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-critical?style=flat-square)

---

## 📋 Table of Contents

- [What is a FIM?](#-what-is-a-fim)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
- [Demo Folder](#-demo-folder)
- [Auto-Scan Watch Mode](#-auto-scan-watch-mode)
- [Scan History](#-scan-history)
- [Screenshots Overview](#-screenshots-overview)
- [Dependencies](#-dependencies)
- [Security Considerations](#-security-considerations)
- [Real-World Use Cases](#-real-world-use-cases)

---

## 🔍 What is a FIM?

A **File Integrity Monitor** detects unauthorised or unexpected changes to files by comparing cryptographic fingerprints (hashes) against a known-good snapshot called the **baseline**.

> Every file has a unique SHA-256 hash — like a fingerprint. If even **one character** in a file changes, the hash changes completely. This is called the **Avalanche Effect**.

```
"hello world"  →  b94d27b9934d3e08a52e52d7da7dabfa...
"Hello world"  →  a591a6d40bf420404a011733cfb7b190...
                  ↑ completely different — one character changed
```

---

## ✨ Features

| Feature | Description |
|---|---|
| **⚙️ Baseline Generation** | Recursively scans a directory, computes SHA-256 hashes, saves to `baseline.json` |
| **🔍 Integrity Scan** | Compares current file hashes against the baseline to detect changes |
| **🚨 Alert Banner** | Red alert fires on any violation; green banner confirms clean state |
| **📊 Metric Cards** | Summary counts — Total, Clean, Modified, Added, Deleted |
| **📈 Bar Chart** | Visual breakdown of current scan results by status category |
| **📋 Results Table** | Colour-coded table with status badges, hash previews, and timestamps |
| **🔎 Status Filter** | Filter results by Modified / Added / Deleted / Clean |
| **⬇️ CSV Export** | Download scan results as a timestamped CSV for reporting |
| **⚡ Watch Mode** | Auto-scan every 10s–5min with live countdown timer |
| **🕓 Scan History** | Persistent log of all scans + violation trend line chart |
| **📖 Sidebar Explainer** | Educational content on SHA-256, avalanche effect, and FIM workflow |

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  1. GENERATE BASELINE                               │
│     └─ Scan directory → compute SHA-256 per file   │
│     └─ Save {filepath: hash} to baseline.json      │
│                                                     │
│  2. FILES CHANGE (tamper / add / delete)            │
│                                                     │
│  3. RUN INTEGRITY SCAN                              │
│     └─ Re-hash all files                           │
│     └─ Compare against baseline.json               │
│     └─ Classify each file:                         │
│          🔴 Modified  — hash changed               │
│          🟡 Added     — not in baseline            │
│          ⚪ Deleted   — missing from disk          │
│          🟢 Clean     — hash matches               │
│                                                     │
│  4. DISPLAY RESULTS                                 │
│     └─ Alert banner, metrics, chart, table         │
│     └─ Append summary to scan_history.json         │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
Cybersecurity Project/
│
├── File_Integrity_Monitor.py   ← Main application (all logic + UI)
├── baseline.json               ← Auto-generated hash snapshot (created on first baseline)
├── scan_history.json           ← Auto-generated scan log (created on first scan)
├── README.md                   ← This file
│
└── demo_folder/                ← Sample files for testing
    ├── configs/
    │   ├── app_config.ini      ← Server/DB config (good for "Modified" demo)
    │   └── settings.json       ← Feature flags
    ├── docs/
    │   ├── project_overview.txt
    │   ├── changelog.txt       ← Good "Deleted" demo target
    │   └── access_log.txt      ← Simulates log wiping when deleted
    └── scripts/
        ├── backup.py           ← Good "Modified script" demo target
        └── deploy.sh           ← Critical deploy script
```

---

## 🚀 Installation & Setup

### Prerequisites

- Python **3.10 or higher**

```bash
python --version
```

### Install the dependency

```bash
pip install streamlit
```

> That's it. Everything else (`hashlib`, `json`, `pathlib`, `os`, `time`) is built into Python's standard library.

### Launch the app

```bash
streamlit run File_Integrity_Monitor.py
```

The browser opens automatically at **`http://localhost:8501`**

---

## 📖 Usage Guide

### Step 1 — Enter the directory to monitor

In the **"📁 Directory to Monitor"** input box, enter the full path:

```
d:\Coding Journey\Cybersecurity Project\demo_folder
```

Leave the **"💾 Baseline File"** field as `baseline.json`.

---

### Step 2 — Generate the Baseline

Click **⚙️ Generate Baseline**

- All files are recursively scanned
- SHA-256 hash computed for each file (read in 64 KB chunks)
- Saved to `baseline.json`

```
✅ Baseline saved to baseline.json — 7 file(s) recorded.
```

---

### Step 3 — Run an Integrity Scan

Click **🔍 Run Integrity Scan**

- All files re-hashed
- Compared against `baseline.json`
- Results displayed with metric cards, alert banner, chart, and table

---

### Step 4 — Filter & Export

- Use the **dropdown filter** to narrow by status: `All | Modified | Added | Deleted | Clean`
- Click **⬇️ Export Results as CSV** to download a report

---

## 🧪 Demo Folder

Use the included `demo_folder/` to test all detection scenarios:

### 🔴 Simulate a Modified file
Open `demo_folder\configs\app_config.ini` and change:
```ini
debug = false
```
to:
```ini
debug = true
```
Save, then run a scan → `app_config.ini` shows as 🔴 **Modified**

---

### 🟡 Simulate an Added file
```bash
echo "Injected payload" > demo_folder\scripts\malware.py
```
Run a scan → `scripts/malware.py` shows as 🟡 **Added**

---

### ⚪ Simulate a Deleted file
```bash
Remove-Item demo_folder\docs\changelog.txt
```
Run a scan → `docs/changelog.txt` shows as ⚪ **Deleted**

---

### 🔥 All three at once (best for demos)
Do all three changes above before scanning — the 🚨 alert fires with Modified + Added + Deleted simultaneously.

---

## ⚡ Auto-Scan Watch Mode

Watch Mode enables continuous automated monitoring without any button clicks.

### How to enable

1. Open the **sidebar** (click `>` on the top-left)
2. Toggle **"Enable Watch Mode"** → ON
3. Set the **interval slider** (10s / 15s / 30s / 60s / 2min / 5min)

### What happens

```
┌─────────────────────────────────────────────┐
│  🔄 Next auto-scan in 8s (interval: 10s)   │
│     modify a file to see it detected        │
└─────────────────────────────────────────────┘
```

- A live countdown timer updates every second
- When it hits zero, the scan runs automatically
- Dashboard refreshes with new results
- Loop continues until you toggle Watch Mode off

> 💡 **Demo tip:** Set interval to 10s, modify a file, and let the audience watch the 🚨 alert appear without you clicking anything.

> ⚠️ The manual scan button is disabled while Watch Mode is active.

---

## 🕓 Scan History

Every scan (manual or auto) is logged to `scan_history.json` automatically.

### What is stored per scan

```json
{
  "timestamp": "2025-07-14 15:30:42",
  "directory": "d:/demo_folder",
  "total": 7,
  "clean": 5,
  "modified": 1,
  "added": 1,
  "deleted": 0
}
```

### How to view it

Scroll to the bottom of the dashboard:

- **Trend line chart** — Modified / Added / Deleted counts over time (requires 2+ scans)
- **"📄 View all scan records"** — expandable table, newest first, violations highlighted

### Clear history

In the sidebar → **🗑️ Clear History** wipes `scan_history.json`

> History is capped at **50 entries** to prevent unbounded file growth.

---

## 📸 Screenshots Overview

| Section | What you see |
|---|---|
| Top of page | Directory input + Baseline and Scan buttons |
| After scan (clean) | 5 green metric cards + ✅ success banner + green bar chart |
| After scan (violations) | Mixed metric cards + 🚨 red alert banner + bar chart with red/yellow bars |
| Results table | Colour-coded status badges, file paths, hash previews, timestamps |
| Bottom of page | Scan History trend chart + expandable history table |
| Sidebar | Watch Mode toggle + interval slider + SHA-256 explainer |

---

## 📦 Dependencies

| Library | Source | Purpose |
|---|---|---|
| `streamlit` | `pip install streamlit` | Web dashboard framework |
| `hashlib` | Python stdlib | SHA-256 hashing |
| `json` | Python stdlib | Read/write JSON files |
| `pathlib` | Python stdlib | Cross-platform directory walking |
| `os` | Python stdlib | Directory validation |
| `time` | Python stdlib | Watch Mode countdown timer |
| `datetime` | Python stdlib | Scan timestamps |
| `pandas` | Bundled with Streamlit | Chart DataFrames |

---

## 🔒 Security Considerations

### Strengths
- **SHA-256 collision resistance** — practically impossible to tamper a file without detection
- **Chunked reading** — memory-safe for large files (64 KB at a time)
- **Portable relative paths** — baseline works across operating systems
- **Permission-safe** — unreadable files are skipped silently

### Limitations & Future Improvements

| Limitation | Potential Improvement |
|---|---|
| Baseline file could itself be tampered | Sign with HMAC or store on read-only media |
| No real-time filesystem event hook | Integrate `watchdog` library for instant detection |
| No alerting outside the dashboard | Add email/Slack notifications on violation |
| No authentication | Add login before deploying on shared server |

---

## 🌍 Real-World Use Cases

- 🦠 **Malware detection** — detecting modified system binaries or injected scripts
- 📦 **Software verification** — confirming downloaded packages haven't been tampered
- 📋 **Compliance monitoring** — satisfying PCI-DSS Req. 11.5, HIPAA, SOC 2 controls
- 🌐 **Web defacement detection** — monitoring static web assets for unauthorised changes
- 🔍 **Forensic auditing** — establishing what changed and when after a security incident

---

## 🧠 Key Concepts Explained

### SHA-256
A cryptographic hash function that maps any input to a fixed 256-bit (64 hex character) digest. Standardised by NIST in FIPS PUB 180-4.

### Avalanche Effect
A property of cryptographic hash functions where a tiny change in input causes a completely different output. This makes it impossible for tampering to go undetected.

### Baseline
A trusted snapshot of file hashes taken at a known-good point in time. All future scans are compared against this reference.

### Integrity Scan
A fresh computation of all file hashes, compared against the baseline to identify Modified, Added, and Deleted files.

---

## 📄 License

This project is released under the **MIT License** — free to use, modify, and distribute.

---

*Built with Python & Streamlit · Cybersecurity Project*
