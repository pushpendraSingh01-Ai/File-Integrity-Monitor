#!/usr/bin/env python3
"""
backup.py — Automated backup script for critical configuration files.
This script is monitored by the FIM. Any unauthorised modification
would be detected on the next integrity scan.
"""

import shutil
import os
from datetime import datetime

BACKUP_SOURCES = [
    "configs/app_config.ini",
    "configs/settings.json",
]

BACKUP_DEST = "backups/"


def run_backup():
    """Copy each source file to the backup destination with a timestamp."""
    os.makedirs(BACKUP_DEST, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for source in BACKUP_SOURCES:
        if os.path.exists(source):
            filename = os.path.basename(source)
            dest = os.path.join(BACKUP_DEST, f"{timestamp}_{filename}")
            shutil.copy2(source, dest)
            print(f"[OK] Backed up: {source} → {dest}")
        else:
            print(f"[WARN] Source not found: {source}")


if __name__ == "__main__":
    print("Starting backup...")
    run_backup()
    print("Backup complete.")
