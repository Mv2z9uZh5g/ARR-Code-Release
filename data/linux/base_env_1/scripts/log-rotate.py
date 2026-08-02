#!/usr/bin/env python3
"""Simple log rotation script for application logs."""

import gzip
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path.home() / "logs"
MAX_AGE_DAYS = 14
MAX_SIZE_MB = 50


def rotate_logs():
    if not LOG_DIR.exists():
        return

    for log_file in LOG_DIR.glob("*.log"):
        size_mb = log_file.stat().st_size / (1024 * 1024)

        if size_mb > MAX_SIZE_MB:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"{log_file.stem}_{timestamp}.log.gz"
            archive_path = LOG_DIR / "archive" / archive_name

            archive_path.parent.mkdir(exist_ok=True)

            with open(log_file, "rb") as f_in:
                with gzip.open(archive_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            log_file.write_text("")
            print(f"Rotated: {log_file.name} -> {archive_name}")


def cleanup_old():
    archive_dir = LOG_DIR / "archive"
    if not archive_dir.exists():
        return

    cutoff = datetime.now() - timedelta(days=MAX_AGE_DAYS)

    for archive in archive_dir.glob("*.gz"):
        mtime = datetime.fromtimestamp(archive.stat().st_mtime)
        if mtime < cutoff:
            archive.unlink()
            print(f"Removed old archive: {archive.name}")


if __name__ == "__main__":
    rotate_logs()
    cleanup_old()
