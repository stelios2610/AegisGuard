"""Gateway AntiVirus - ClamAV integration (WatchGuard GAV equivalent)."""
import os
import subprocess
import threading
import tempfile
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

_scan_stats = {"scanned": 0, "threats": 0, "last_threat": "", "last_scan": ""}
_callbacks = []


def register_callback(fn):
    _callbacks.append(fn)


def _fire(alert):
    for fn in _callbacks:
        try:
            fn(alert)
        except Exception:
            pass


def is_clamav_available():
    ok, _, _ = run(["clamscan", "--version"])
    return ok


def update_definitions():
    """Update ClamAV virus definitions."""
    if not IS_LINUX:
        return False, "ClamAV update requires Linux"
    ok, out, err = run(["freshclam"], timeout=120)
    database.add_log("INFO", details=f"ClamAV definitions updated: {'OK' if ok else err}")
    return ok, out if ok else err


def scan_file(file_path):
    """Scan a single file with ClamAV. Returns (clean, threat_name)."""
    if not os.path.isfile(file_path):
        return True, ""
    ok, out, err = run(["clamscan", "--no-summary", file_path], timeout=60)
    _scan_stats["scanned"] += 1
    _scan_stats["last_scan"] = datetime.now().isoformat()
    if not ok:
        # ClamAV returns exit code 1 when threat found
        threat = ""
        for line in out.splitlines():
            if "FOUND" in line:
                threat = line.split(":")[1].strip() if ":" in line else "Unknown"
                break
        if threat:
            _scan_stats["threats"] += 1
            _scan_stats["last_threat"] = threat
            database.add_log("THREAT", src_ip=file_path,
                             rule_name="Gateway AntiVirus",
                             details=f"Threat detected: {threat} in {file_path}")
            alert = {"file": file_path, "threat": threat, "timestamp": datetime.now().isoformat()}
            _fire(alert)
            return False, threat
    return True, ""


def scan_bytes(data, filename="upload"):
    """Scan bytes in memory using ClamAV."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as f:
        f.write(data)
        tmp = f.name
    try:
        clean, threat = scan_file(tmp)
        return clean, threat
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def scan_directory(path, recursive=True):
    """Scan a directory."""
    flags = ["-r"] if recursive else []
    ok, out, err = run(["clamscan", "--no-summary"] + flags + [path], timeout=300)
    results = []
    for line in out.splitlines():
        if "FOUND" in line:
            parts = line.split(":")
            results.append({"file": parts[0].strip(), "threat": parts[1].strip() if len(parts) > 1 else "Unknown"})
    return results


def get_stats():
    stats = dict(_scan_stats)
    stats["available"]        = is_clamav_available()
    stats["version"]          = get_clamav_version()
    stats["definitions_date"] = get_definitions_date()
    return stats


def get_clamav_version():
    ok, out, _ = run(["clamscan", "--version"])
    return out.split("\n")[0] if ok else "Not installed"


def get_definitions_date():
    ok, out, _ = run(["sigtool", "--info", "/var/lib/clamav/main.cvd"])
    if ok:
        for line in out.splitlines():
            if "Build time" in line:
                return line.split(":", 1)[1].strip()
    return "Unknown"
