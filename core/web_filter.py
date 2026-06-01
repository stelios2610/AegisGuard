"""Web Filter - domain/URL blocking via hosts file (Linux/Windows)."""
import os
import re
import subprocess
from db import database
from core.platform import IS_LINUX

HOSTS_PATH = "/etc/hosts" if IS_LINUX else r"C:\Windows\System32\drivers\etc\hosts"
MARKER_BEGIN = "# AegisGuard Web Filter BEGIN"
MARKER_END   = "# AegisGuard Web Filter END"

BUILTIN_CATEGORIES = {
    "Adult Content": [
        "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com",
        "tube8.com", "xhamster.com", "beeg.com", "brazzers.com", "hentai.tv",
    ],
    "Gambling": [
        "bet365.com", "pokerstars.com", "888casino.com", "betway.com",
        "draftkings.com", "fanduel.com", "caesarsonline.com", "unibet.com",
    ],
    "Malware": [
        "malware-domain.com", "ransomware.site", "cryptolocker.biz",
        "trojandownloader.net", "botnet-cc.ru",
    ],
    "Phishing": [
        "phishing-example.com", "fake-paypal.com", "secure-login-update.com",
    ],
    "Ads & Tracking": [
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "scorecardresearch.com", "quantserve.com", "adnxs.com", "adsrvr.org",
        "moatads.com", "outbrain.com", "taboola.com", "advertising.com",
        "ads.yahoo.com", "cdn.taboola.com", "pixel.advertising.com",
    ],
}


def _read_hosts():
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except PermissionError:
        return None
    except FileNotFoundError:
        return ""


def _write_hosts(content):
    try:
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        return True, "OK"
    except PermissionError:
        msg = "Permission denied — run as root" if IS_LINUX else "Permission denied — run as Administrator"
        return False, msg
    except Exception as e:
        return False, str(e)


def _strip_aegisguard_block(content):
    lines = content.splitlines(keepends=True)
    result = []
    inside = False
    for line in lines:
        if MARKER_BEGIN in line:
            inside = True
            continue
        if MARKER_END in line:
            inside = False
            continue
        if not inside:
            result.append(line)
    return "".join(result)


def apply_filters():
    """Write all enabled blocked domains to the hosts file."""
    if database.get_setting("web_filter_enabled", "1") != "1":
        return remove_filters()

    if database.get_setting("web_filter_use_hosts", "1") != "1":
        return True, "Hosts-file mode disabled"

    filters = database.get_web_filters()
    blocked_domains = set()

    categories = {c["name"]: c["enabled"] for c in database.get_web_categories()}
    for cat, domains in BUILTIN_CATEGORIES.items():
        if categories.get(cat, 1):
            blocked_domains.update(domains)

    for f in filters:
        if f["enabled"] and f["action"] == "BLOCK":
            pattern = f["pattern"].strip().lower()
            pattern = re.sub(r"^https?://", "", pattern)
            pattern = pattern.split("/")[0]
            if pattern:
                blocked_domains.add(pattern)

    current = _read_hosts()
    if current is None:
        return False, "Cannot read hosts file (permission denied)"

    clean = _strip_aegisguard_block(current)
    if not clean.endswith("\n"):
        clean += "\n"

    block_lines = [f"\n{MARKER_BEGIN}\n"]
    for domain in sorted(blocked_domains):
        block_lines.append(f"0.0.0.0 {domain}\n")
        block_lines.append(f"0.0.0.0 www.{domain}\n")
    block_lines.append(f"{MARKER_END}\n")

    new_content = clean + "".join(block_lines)
    ok, msg = _write_hosts(new_content)
    if ok:
        database.add_log("INFO", details=f"Web filter applied: {len(blocked_domains)} domains blocked")
    return ok, msg


def remove_filters():
    """Remove AegisGuard block from hosts file."""
    current = _read_hosts()
    if current is None:
        return False, "Cannot read hosts file"
    clean = _strip_aegisguard_block(current)
    return _write_hosts(clean)


def flush_dns():
    """Flush DNS cache — cross-platform."""
    try:
        if IS_LINUX:
            for cmd in [
                ["resolvectl", "flush-caches"],
                ["systemd-resolve", "--flush-caches"],
            ]:
                r = subprocess.run(cmd, capture_output=True, timeout=5)
                if r.returncode == 0:
                    return True
            # Fallback: reload dnsmasq if running
            subprocess.run(["systemctl", "reload", "dnsmasq"],
                           capture_output=True, timeout=5)
            return True
        else:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
            return True
    except Exception:
        return False


def get_blocked_count():
    filters = database.get_web_filters()
    categories = {c["name"]: c["enabled"] for c in database.get_web_categories()}
    count = sum(1 for f in filters if f["enabled"] and f["action"] == "BLOCK")
    for cat, domains in BUILTIN_CATEGORIES.items():
        if categories.get(cat, 1):
            count += len(domains)
    return count


def get_hosts_status():
    content = _read_hosts()
    if content is None:
        return "error", 0
    if MARKER_BEGIN in content:
        domain_count = sum(
            1 for line in content.splitlines()
            if line.startswith("0.0.0.0") and MARKER_BEGIN not in line
        )
        return "active", domain_count
    return "inactive", 0
