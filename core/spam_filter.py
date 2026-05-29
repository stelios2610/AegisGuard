"""spamBlocker - Email spam detection (WatchGuard spamBlocker equivalent).
Uses SpamAssassin on Linux or regex-based heuristics."""
import re
import subprocess
import os
import tempfile
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

# Spam scoring: score >= threshold = spam
SPAM_THRESHOLD = 5.0
SPAM_TAG_THRESHOLD = 3.0


def is_spamassassin_available():
    ok, _, _ = run(["spamc", "--version"])
    return ok


def check_email_spamassassin(email_content: bytes) -> dict:
    """Check email via SpamAssassin spamc."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as f:
        f.write(email_content)
        tmp = f.name
    try:
        result = subprocess.run(
            ["spamc", "-E", "--max-size=2000000"],
            input=email_content, capture_output=True, timeout=30
        )
        output = result.stdout.decode("utf-8", errors="ignore")
        score = _parse_score(output)
        is_spam = score >= SPAM_THRESHOLD
        if is_spam:
            database.add_log("BLOCK", details=f"SpamAssassin: score={score:.1f}")
        return {
            "is_spam": is_spam,
            "score": score,
            "threshold": SPAM_THRESHOLD,
            "report": output[:500],
        }
    except Exception as e:
        return {"is_spam": False, "score": 0, "error": str(e)}
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _parse_score(output):
    for line in output.splitlines():
        if "score=" in line.lower():
            m = re.search(r"score=([+-]?\d+\.?\d*)", line, re.IGNORECASE)
            if m:
                return float(m.group(1))
    return 0.0


# ── Heuristic spam scoring (no SpamAssassin needed) ──────────────────────────

SPAM_PATTERNS = [
    (r"(?i)\bviagra\b",           2.0, "Pharmaceutical spam"),
    (r"(?i)\bcialis\b",           2.0, "Pharmaceutical spam"),
    (r"(?i)\blottery\b",          2.5, "Lottery scam"),
    (r"(?i)\byou.ve won\b",       3.0, "Lottery scam"),
    (r"(?i)\bnigerian\b",         2.5, "419 scam"),
    (r"(?i)\bunsubscribe\b",      0.5, "Marketing"),
    (r"(?i)\bclick here\b",       0.5, "Phishing"),
    (r"(?i)\bverify your account\b", 2.0, "Phishing"),
    (r"(?i)\bsuspended\b.*\baccount\b", 2.0, "Account phishing"),
    (r"(?i)\bfree money\b",       3.0, "Scam"),
    (r"(?i)\bmake money fast\b",  3.0, "Scam"),
    (r"(?i)\b100% free\b",        1.5, "Spam"),
    (r"(?i)\bact now\b",          1.0, "Urgency spam"),
    (r"(?i)\blimited time\b",     1.0, "Urgency spam"),
    (r"(?i)\bno risk\b",          1.5, "Scam"),
    (r"(?i)\bcash bonus\b",       2.0, "Scam"),
    (r"(?i)\bwork from home\b",   1.5, "Job scam"),
    (r"(?i)(\$\$\$|\b\d+%\s*off\b)", 1.0, "Commercial spam"),
]


def check_email_heuristic(email_content: str) -> dict:
    """Heuristic-based spam scoring."""
    score = 0.0
    matches = []
    for pattern, weight, label in SPAM_PATTERNS:
        if re.search(pattern, email_content):
            score += weight
            matches.append(label)

    # Extra checks
    if email_content.count("!") > 5:
        score += 1.0
        matches.append("Excessive exclamation marks")
    if re.search(r"[A-Z]{5,}", email_content):
        score += 0.5
        matches.append("Excessive capitals")
    caps_ratio = sum(1 for c in email_content if c.isupper()) / max(len(email_content), 1)
    if caps_ratio > 0.3:
        score += 1.0
        matches.append("High caps ratio")

    is_spam = score >= SPAM_THRESHOLD
    return {
        "is_spam": is_spam,
        "score": score,
        "threshold": SPAM_THRESHOLD,
        "matches": matches,
    }


def check_email(email_content) -> dict:
    """Check email using SpamAssassin if available, else heuristic."""
    if isinstance(email_content, str):
        email_bytes = email_content.encode("utf-8", errors="ignore")
        email_str = email_content
    else:
        email_bytes = email_content
        email_str = email_content.decode("utf-8", errors="ignore")

    if is_spamassassin_available():
        return check_email_spamassassin(email_bytes)
    return check_email_heuristic(email_str)


def update_spamassassin():
    """Update SpamAssassin rules."""
    ok, out, err = run(["sa-update"], timeout=60)
    return ok, out if ok else err
