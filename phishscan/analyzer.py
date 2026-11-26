"""PhishScan — local, offline phishing-link detector.

Does not download or open the target. Analysis is based on the URL,
filename, HTML, and email text you paste or load from a file.
"""
from __future__ import annotations

import email
import html
import re
import unicodedata
from dataclasses import dataclass, field
from email import policy
from html.parser import HTMLParser
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, unquote, urlparse

VERDICT_CLEAN = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_PHISHING = "PHISHING"

PHISHING_SCORE = 8
SUSPICIOUS_SCORE = 4

CLOUD_SHARE_HOSTS = (
    "sharepoint.com",
    "onedrive.live.com",
    "1drv.ms",
    "onedrive.com",
    "docs.google.com",
    "drive.google.com",
    "dropbox.com",
    "dropboxusercontent.com",
    "box.com",
    "boxcloud.com",
    "wetransfer.com",
    "we.tl",
    "icloud.com",
    "my.sharepoint.com",
)

TRUSTED_BRAND_HOSTS = {
    "microsoft": (
        "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
        "live.com", "outlook.com", "office.net", "azure.com", "windows.net",
        "sharepoint.com", "onedrive.com", "onedrive.live.com", "1drv.ms",
        "visualstudio.com", "azurewebsites.net", "microsoftonline.us",
    ),
    "google": ("google.com", "google.gr", "gmail.com", "gstatic.com", "googleapis.com", "googleusercontent.com"),
    "apple": ("apple.com", "icloud.com", "appleid.apple.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "amazon": ("amazon.com", "amazon.gr", "amazonaws.com"),
    "nbg": ("nbg.gr",),
    "eurobank": ("eurobank.gr",),
    "piraeus": ("piraeusbank.gr", "winbank.gr"),
}

BRAND_ALIASES = {
    "microsoft 365": "microsoft",
    "office 365": "microsoft",
    "onedrive": "microsoft",
    "sharepoint": "microsoft",
    "outlook": "microsoft",
    "teams": "microsoft",
    "hotmail": "microsoft",
    "live.com": "microsoft",
    "paypal": "paypal",
    "google": "google",
    "gmail": "google",
    "apple": "apple",
    "icloud": "apple",
    "amazon": "amazon",
    "εθνική": "nbg",
    "eurobank": "eurobank",
    "πειραιώς": "piraeus",
}

# Instruction-as-filename lures (Greek + English + common variants).
LURE_PHRASES = (
    "ασφαλές μήνυμα",
    "ασφαλεσ μηνυμα",
    "προστατευμένο μήνυμα",
    "προστατευμενο μηνυμα",
    "κρυπτογραφημένο μήνυμα",
    "κρυπτογραφημενο μηνυμα",
    "κάντε κλικ",
    "καντε κλικ",
    "λήψη εγγράφου",
    "ληψη εγγραφου",
    "για να το δείτε",
    "για να το δειτε",
    "για να το ανοίξετε",
    "πατήστε εδώ",
    "πατηστε εδω",
    "κατεβάστε το έγγραφο",
    "secure message",
    "encrypted message",
    "protected message",
    "protected file",
    "click to view",
    "click to open",
    "click to download",
    "click the download",
    "download document",
    "download the document",
    "view the document",
    "open the document",
    "shared a file with you",
    "sent you a secure",
    "sent you a protected",
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "zip", "mov", "gq", "tk", "ml", "cf", "ga",
    "rest", "country", "work", "support", "loan", "icu", "cfd", "shop",
    "sbs", "cyou", "bond", "beauty", "autos",
}

SHORTENER_HOSTS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at", "trib.al",
}

UNWRAP_HOSTS = {
    "safelinks.protection.outlook.com": "url",
    "nam.safelinks.protection.outlook.com": "url",
    "nam01.safelinks.protection.outlook.com": "url",
    "nam02.safelinks.protection.outlook.com": "url",
    "nam03.safelinks.protection.outlook.com": "url",
    "nam04.safelinks.protection.outlook.com": "url",
    "nam10.safelinks.protection.outlook.com": "url",
    "eur.safelinks.protection.outlook.com": "url",
    "eur01.safelinks.protection.outlook.com": "url",
    "eur02.safelinks.protection.outlook.com": "url",
    "linkprotect.cudasvc.com": "url",
}

INVISIBLE_CHARS = (
    "\u00a0",  # nbsp — used in the Premier Fire lure
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060",
    "\u202f", "\u00ad", "\u180e",
)


@dataclass
class Finding:
    id: str
    severity: str
    points: int
    title: str
    detail: str


@dataclass
class UrlReport:
    url: str
    host: str
    decoded_path: str
    filename: str
    score: int
    verdict: str
    findings: List[Finding] = field(default_factory=list)
    unwrapped_from: str = ""


@dataclass
class ScanReport:
    verdict: str
    score: int
    urls: List[UrlReport]
    text_findings: List[Finding]
    advice: str
    summary: str


def analyze_url(url: str) -> UrlReport:
    raw = (url or "").strip().strip("<>").rstrip(").,;")
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    raw = _hxxp_to_http(raw)
    original = raw
    unwrapped_from = ""
    inner, via = unwrap_security_wrapper(raw)
    if via:
        unwrapped_from = via
        raw = inner

    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    decoded_path = _fully_unquote(parsed.path or "")
    filename = _filename_from_path(decoded_path)
    findings: List[Finding] = []

    if unwrapped_from:
        findings.append(Finding(
            "unwrapped", "LOW", 0,
            "Ο σύνδεσμος ήταν τυλιγμένος (SafeLinks / gateway)",
            f"Αναλύθηκε ο εσωτερικός σύνδεσμος, όχι το {unwrapped_from}.",
        ))

    if parsed.scheme in ("javascript", "data", "vbscript"):
        findings.append(Finding(
            "dangerous_scheme", "HIGH", 10,
            "Επικίνδυνο σχήμα URL",
            f"Το σχήμα «{parsed.scheme}:» χρησιμοποιείται για εκτέλεση κώδικα, όχι για άνοιγμα αρχείου.",
        ))

    if not host:
        if parsed.scheme not in ("javascript", "data", "vbscript"):
            findings.append(Finding(
                "empty_host", "MEDIUM", 3,
                "Δεν βρέθηκε κανονικό hostname",
                "Ο σύνδεσμος δεν έχει έγκυρο domain.",
            ))
        return _finalize_url(original, host, decoded_path, filename, findings, unwrapped_from)

    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        findings.append(Finding(
            "userinfo", "HIGH", 6,
            "Username μέσα στο URL (@)",
            "Τεχνική που κρύβει το πραγματικό domain μετά το @.",
        ))

    if _is_ip_host(host):
        findings.append(Finding(
            "ip_host", "MEDIUM", 4,
            "Ο σύνδεσμος δείχνει σε διεύθυνση IP",
            "Οι νόμιμες εταιρείες σπάνια μοιράζονται αρχεία με γυμνή IP.",
        ))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(Finding(
            "punycode", "HIGH", 6,
            "Punycode / διεθνές domain (xn--)",
            "Συχνά κρύβει οπτικά παρόμοιο όνομα μάρκας (homograph).",
        ))

    if _mixed_scripts(host):
        findings.append(Finding(
            "mixed_script", "HIGH", 6,
            "Ανάμεικτα αλφάβητα στο domain",
            "Το hostname ανακατεύει λατινικά με άλλα αλφάβητα — τυπικό homograph.",
        ))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(
            "bad_tld", "MEDIUM", 3,
            f"Ύποπτο TLD (.{tld})",
            "Αυτός ο καταληκτικός τομέας χρησιμοποιείται συχνά σε καμπάνιες phishing.",
        ))

    if _host_matches_any(host, SHORTENER_HOSTS):
        findings.append(Finding(
            "shortener", "MEDIUM", 4,
            "URL shortener",
            "Ο πραγματικός προορισμός είναι κρυμμένος. Μην τον ανοίξετε· ζητήστε τον πλήρη σύνδεσμο.",
        ))

    for ch in INVISIBLE_CHARS:
        if ch in decoded_path or ch in raw:
            label = "non-breaking space (NBSP)" if ch == "\u00a0" else f"αόρατος χαρακτήρας U+{ord(ch):04X}"
            findings.append(Finding(
                "invisible_char", "HIGH", 4,
                "Κρυφός χαρακτήρας στο όνομα αρχείου",
                f"Βρέθηκε {label}. Χρησιμοποιείται για να μοιάζει το όνομα «κανονικό» ενώ δεν είναι.",
            ))
            break

    path_norm = _normalize_for_match(decoded_path)
    file_norm = _normalize_for_match(filename)
    lure_hits = _lure_hits(path_norm) + [h for h in _lure_hits(file_norm) if h not in _lure_hits(path_norm)]
    if lure_hits:
        findings.append(Finding(
            "lure_filename", "HIGH", 8,
            "Το όνομα αρχείου είναι οδηγία phishing",
            "Το αρχείο δεν έχει κανονικό όνομα (π.χ. τιμολόγιο.pdf). Το όνομα λέει "
            "«ασφαλές μήνυμα / κάντε κλικ / download document»: "
            + ", ".join(lure_hits[:4])
            + ".",
        ))

    if _sentence_filename(filename):
        findings.append(Finding(
            "sentence_filename", "HIGH", 4,
            "Ολόκληρη πρόταση ως όνομα αρχείου",
            f"«{filename[:120]}» μοιάζει με μήνυμα προς τον χρήστη, όχι με έγγραφο.",
        ))

    if _host_matches_any(host, CLOUD_SHARE_HOSTS) or host.endswith("-my.sharepoint.com") or host.endswith(".sharepoint.com"):
        if lure_hits or _sentence_filename(filename):
            findings.append(Finding(
                "trusted_host_lure", "HIGH", 5,
                "Αληθινό SharePoint/OneDrive, ψεύτικο περιεχόμενο",
                "Το domain είναι της Microsoft. Αυτό δεν σημαίνει ότι το αρχείο είναι ασφαλές. "
                "Οι επιτιθέμενοι μοιράζουν PDF/HTML από παραβιασμένους λογαριασμούς M365.",
            ))
        ext = _extension(filename)
        if ext in {"html", "htm", "xhtml", "js", "vbs", "iso", "img", "lnk", "iso"}:
            findings.append(Finding(
                "dangerous_share_ext", "HIGH", 6,
                f"Κοινοποίηση .{ext} από cloud drive",
                "Τα HTML/script αρχεία σε OneDrive/SharePoint χρησιμοποιούνται για credential phishing.",
            ))

    brand = _brand_mentioned(raw + " " + decoded_path + " " + filename)
    if brand:
        allowed = TRUSTED_BRAND_HOSTS.get(brand, ())
        if host and not _host_matches_any(host, allowed) and not _host_matches_any(host, SHORTENER_HOSTS):
            findings.append(Finding(
                "brand_mismatch", "HIGH", 8,
                f"Αναφορά σε {brand} αλλά το domain δεν είναι δικό τους",
                f"Το host είναι «{host}», όχι επίσημο domain της μάρκας.",
            ))

    if parsed.query and len(parsed.query) > 400:
        findings.append(Finding(
            "huge_query", "LOW", 1,
            "Πολύ μεγάλο query string",
            "Μεγάλα tokens είναι φυσιολογικά σε SharePoint sharing links. Από μόνο του δεν είναι απόδειξη.",
        ))

    return _finalize_url(original, host, decoded_path, filename, findings, unwrapped_from)


def analyze_text(text: str, extra_urls: Optional[Sequence[str]] = None) -> ScanReport:
    text = text or ""
    found_urls = list(extract_urls(text))
    if extra_urls:
        found_urls.extend(extra_urls)

    found_urls = _drop_prefix_urls(found_urls)
    seen = set()
    unique_urls: List[str] = []
    for u in found_urls:
        key = u.strip()
        if key and key not in seen:
            seen.add(key)
            unique_urls.append(u)

    url_reports = [analyze_url(u) for u in unique_urls]
    text_findings: List[Finding] = []

    href_mismatches = extract_href_mismatches(text)
    for shown, href in href_mismatches:
        text_findings.append(Finding(
            "href_mismatch", "HIGH", 7,
            "Το κείμενο του συνδέσμου δεν ταιριάζει με τον πραγματικό προορισμό",
            f"Φαίνεται «{shown[:80]}» αλλά πάει στο «{href[:120]}».",
        ))

    body_norm = _normalize_for_match(text)
    lure_in_body = _lure_hits(body_norm)
    if lure_hits_in_share_context(body_norm, url_reports):
        text_findings.append(Finding(
            "body_lure", "MEDIUM", 3,
            "Κείμενο «ασφαλές/encrypted message» μαζί με cloud link",
            "Βρέθηκαν φράσεις: " + ", ".join(lure_in_body[:4]) + ".",
        ))

    all_findings: List[Finding] = list(text_findings)
    score = sum(f.points for f in text_findings)
    for r in url_reports:
        score += r.score
        all_findings.extend(r.findings)

    verdict = _verdict_from_score(score)
    # A single high-confidence lure on a cloud host is enough.
    if any(f.id in {"lure_filename", "trusted_host_lure", "brand_mismatch", "dangerous_scheme"} for f in all_findings):
        if score >= PHISHING_SCORE:
            verdict = VERDICT_PHISHING
        elif verdict == VERDICT_CLEAN:
            verdict = VERDICT_SUSPICIOUS

    advice = {
        VERDICT_PHISHING: (
            "Μην ανοίξετε τον σύνδεσμο και μην εισάγετε κωδικούς. "
            "Επιβεβαιώστε με τον αποστολέα από γνωστό τηλέφωνο — όχι απαντώντας στο email. "
            "Αν κάποιος ήδη έκανε login, αλλάξτε κωδικό και ελέγξτε MFA / κανόνες Inbox."
        ),
        VERDICT_SUSPICIOUS: (
            "Μην ανοίξετε τον σύνδεσμο μέχρι να τον επιβεβαιώσετε από άλλο κανάλι. "
            "Αν είναι SharePoint, ζητήστε από τον αποστολέα το κανονικό όνομα του αρχείου."
        ),
        VERDICT_CLEAN: (
            "Δεν βρέθηκαν τα κλασικά σημάδια αυτού του είδους phishing. "
            "Αν κάτι σας φαίνεται περίεργο, πάλι επιβεβαιώστε τον αποστολέα."
        ),
    }[verdict]

    if not unique_urls and not text.strip():
        summary = "Δεν δόθηκε σύνδεσμος ή κείμενο."
        verdict = VERDICT_CLEAN
        score = 0
        advice = "Επικολλήστε ένα URL, ένα email, ή φορτώστε αρχείο .eml."
    elif not unique_urls:
        summary = "Δεν βρέθηκαν σύνδεσμοι. Ελέγχθηκε μόνο το κείμενο."
    elif len(url_reports) == 1:
        summary = f"{verdict}: {url_reports[0].host or '—'}  (βαθμός {score})"
    else:
        summary = f"{verdict}: {len(url_reports)} σύνδεσμοι, υψηλότερος κίνδυνος βαθμός {score}"

    return ScanReport(
        verdict=verdict,
        score=score,
        urls=url_reports,
        text_findings=text_findings,
        advice=advice,
        summary=summary,
    )


def analyze_eml_bytes(data: bytes) -> ScanReport:
    msg = email.message_from_bytes(data, policy=policy.default)
    parts: List[str] = []
    subj = msg.get("subject", "") or ""
    frm = msg.get("from", "") or ""
    parts.append(f"Subject: {subj}")
    parts.append(f"From: {frm}")
    for header in ("To", "Cc", "Reply-To", "Return-Path"):
        if msg.get(header):
            parts.append(f"{header}: {msg.get(header)}")
    body = _eml_body(msg)
    parts.append(body)
    return analyze_text("\n".join(parts))


def extract_urls(text: str) -> List[str]:
    urls: List[str] = []
    blob = text or ""
    for m in re.finditer(r"(?i)(?:https?|hxxps?)://", blob):
        urls.append(_take_url(blob, m.start()))
    for _shown, href in extract_href_mismatches(blob):
        if href and href.lower().startswith(("http://", "https://", "hxxp://", "hxxps://")):
            urls.append(_hxxp_to_http(href.strip()))
    return _drop_prefix_urls(urls)


def _take_url(text: str, start: int) -> str:
    """Grab a URL, keeping spaces inside SharePoint/OneDrive filenames."""
    n = len(text)
    i = start
    while i < n and text[i] not in "\r\n<>\"'":
        i += 1
    raw = text[start:i]
    first, _, rest = raw.partition(" ")
    first = first.rstrip(").,;]>\"'")
    candidate = _hxxp_to_http(html.unescape(first))
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    allow_spaces = (
        "sharepoint" in host
        or "onedrive" in host
        or host.endswith("1drv.ms")
        or "/documents/" in candidate.lower()
        or "/personal/" in candidate.lower()
        or "%" in candidate
    )
    if not allow_spaces or not rest:
        return candidate
    # Keep space-separated filename tokens up to extension + query.
    extended = first
    remainder = raw[len(first):]
    # remainder starts with spaces
    m = re.match(
        r"(?is)((?:[ \u00a0]+[^\s<>\"'?]+)+)(\.[A-Za-z0-9]{2,5})?(\?[^\s<>\"']*)?",
        remainder,
    )
    if not m:
        return candidate
    extended = (first + m.group(0)).rstrip(").,;]>\"'")
    return _hxxp_to_http(html.unescape(extended))


def _drop_prefix_urls(urls: Sequence[str]) -> List[str]:
    """Drop fragments that are just a truncated prefix of a longer URL."""
    cleaned = []
    seen = set()
    ordered = sorted((u.strip() for u in urls if u and u.strip()), key=len, reverse=True)
    for u in ordered:
        if u in seen:
            continue
        if any(keep.startswith(u) and keep != u for keep in cleaned):
            continue
        seen.add(u)
        cleaned.append(u)
    # restore first-seen order among survivors
    survivors = {c for c in cleaned}
    out = []
    for u in urls:
        u = u.strip()
        if u in survivors and u not in out:
            out.append(u)
    return out


def extract_href_mismatches(text: str) -> List[Tuple[str, str]]:
    parser = _HrefParser()
    try:
        parser.feed(text or "")
        parser.close()
    except Exception:
        return []
    mismatches = []
    for shown, href in parser.pairs:
        shown_s = " ".join(shown.split())
        href_s = href.strip()
        if not href_s or href_s.startswith("#") or href_s.lower().startswith("mailto:"):
            continue
        if _looks_like_url(shown_s) and _hosts_differ(shown_s, href_s):
            mismatches.append((shown_s, href_s))
    return mismatches


def unwrap_security_wrapper(url: str) -> Tuple[str, str]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    for wrap_host, param in UNWRAP_HOSTS.items():
        if host == wrap_host or host.endswith("." + wrap_host) or host.endswith("safelinks.protection.outlook.com"):
            qs = parse_qs(parsed.query)
            inner = (qs.get(param) or [""])[0]
            if inner:
                return unquote(inner), host
    if host.endswith("urldefense.proofpoint.com"):
        qs = parse_qs(parsed.query)
        inner = (qs.get("u") or [""])[0]
        if inner:
            inner = inner.replace("-3A", ":").replace("-2F", "/").replace("_", "/")
            return inner, host
    return url, ""


def lure_hits_in_share_context(body_norm: str, url_reports: Sequence[UrlReport]) -> bool:
    if not _lure_hits(body_norm):
        return False
    return any(
        r.host.endswith("sharepoint.com")
        or r.host.endswith("onedrive.live.com")
        or _host_matches_any(r.host, CLOUD_SHARE_HOSTS)
        for r in url_reports
    )


# ── internals ──────────────────────────────────────────────────────────────


def _finalize_url(url, host, decoded_path, filename, findings, unwrapped_from) -> UrlReport:
    score = sum(f.points for f in findings)
    return UrlReport(
        url=url,
        host=host,
        decoded_path=decoded_path,
        filename=filename,
        score=score,
        verdict=_verdict_from_score(score),
        findings=findings,
        unwrapped_from=unwrapped_from,
    )


def _verdict_from_score(score: int) -> str:
    if score >= PHISHING_SCORE:
        return VERDICT_PHISHING
    if score >= SUSPICIOUS_SCORE:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def _hxxp_to_http(url: str) -> str:
    return re.sub(r"(?i)^hxxps://", "https://", re.sub(r"(?i)^hxxp://", "http://", url))


def _fully_unquote(s: str) -> str:
    prev = s
    for _ in range(4):
        nxt = unquote(prev.replace("+", " "))
        if nxt == prev:
            break
        prev = nxt
    return html.unescape(prev)


def _filename_from_path(path: str) -> str:
    if not path:
        return ""
    name = path.rstrip("/").split("/")[-1]
    return name


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _normalize_for_match(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    for ch in INVISIBLE_CHARS:
        s = s.replace(ch, " ")
    s = s.replace("ς", "σ")
    s = s.casefold()
    s = re.sub(r"\s+", " ", s)
    return s


def _lure_hits(norm_text: str) -> List[str]:
    hits = []
    for phrase in LURE_PHRASES:
        if _normalize_for_match(phrase) in norm_text:
            hits.append(phrase)
    return hits


def _sentence_filename(filename: str) -> bool:
    if not filename:
        return False
    stem = filename
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    if len(stem) < 35:
        return False
    spaces = stem.count(" ") + stem.count("\u00a0")
    punct = sum(stem.count(c) for c in ".!?;:")
    return spaces >= 5 and (punct >= 1 or "κλικ" in stem.lower() or "click" in stem.lower())


def _host_matches_any(host: str, domains: Iterable[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    for d in domains:
        d = d.lower().lstrip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


def _is_ip_host(host: str) -> bool:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""):
        return True
    if host.startswith("[") and host.endswith("]"):
        return True
    return ":" in host and all(c in "0123456789abcdef:" for c in host.lower())


def _mixed_scripts(host: str) -> bool:
    scripts = set()
    for ch in host:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if "LATIN" in name:
            scripts.add("LATIN")
        elif "GREEK" in name:
            scripts.add("GREEK")
        elif "CYRILLIC" in name:
            scripts.add("CYRILLIC")
        elif "CYRILLIC" not in name and "LATIN" not in name and "GREEK" not in name:
            if "LETTER" in name:
                scripts.add("OTHER")
    return len(scripts) > 1


def _brand_mentioned(text: str) -> str:
    n = _normalize_for_match(text)
    # Prefer longer aliases first.
    for alias, brand in sorted(BRAND_ALIASES.items(), key=lambda kv: -len(kv[0])):
        if _normalize_for_match(alias) in n:
            return brand
    return ""


def _looks_like_url(s: str) -> bool:
    s = s.strip()
    if "://" in s or s.lower().startswith("www."):
        return True
    return bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?:/|\b)", s, re.I))


def _hosts_differ(shown: str, href: str) -> bool:
    def host_of(u: str) -> str:
        u = u.strip()
        if not re.match(r"^[a-z][a-z0-9+.-]*://", u, re.I):
            u = "http://" + u
        return (urlparse(u).hostname or "").lower().rstrip(".")

    a, b = host_of(shown), host_of(href)
    if not a or not b:
        return False
    return a != b and not a.endswith("." + b) and not b.endswith("." + a)


def _eml_body(msg) -> str:
    chunks: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    chunks.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    chunks.append(payload.decode("utf-8", errors="replace"))
    else:
        try:
            chunks.append(msg.get_content())
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            chunks.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(chunks)


class _HrefParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pairs: List[Tuple[str, str]] = []
        self._href: Optional[str] = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href
                self._buf = []

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.pairs.append(("".join(self._buf), self._href))
            self._href = None
            self._buf = []
