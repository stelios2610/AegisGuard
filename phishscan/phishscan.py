#!/usr/bin/env python3
"""PhishScan — εντοπισμός phishing συνδέσμων στον υπολογιστή σας.

Χωρίς εγκατάσταση πακέτων. Αρκεί Python 3.9+.
  Διπλό κλικ στο PhishScan.bat  →  παράθυρο
  python phishscan.py URL       →  γραμμή εντολών
  python phishscan.py email.eml
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from this folder without installing a package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import (  # noqa: E402
    VERDICT_CLEAN,
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
    ScanReport,
    analyze_eml_bytes,
    analyze_text,
    analyze_url,
)


BANNER = "PhishScan  ·  τοπικός έλεγχος συνδέσμων (δεν ανοίγει το αρχείο)"

VERDICT_EL = {
    VERDICT_PHISHING: "PHISHING  —  μην το ανοίξετε",
    VERDICT_SUSPICIOUS: "ΎΠΟΠΤΟ  —  μην το ανοίξετε μέχρι επιβεβαίωση",
    VERDICT_CLEAN: "ΚΑΘΑΡΟ  —  δεν βρέθηκαν τα κλασικά σημάδια",
}

COLORS = {
    VERDICT_PHISHING: "\033[1;31m",
    VERDICT_SUSPICIOUS: "\033[1;33m",
    VERDICT_CLEAN: "\033[1;32m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def _c(enabled: bool, code: str, text: str) -> str:
    if not enabled:
        return text
    return f"{code}{text}{COLORS['reset']}"


def render_report(report: ScanReport, color: bool) -> str:
    lines = [
        BANNER,
        "═" * 64,
        _c(color, COLORS.get(report.verdict, ""), f"Κρίση:  {VERDICT_EL.get(report.verdict, report.verdict)}"),
        f"Βαθμός: {report.score}   (phishing ≥ 8, ύποπτο ≥ 4)",
        f"{report.summary}",
        "",
    ]
    if report.urls:
        lines.append("Σύνδεσμοι")
        lines.append("─" * 64)
        for i, u in enumerate(report.urls, 1):
            lines.append(f"  {i}. [{u.verdict}]  {u.host or '—'}")
            lines.append(f"     {_c(color, COLORS['dim'], u.url[:160])}")
            if u.filename:
                lines.append(f"     αρχείο: {u.filename[:140]}")
            if u.unwrapped_from:
                lines.append(f"     (από wrapper: {u.unwrapped_from})")
            for f in u.findings:
                if f.points == 0 and f.id == "unwrapped":
                    lines.append(f"       · {f.title}")
                    continue
                lines.append(f"       [{f.severity} +{f.points}] {f.title}")
                lines.append(f"         {f.detail}")
            lines.append("")
    if report.text_findings:
        lines.append("Ενδείξεις στο κείμενο / email")
        lines.append("─" * 64)
        for f in report.text_findings:
            lines.append(f"  [{f.severity} +{f.points}] {f.title}")
            lines.append(f"    {f.detail}")
        lines.append("")
    lines.append("Σύσταση")
    lines.append("─" * 64)
    lines.append(report.advice)
    lines.append("")
    lines.append("Το πρόγραμμα δεν κατεβάζει ούτε ανοίγει τον σύνδεσμο. Η ανάλυση είναι τοπική.")
    return "\n".join(lines)


def report_to_dict(report: ScanReport) -> dict:
    def finding(f):
        return {
            "id": f.id, "severity": f.severity, "points": f.points,
            "title": f.title, "detail": f.detail,
        }

    return {
        "verdict": report.verdict,
        "score": report.score,
        "summary": report.summary,
        "advice": report.advice,
        "text_findings": [finding(f) for f in report.text_findings],
        "urls": [
            {
                "url": u.url,
                "host": u.host,
                "filename": u.filename,
                "decoded_path": u.decoded_path,
                "score": u.score,
                "verdict": u.verdict,
                "unwrapped_from": u.unwrapped_from,
                "findings": [finding(f) for f in u.findings],
            }
            for u in report.urls
        ],
    }


def scan_input(url: str = "", text: str = "", eml_path: str = "") -> ScanReport:
    if eml_path:
        data = Path(eml_path).read_bytes()
        return analyze_eml_bytes(data)
    if text:
        extra = [url] if url else None
        return analyze_text(text, extra_urls=extra)
    if url:
        return analyze_text(url, extra_urls=[url])
    return analyze_text("")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="phishscan",
        description="Τοπικός εντοπισμός phishing συνδέσμων (SharePoint/OneDrive lures, spoofed domains, κ.ά.).",
    )
    p.add_argument("target", nargs="?", help="URL ή αρχείο .eml")
    p.add_argument("-f", "--file", help="Αρχείο .eml / .txt / .html για σάρωση")
    p.add_argument("-t", "--text", help="Κείμενο ή σώμα email")
    p.add_argument("--gui", action="store_true", help="Άνοιγμα παραθύρου")
    p.add_argument("--json", action="store_true", help="Έξοδος JSON")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    if args.gui or (not args.target and not args.file and not args.text and sys.stdin.isatty()):
        from gui import run_gui
        run_gui()
        return 0

    url = ""
    text = args.text or ""
    eml_path = args.file or ""

    if args.target:
        t = args.target
        if Path(t).is_file():
            eml_path = t
        else:
            url = t

    if not url and not text and not eml_path and not sys.stdin.isatty():
        text = sys.stdin.read()

    report = scan_input(url=url, text=text, eml_path=eml_path)
    if args.json:
        json.dump(report_to_dict(report), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        color = (not args.no_color) and sys.stdout.isatty()
        print(render_report(report, color=color))
    return 2 if report.verdict == VERDICT_PHISHING else (1 if report.verdict == VERDICT_SUSPICIOUS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
