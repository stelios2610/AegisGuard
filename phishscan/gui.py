"""PhishScan desktop window (tkinter — included with Python on Windows)."""
from __future__ import annotations

import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import VERDICT_CLEAN, VERDICT_PHISHING, VERDICT_SUSPICIOUS, analyze_eml_bytes, analyze_text
from phishscan import render_report

WIN = sys.platform == "win32"
FONT_UI = ("Segoe UI", 10) if WIN else ("DejaVu Sans", 10)
FONT_UI_BOLD = ("Segoe UI", 13, "bold") if WIN else ("DejaVu Sans", 13, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold") if WIN else ("DejaVu Sans", 16, "bold")
FONT_SMALL = ("Segoe UI", 9) if WIN else ("DejaVu Sans", 9)
FONT_MONO = ("Consolas", 10) if WIN else ("DejaVu Sans Mono", 10)


BG = "#0f1419"
CARD = "#1a222c"
FG = "#e8eef4"
MUTED = "#8b9aab"
ACCENT = "#3d8bfd"
RED = "#e35d6a"
ORANGE = "#e0a54b"
GREEN = "#3dd68c"


class PhishScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishScan — έλεγχος phishing συνδέσμων")
        self.geometry("920x720")
        self.minsize(760, 560)
        self.configure(bg=BG)
        self._build_style()
        self._build()

    def _build_style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=BG, foreground=FG, fieldbackground=CARD)
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=CARD)
        s.configure("TLabel", background=BG, foreground=FG, font=FONT_UI)
        s.configure("Muted.TLabel", background=BG, foreground=MUTED, font=FONT_SMALL)
        s.configure("Title.TLabel", background=BG, foreground=FG, font=FONT_TITLE)
        s.configure("TButton", font=FONT_UI, padding=8)
        s.configure("Accent.TButton", background=ACCENT, foreground="#fff")
        s.map("Accent.TButton", background=[("active", "#5aa2ff")])

    def _build(self):
        pad = ttk.Frame(self)
        pad.pack(fill="both", expand=True, padx=18, pady=16)

        ttk.Label(pad, text="PhishScan", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            pad,
            text="Τοπικός έλεγχος. Δεν ανοίγει ο σύνδεσμος και δεν στέλνει τίποτα στο διαδίκτυο.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 12))

        ttk.Label(pad, text="URL, κείμενο email, ή επικόλληση από το Outlook").pack(anchor="w")
        self.input = tk.Text(
            pad, height=8, wrap="word", bg=CARD, fg=FG, insertbackground=FG,
            relief="flat", font=FONT_MONO, highlightthickness=1,
            highlightbackground="#2a3542", highlightcolor=ACCENT,
        )
        self.input.pack(fill="x", pady=(4, 8))
        self.input.bind("<Control-Return>", lambda e: self.scan())

        btns = ttk.Frame(pad)
        btns.pack(fill="x", pady=(0, 10))
        ttk.Button(btns, text="Έλεγχος", style="Accent.TButton", command=self.scan).pack(side="left")
        ttk.Button(btns, text="Άνοιγμα αρχείου .eml", command=self.open_eml).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Καθαρισμός", command=self.clear).pack(side="left", padx=(8, 0))

        self.badge = tk.Label(
            pad, text="—", bg=CARD, fg=MUTED, font=FONT_UI_BOLD,
            padx=12, pady=8, anchor="w",
        )
        self.badge.pack(fill="x", pady=(0, 8))

        ttk.Label(pad, text="Αποτέλεσμα", style="Muted.TLabel").pack(anchor="w")
        self.out = tk.Text(
            pad, wrap="word", bg=CARD, fg=FG, relief="flat", font=FONT_MONO,
            state="disabled", highlightthickness=1, highlightbackground="#2a3542",
        )
        self.out.pack(fill="both", expand=True, pady=(4, 0))

        self.input.focus_set()

    def clear(self):
        self.input.delete("1.0", "end")
        self._set_out("")
        self._set_badge("—", MUTED)

    def open_eml(self):
        path = filedialog.askopenfilename(
            title="Επιλογή email",
            filetypes=[
                ("Email", "*.eml *.txt *.html *.htm"),
                ("Όλα", "*.*"),
            ],
        )
        if not path:
            return
        try:
            raw = Path(path).read_bytes()
            if path.lower().endswith(".eml"):
                report = analyze_eml_bytes(raw)
            else:
                report = analyze_text(raw.decode("utf-8", errors="replace"))
            self._show(report)
        except OSError as e:
            messagebox.showerror("PhishScan", f"Δεν μπόρεσα να διαβάσω το αρχείο:\n{e}")

    def scan(self):
        blob = self.input.get("1.0", "end").strip()
        if not blob:
            messagebox.showinfo("PhishScan", "Επικολλήστε ένα URL ή το κείμενο ενός email.")
            return
        report = analyze_text(blob)
        self._show(report)

    def _show(self, report):
        color = {VERDICT_PHISHING: RED, VERDICT_SUSPICIOUS: ORANGE, VERDICT_CLEAN: GREEN}[report.verdict]
        label = {
            VERDICT_PHISHING: f"PHISHING   βαθμός {report.score}   — μην ανοίξετε τον σύνδεσμο",
            VERDICT_SUSPICIOUS: f"ΎΠΟΠΤΟ   βαθμός {report.score}   — μην το ανοίξετε χωρίς επιβεβαίωση",
            VERDICT_CLEAN: f"ΚΑΘΑΡΟ   βαθμός {report.score}   — δεν βρέθηκαν τα κλασικά σημάδια",
        }[report.verdict]
        self._set_badge(label, color)
        self._set_out(render_report(report, color=False))

    def _set_badge(self, text, color):
        self.badge.configure(text=text, fg=color, bg=CARD)

    def _set_out(self, text):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)
        self.out.configure(state="disabled")


def run_gui():
    app = PhishScanApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
