"""FGUARD UTC — License Generator (GUI)"""
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import json
import base64
import csv
import os
from datetime import datetime, timedelta

# ── Πρέπει να είναι ΙΔΙΟ με core/license_manager.py ──────────────────────────
SECRET_KEY = "CHANGE_THIS_TO_YOUR_SECRET_KEY"
LOG_FILE = os.path.join(os.path.dirname(__file__), "licenses.csv")
# ─────────────────────────────────────────────────────────────────────────────


def generate_license(mac: str, customer: str, months: int) -> tuple[str, str]:
    expires = (datetime.now() + timedelta(days=30 * months)).strftime("%Y-%m-%d")
    data = {
        "mac": mac.upper().strip(),
        "customer": customer.strip(),
        "issued": datetime.now().strftime("%Y-%m-%d"),
        "expires": expires,
    }
    payload = json.dumps(data, separators=(',', ':'), sort_keys=True)
    signature = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()
    data["signature"] = signature
    key = base64.b64encode(json.dumps(data).encode()).decode()
    return key, expires


def save_log(mac, customer, expires, key):
    exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["Issued", "Customer", "MAC", "Expires", "Key"])
        w.writerow([datetime.now().strftime("%Y-%m-%d"), customer, mac.upper(), expires, key])


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FGUARD UTC — License Generator")
        self.resizable(False, False)
        self.configure(bg="#1e2329")
        self._build_ui()
        self._center()

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"+{x}+{y}")

    def _build_ui(self):
        PAD = {"padx": 18, "pady": 6}
        BG = "#1e2329"
        FG = "#e0e6ed"
        ENTRY_BG = "#161b22"
        ACCENT = "#c0392b"
        FONT = ("Segoe UI", 10)
        FONT_BOLD = ("Segoe UI", 10, "bold")
        FONT_TITLE = ("Segoe UI", 14, "bold")

        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=ACCENT, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🛡  FGUARD UTC", font=("Segoe UI", 16, "bold"),
                 bg=ACCENT, fg="#fff").pack()
        tk.Label(hdr, text="License Generator", font=("Segoe UI", 10),
                 bg=ACCENT, fg="#f5b7b1").pack()

        # ── Form ──────────────────────────────────────────────────────────────
        form = tk.Frame(self, bg=BG, padx=20, pady=16)
        form.pack(fill="x")

        def lbl(text):
            tk.Label(form, text=text, bg=BG, fg="#8b949e",
                     font=FONT, anchor="w").pack(fill="x", pady=(10, 2))

        def entry(var):
            e = tk.Entry(form, textvariable=var, bg=ENTRY_BG, fg=FG,
                         font=FONT, insertbackground=FG,
                         relief="flat", bd=6)
            e.pack(fill="x", ipady=4)
            return e

        self.mac_var = tk.StringVar()
        self.cust_var = tk.StringVar()
        self.months_var = tk.StringVar(value="12")

        lbl("MAC Address συσκευής")
        self.mac_entry = entry(self.mac_var)
        tk.Label(form, text="π.χ.  AA:BB:CC:DD:EE:FF  ή  aa:bb:cc:dd:ee:ff",
                 bg=BG, fg="#555", font=("Segoe UI", 8)).pack(anchor="w")

        lbl("Όνομα Πελάτη")
        entry(self.cust_var)

        lbl("Διάρκεια (μήνες)")
        months_frame = tk.Frame(form, bg=BG)
        months_frame.pack(fill="x")
        for m, txt in [(6, "6 μήνες"), (12, "12 μήνες"), (24, "24 μήνες")]:
            tk.Radiobutton(months_frame, text=txt, variable=self.months_var,
                           value=str(m), bg=BG, fg=FG, selectcolor=ENTRY_BG,
                           activebackground=BG, activeforeground=FG,
                           font=FONT).pack(side="left", padx=(0, 12))

        # ── Generate Button ───────────────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=BG, padx=20, pady=4)
        btn_frame.pack(fill="x")
        tk.Button(btn_frame, text="⚡  Δημιουργία License",
                  command=self._generate,
                  bg=ACCENT, fg="#fff", font=FONT_BOLD,
                  relief="flat", bd=0, pady=10, cursor="hand2",
                  activebackground="#a93226", activeforeground="#fff"
                  ).pack(fill="x")

        # ── Result ────────────────────────────────────────────────────────────
        sep = tk.Frame(self, bg="#30363d", height=1)
        sep.pack(fill="x", padx=20, pady=(14, 0))

        res = tk.Frame(self, bg=BG, padx=20, pady=12)
        res.pack(fill="x")

        tk.Label(res, text="License Key", bg=BG, fg="#8b949e", font=FONT).pack(anchor="w")

        key_frame = tk.Frame(res, bg=ENTRY_BG, bd=0)
        key_frame.pack(fill="x", pady=(2, 6))
        self.key_text = tk.Text(key_frame, height=3, bg=ENTRY_BG, fg="#58a6ff",
                                font=("Consolas", 9), relief="flat", bd=6,
                                wrap="word", state="disabled", cursor="arrow")
        self.key_text.pack(fill="x")
        tk.Button(res, text="📋 Αντιγραφή Key",
                  command=lambda: self._copy(self.key_text.get("1.0", "end").strip()),
                  bg="#21262d", fg=FG, font=FONT, relief="flat", cursor="hand2"
                  ).pack(anchor="e", pady=(0, 10))

        tk.Label(res, text="Εντολές εγκατάστασης (SSH)", bg=BG, fg="#8b949e", font=FONT).pack(anchor="w")

        cmd_frame = tk.Frame(res, bg=ENTRY_BG, bd=0)
        cmd_frame.pack(fill="x", pady=(2, 6))
        self.cmd_text = tk.Text(cmd_frame, height=4, bg=ENTRY_BG, fg="#3fb950",
                                font=("Consolas", 9), relief="flat", bd=6,
                                wrap="none", state="disabled", cursor="arrow")
        self.cmd_text.pack(fill="x")
        tk.Button(res, text="📋 Αντιγραφή Εντολών",
                  command=lambda: self._copy(self.cmd_text.get("1.0", "end").strip()),
                  bg="#21262d", fg=FG, font=FONT, relief="flat", cursor="hand2"
                  ).pack(anchor="e")

        # ── Info bar ─────────────────────────────────────────────────────────
        info = tk.Frame(self, bg="#161b22", padx=20, pady=8)
        info.pack(fill="x")
        self.info_var = tk.StringVar(value="Συμπλήρωσε τα στοιχεία και πάτα «Δημιουργία License»")
        tk.Label(info, textvariable=self.info_var, bg="#161b22", fg="#555",
                 font=("Segoe UI", 9)).pack(anchor="w")

        tk.Button(info, text="📂 Άνοιγμα licenses.csv",
                  command=self._open_log,
                  bg="#161b22", fg="#555", font=("Segoe UI", 8),
                  relief="flat", cursor="hand2").pack(anchor="e")

    def _generate(self):
        mac = self.mac_var.get().strip()
        customer = self.cust_var.get().strip()
        months_str = self.months_var.get()

        if not mac:
            messagebox.showerror("Σφάλμα", "Συμπλήρωσε το MAC address.")
            self.mac_entry.focus()
            return
        if not customer:
            messagebox.showerror("Σφάλμα", "Συμπλήρωσε το όνομα πελάτη.")
            return

        # Normalize MAC (accept with or without colons)
        mac_clean = mac.replace("-", ":").replace(".", ":").upper()
        if len(mac_clean.replace(":", "")) == 12 and ":" not in mac_clean:
            mac_clean = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))

        months = int(months_str) if months_str.isdigit() else 12

        try:
            key, expires = generate_license(mac_clean, customer, months)
            save_log(mac_clean, customer, expires, key)
        except Exception as e:
            messagebox.showerror("Σφάλμα", str(e))
            return

        cmds = (
            f"sudo mkdir -p /etc/aegisguard\n"
            f"echo Balloteli1997 | sudo -S bash -c 'printf \"%s\" \"{key}\" > /etc/aegisguard/license.key'\n"
            f"sudo systemctl restart aegisguard"
        )

        self._set_text(self.key_text, key)
        self._set_text(self.cmd_text, cmds)
        self.info_var.set(f"✅  License για «{customer}» | Λήξη: {expires} | Αποθηκεύτηκε στο licenses.csv")

    def _set_text(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.info_var.set("✅  Αντιγράφηκε στο clipboard!")

    def _open_log(self):
        if os.path.isfile(LOG_FILE):
            os.startfile(LOG_FILE)
        else:
            messagebox.showinfo("Info", "Δεν υπάρχουν licenses ακόμα.")


if __name__ == "__main__":
    app = App()
    app.mainloop()
