#!/usr/bin/env python3
"""
FGUARD UTC License Generator
Run on YOUR PC to generate license keys for customers.
NEVER share this file or commit it with the real SECRET_KEY.
"""
import hashlib
import json
import base64
import csv
import os
from datetime import datetime, timedelta

# Must match core/license_manager.py SECRET_KEY — keep this PRIVATE
SECRET_KEY = "CHANGE_THIS_TO_YOUR_SECRET_KEY"

LOG_FILE = "licenses.csv"


LIFETIME_EXPIRES = "9999-12-31"


def generate_license(mac_address: str, customer_name: str, months: int = 12, lifetime: bool = False) -> str:
    expires = LIFETIME_EXPIRES if lifetime else (datetime.now() + timedelta(days=30 * months)).strftime("%Y-%m-%d")
    data = {
        "mac": mac_address.upper().strip(),
        "customer": customer_name.strip(),
        "issued": datetime.now().strftime("%Y-%m-%d"),
        "expires": expires,
    }
    payload = json.dumps(data, separators=(',', ':'), sort_keys=True)
    signature = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()
    data["signature"] = signature
    return base64.b64encode(json.dumps(data).encode()).decode()


def save_to_log(mac, customer, expires, key):
    exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["Issued", "Customer", "MAC", "Expires", "Key"])
        w.writerow([datetime.now().strftime("%Y-%m-%d"), customer, mac, expires, key])


if __name__ == "__main__":
    print("=" * 60)
    print("  FGUARD UTC — License Generator")
    print("=" * 60)

    mac = input("\nMAC address συσκευής (π.χ. AA:BB:CC:DD:EE:FF): ").strip()
    customer = input("Όνομα πελάτη: ").strip()
    print("Διάρκεια: 6 / 12 / 24 μήνες  ή  0 = Lifetime (επ' αόριστον)")
    months_str = input("Επιλογή [12]: ").strip()
    months = int(months_str) if months_str.isdigit() else 12
    lifetime = (months == 0)

    key = generate_license(mac, customer, months if not lifetime else 0, lifetime=lifetime)
    expires = LIFETIME_EXPIRES if lifetime else (datetime.now() + timedelta(days=30 * months)).strftime("%Y-%m-%d")

    save_to_log(mac, customer, "LIFETIME" if lifetime else expires, key)

    print("\n" + "=" * 60)
    print(f"  Πελάτης : {customer}")
    print(f"  MAC     : {mac.upper()}")
    print(f"  Έκδοση  : {datetime.now().strftime('%Y-%m-%d')}")
    print(f"  Λήξη    : {'LIFETIME (επ\' αόριστον)' if lifetime else expires}")
    print(f"\n  License Key:")
    print(f"  {key}")
    print("=" * 60)
    print("\n  Εντολές εγκατάστασης στον server (SSH):")
    print(f'  echo Balloteli1997 | sudo -S mkdir -p /etc/aegisguard')
    print(f'  echo Balloteli1997 | sudo -S bash -c \'printf "%s" "{key}" > /etc/aegisguard/license.key\'')
    print(f'  echo Balloteli1997 | sudo -S systemctl restart aegisguard')
    print()
