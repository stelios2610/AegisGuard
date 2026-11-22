#!/usr/bin/env python3
"""
FGUARD License Generator.

Signs a license with the Ed25519 private key on this PC. That key is not in
the repository and is not installed on a firewall. Default path:

    ~/.fguard/license-private.pem

Override with FGUARD_LICENSE_PRIVATE_KEY.
"""
import argparse
import base64
import csv
import json
import os
import sys
from datetime import datetime, timedelta

from core.license_manager import canonical_payload

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.csv")
LIFETIME_EXPIRES = "9999-12-31"


def private_key_path():
    override = os.environ.get("FGUARD_LICENSE_PRIVATE_KEY", "").strip()
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".fguard", "license-private.pem")


def _normalize_mac(mac):
    mac = mac.strip().upper().replace("-", ":").replace(".", ":")
    bare = mac.replace(":", "")
    if len(bare) == 12 and ":" not in mac:
        mac = ":".join(bare[i:i + 2] for i in range(0, 12, 2))
    return mac


def _sign(payload):
    path = private_key_path()
    if not os.path.isfile(path):
        raise FileNotFoundError(
            "Private key not found at %s. This file stays on the PC that issues licenses."
            % path
        )
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(path, "rb") as handle:
        key = load_pem_private_key(handle.read(), password=None)
    signature = key.sign(payload)
    if len(signature) != 64:
        raise RuntimeError("license signature had an unexpected length")
    return signature


def generate_license(mac_address, customer_name, months=12, lifetime=False):
    """Return (license_key, expires_label). months=0 or lifetime=True is lifetime."""
    lifetime = lifetime or months == 0
    expires = LIFETIME_EXPIRES if lifetime else (
        datetime.now() + timedelta(days=30 * months)
    ).strftime("%Y-%m-%d")
    issued = datetime.now().strftime("%Y-%m-%d")
    fields = {
        "mac": _normalize_mac(mac_address),
        "customer": customer_name.strip(),
        "issued": issued,
        "expires": expires,
    }
    payload = canonical_payload(fields)
    signed = dict(json.loads(payload.decode()))
    signed["signature"] = base64.b64encode(_sign(payload)).decode()
    key = base64.b64encode(json.dumps(signed).encode()).decode()
    return key, ("LIFETIME" if lifetime else expires)


def save_to_log(mac, customer, expires, key):
    exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if not exists:
            writer.writerow(["Issued", "Customer", "MAC", "Expires", "Key"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d"), customer, mac, expires, key])


def _print_key(customer, mac, expires_label, key):
    print("\n" + "=" * 60)
    print("  Πελάτης : %s" % customer)
    print("  MAC     : %s" % mac)
    print("  Έκδοση  : %s" % datetime.now().strftime("%Y-%m-%d"))
    print("  Λήξη    : %s" % ("LIFETIME (επ' αόριστον)" if expires_label == "LIFETIME" else expires_label))
    print("\n  License Key:")
    print("  %s" % key)
    print("=" * 60)
    print("\n  Εντολές εγκατάστασης στον server (SSH):")
    print("  sudo mkdir -p /etc/fguard")
    print("  sudo bash -c 'printf \"%%s\" \"%s\" > /etc/fguard/license.key'" % key)
    print("  sudo systemctl restart fguard")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(description="FGUARD license generator")
    parser.add_argument("--mac")
    parser.add_argument("--customer")
    parser.add_argument("--months", type=int, default=12)
    parser.add_argument("--lifetime", action="store_true")
    args = parser.parse_args(argv)

    if args.mac or args.customer:
        if not args.mac or not args.customer:
            parser.error("--mac and --customer are both required")
        months = 0 if args.lifetime else args.months
        key, label = generate_license(args.mac, args.customer, months, lifetime=args.lifetime)
        mac = _normalize_mac(args.mac)
        save_to_log(mac, args.customer.strip(), label, key)
        _print_key(args.customer.strip(), mac, label, key)
        return 0

    print("=" * 60)
    print("  FGUARD — License Generator")
    print("=" * 60)
    mac = input("\nMAC address συσκευής (π.χ. AA:BB:CC:DD:EE:FF): ").strip()
    customer = input("Όνομα πελάτη: ").strip()
    print("Διάρκεια: 6 / 12 / 24 μήνες  ή  0 = Lifetime (επ' αόριστον)")
    months_str = input("Επιλογή [12]: ").strip()
    months = int(months_str) if months_str.isdigit() else 12
    key, label = generate_license(mac, customer, months, lifetime=(months == 0))
    mac = _normalize_mac(mac)
    save_to_log(mac, customer, label, key)
    _print_key(customer, mac, label, key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
