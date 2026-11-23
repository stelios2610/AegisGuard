import base64
import json

from core.license_manager import canonical_payload, inspect_key
from tests.conftest import openssl_keypair, openssl_sign


def _license(tmp_path, mac, expires, customer="Acme", tamper=False):
    private, public = openssl_keypair(str(tmp_path))
    fields = {
        "mac": mac,
        "customer": customer,
        "issued": "2026-11-23",
        "expires": expires,
    }
    payload = canonical_payload(fields)
    signature = openssl_sign(private, payload)
    signed = json.loads(payload.decode())
    signed["signature"] = base64.b64encode(signature).decode()
    if tamper:
        signed["customer"] = "Someone else"
    key = base64.b64encode(json.dumps(signed).encode()).decode()
    return key, public


def test_valid_license_matches_mac(tmp_path):
    key, public = _license(tmp_path, "AA:BB:CC:DD:EE:FF", "9999-12-31")
    status, info = inspect_key(key, {"AA:BB:CC:DD:EE:FF"}, public)
    assert status == "valid"
    assert info["customer"] == "Acme"
    assert info["expires"] == "Lifetime"


def test_wrong_mac_is_rejected(tmp_path):
    key, public = _license(tmp_path, "AA:BB:CC:DD:EE:FF", "9999-12-31")
    status, _info = inspect_key(key, {"11:22:33:44:55:66"}, public)
    assert status == "invalid"


def test_expired_license(tmp_path):
    key, public = _license(tmp_path, "AA:BB:CC:DD:EE:FF", "2020-01-01")
    status, info = inspect_key(key, {"AA:BB:CC:DD:EE:FF"}, public)
    assert status == "expired"
    assert info["days_remaining"] < 0


def test_tampered_customer_is_rejected(tmp_path):
    key, public = _license(tmp_path, "AA:BB:CC:DD:EE:FF", "9999-12-31", tamper=True)
    status, _info = inspect_key(key, {"AA:BB:CC:DD:EE:FF"}, public)
    assert status == "invalid"


def test_legacy_unsigned_blob_is_rejected(tmp_path):
    _private, public = openssl_keypair(str(tmp_path))
    blob = base64.b64encode(json.dumps({"v": 1, "mac": "AA:BB:CC:DD:EE:FF"}).encode()).decode()
    status, _info = inspect_key(blob, {"AA:BB:CC:DD:EE:FF"}, public)
    assert status == "invalid"
