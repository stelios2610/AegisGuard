#!/usr/bin/env python3
"""Sign an FGUARD update manifest.

The private key is the license key at ~/.fguard/license-private.pem
(override with FGUARD_LICENSE_PRIVATE_KEY). It never goes on a firewall.
Publish the written version.json and version.json.sig next to each other.
The appliance downloads only the https URL inside the signed manifest and
keeps the zip only when its sha256 matches.

    python sign_update.py --zip dist/fguard.zip \\
        --url https://example.com/fguard-1.0.40.zip \\
        --version-file version.json --out-dir publish/
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

from core.update_trust import canonical_manifest


def _private_key_path():
    override = os.environ.get("FGUARD_LICENSE_PRIVATE_KEY", "").strip()
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".fguard", "license-private.pem")


def _sign(payload, key_path):
    if not os.path.isfile(key_path):
        raise FileNotFoundError(
            "Private key not found at %s. This file stays on the PC that publishes updates."
            % key_path
        )
    with tempfile.TemporaryDirectory() as tmp:
        msg = os.path.join(tmp, "msg.bin")
        sig = os.path.join(tmp, "sig.bin")
        with open(msg, "wb") as handle:
            handle.write(payload)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", key_path, "-rawin", "-in", msg, "-out", sig],
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(detail or "openssl could not sign the update manifest")
        with open(sig, "rb") as handle:
            signature = handle.read()
    if len(signature) != 64:
        raise RuntimeError("update signature had an unexpected length")
    return signature


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(version_file, zip_path, url):
    with open(version_file, "r", encoding="utf-8") as handle:
        current = json.load(handle)
    if not str(url).startswith("https://"):
        raise ValueError("update URL must be https")
    return {
        "version": str(current.get("version", "")),
        "date": str(current.get("date", "")),
        "changelog": [str(item) for item in (current.get("changelog") or [])],
        "url": str(url),
        "sha256": _sha256(zip_path),
    }


def write_signed_manifest(manifest, out_dir, key_path=None):
    os.makedirs(out_dir, exist_ok=True)
    payload = canonical_manifest(manifest)
    signature = _sign(payload, key_path or _private_key_path())
    document = os.path.join(out_dir, "version.json")
    sig_path = os.path.join(out_dir, "version.json.sig")
    with open(document, "w", encoding="utf-8") as handle:
        json.dump(json.loads(payload.decode()), handle, indent=2)
        handle.write("\n")
    with open(sig_path, "w", encoding="ascii") as handle:
        handle.write(base64.b64encode(signature).decode("ascii") + "\n")
    return document, sig_path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sign an FGUARD update manifest")
    parser.add_argument("--zip", required=True, help="Archive the appliance will download")
    parser.add_argument("--url", required=True, help="https URL of that exact archive")
    parser.add_argument("--version-file", default="version.json")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    manifest = build_manifest(args.version_file, args.zip, args.url)
    document, sig_path = write_signed_manifest(manifest, args.out_dir)
    print("Signed %s" % manifest["version"])
    print("sha256 %s" % manifest["sha256"])
    print("manifest %s" % document)
    print("signature %s" % sig_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
