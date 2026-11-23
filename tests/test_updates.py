import base64
import io
import json
import os
import zipfile

from core.update_trust import (
    assert_archive_safe, canonical_manifest, manifest_trusted, safe_extract, verify_archive,
)
from tests.conftest import openssl_keypair, openssl_sign


def _signed(tmp_path, manifest):
    os.makedirs(tmp_path, exist_ok=True)
    private, public = openssl_keypair(str(tmp_path))
    payload = canonical_manifest(manifest)
    signature = openssl_sign(private, payload)
    return public, signature, payload


def test_signed_manifest_verifies(tmp_path):
    manifest = {
        "version": "1.2.3",
        "date": "2026-11-23",
        "changelog": ["signed"],
        "url": "https://example.com/fguard.zip",
        "sha256": "ab" * 32,
    }
    public, signature, _payload = _signed(tmp_path, manifest)
    trusted = manifest_trusted(canonical_manifest(manifest), signature, public)
    assert trusted["version"] == "1.2.3"
    assert trusted["sha256"] == "ab" * 32


def test_tampered_checksum_is_rejected(tmp_path):
    manifest = {
        "version": "1.2.3",
        "date": "2026-11-23",
        "changelog": [],
        "url": "https://example.com/fguard.zip",
        "sha256": "ab" * 32,
    }
    public, signature, payload = _signed(tmp_path, manifest)
    edited = json.loads(payload.decode())
    edited["sha256"] = "cd" * 32
    try:
        manifest_trusted(json.dumps(edited).encode(), signature, public)
    except ValueError as exc:
        assert "not valid" in str(exc)
    else:
        raise AssertionError("tampered manifest was accepted")


def test_http_url_is_rejected(tmp_path):
    manifest = {
        "version": "1.2.3",
        "date": "2026-11-23",
        "changelog": [],
        "url": "http://example.com/fguard.zip",
        "sha256": "ab" * 32,
    }
    public, signature, payload = _signed(tmp_path, manifest)
    try:
        manifest_trusted(payload, signature, public)
    except ValueError as exc:
        assert "https" in str(exc)
    else:
        raise AssertionError("http update URL was accepted")


def test_archive_must_match_signed_checksum(tmp_path):
    archive = tmp_path / "update.zip"
    _zip(archive, {"FGUARD-1.0.40/version.json": b'{"version":"1.0.40"}\n'})
    digest = _sha(archive)
    manifest = {
        "version": "1.0.40",
        "date": "2026-11-23",
        "changelog": [],
        "url": "https://example.com/fguard.zip",
        "sha256": digest,
    }
    public, signature, payload = _signed(tmp_path / "keys", manifest)
    trusted = verify_archive(str(archive), payload, signature, public)
    assert trusted["version"] == "1.0.40"
    archive.write_bytes(archive.read_bytes() + b" ")
    try:
        verify_archive(str(archive), payload, signature, public)
    except ValueError as exc:
        assert "checksum" in str(exc)
    else:
        raise AssertionError("altered archive was accepted")


def test_path_traversal_is_rejected(tmp_path):
    archive = tmp_path / "bad.zip"
    payload = _raw_zip({"../outside.txt": b"nope"})
    archive.write_bytes(payload)
    with zipfile.ZipFile(archive) as handle:
        try:
            assert_archive_safe(handle)
        except ValueError as exc:
            assert "unsafe" in str(exc)
        else:
            raise AssertionError("traversal path was accepted")


def test_safe_extract_keeps_files_inside_dest(tmp_path):
    archive = tmp_path / "ok.zip"
    _zip(archive, {"FGUARD/core/app.py": b"print(1)\n"})
    dest = tmp_path / "out"
    safe_extract(str(archive), str(dest))
    assert (dest / "FGUARD" / "core" / "app.py").read_bytes() == b"print(1)\n"


def _sha(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _zip(path, files):
    with zipfile.ZipFile(path, "w") as handle:
        for name, data in files.items():
            handle.writestr(name, data)


def _raw_zip(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            handle.writestr(info, data)
    return buffer.getvalue()


def test_updater_does_not_download_an_unsigned_branch_archive():
    with open("core/updater.py", "r", encoding="utf-8") as handle:
        source = handle.read()
    assert "archive/refs/heads/main.zip" not in source
    assert "manifest_trusted" in source


def test_signature_file_round_trip(tmp_path):
    manifest = {
        "version": "9.9.9",
        "date": "2026-11-23",
        "changelog": ["round trip"],
        "url": "https://example.com/a.zip",
        "sha256": "11" * 32,
    }
    public, signature, payload = _signed(tmp_path, manifest)
    text = base64.b64encode(signature).decode()
    from core.update_trust import parse_signature
    trusted = manifest_trusted(payload, parse_signature(text + "\n"), public)
    assert trusted["changelog"] == ["round trip"]
    assert os.path.isdir(tmp_path)
