"""Shared helpers. Tests never use the production signing key."""
import base64
import os
import subprocess

import pytest


def openssl_keypair(directory):
    private = os.path.join(directory, "private.pem")
    public = os.path.join(directory, "public.pem")
    subprocess.check_call(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", private],
        stdout=subprocess.DEVNULL,
    )
    subprocess.check_call(
        ["openssl", "pkey", "-in", private, "-pubout", "-out", public],
        stdout=subprocess.DEVNULL,
    )
    with open(public, "r", encoding="utf-8") as handle:
        return private, handle.read()


def openssl_sign(private, payload):
    message = os.path.join(os.path.dirname(private), "message.bin")
    signature = os.path.join(os.path.dirname(private), "signature.bin")
    with open(message, "wb") as handle:
        handle.write(payload)
    subprocess.check_call(
        ["openssl", "pkeyutl", "-sign", "-inkey", private, "-rawin", "-in", message, "-out", signature],
        stdout=subprocess.DEVNULL,
    )
    with open(signature, "rb") as handle:
        return handle.read()


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    import db.database as database
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "firewall.db"))
    database.initialize()
    return database


def b64(data):
    return base64.b64encode(data).decode("ascii")
