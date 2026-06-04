#!/usr/bin/env python3
import sys, sqlite3, hashlib, hmac

DB = '/opt/aegisguard/firewall.db'

try:
    with open(sys.argv[1]) as f:
        lines = f.read().splitlines()
    username = lines[0] if len(lines) > 0 else ''
    password = lines[1] if len(lines) > 1 else ''

    conn = sqlite3.connect(DB)
    row = conn.execute('SELECT password_hash, enabled FROM vpn_users WHERE username=?', (username,)).fetchone()
    conn.close()
    if not row or not row[1]:
        sys.exit(1)
    phash = row[0]
    if ':' not in phash:
        sys.exit(1)
    _, salt, stored = phash.split(':', 2)
    h = hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()
    sys.exit(0 if hmac.compare_digest(h, stored) else 1)
except Exception:
    sys.exit(1)
