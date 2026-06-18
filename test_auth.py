import sqlite3, hashlib, hmac

DB = '/opt/aegisguard/firewall.db'
conn = sqlite3.connect(DB)
row = conn.execute("SELECT username, password_hash, enabled FROM vpn_users WHERE username='Stelios'").fetchone()
conn.close()

print('User:', row[0], 'Enabled:', row[2])
print('Hash:', row[1])

# Test auth
password = 'Balloteli1997'
phash = row[1]
print('Hash format ok:', ':' in phash)

parts = phash.split(':', 2)
print('Parts count:', len(parts))

if len(parts) == 3:
    _, salt, stored = parts
    h = hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()
    ok = hmac.compare_digest(h, stored)
    print('Password match:', ok)
else:
    print('Bad hash format:', parts)
