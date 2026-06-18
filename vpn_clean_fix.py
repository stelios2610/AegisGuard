import sys, os, subprocess, shutil, hashlib, time
os.chdir('/opt/aegisguard')
sys.path.insert(0, '/opt/aegisguard')
from core import ssl_vpn
from db import database
from core.mfa import hash_password

PKI = ssl_vpn.PKI_DIR  # /opt/aegisguard/pki/ssl-vpn

def read(p):
    with open(p) as f:
        return f.read()

print('=== VPN Clean Fix ===')
print('PKI dir:', PKI)
print()

# 1. Stop running OpenVPN
print('Step 1: Stop OpenVPN ...')
subprocess.run('systemctl stop openvpn-server@server', shell=True)
subprocess.run('pkill -f openvpn', shell=True)
time.sleep(2)
r = subprocess.run('pgrep -a openvpn', shell=True, capture_output=True, text=True)
print('  After kill:', r.stdout.strip() or 'no processes (good)')

# 2. Verify PKI files
print()
print('Step 2: Verify original PKI files ...')
needed = ['ca.crt', 'ca.key', 'server.crt', 'server.key', 'dh.pem', 'ta.key']
for fn in needed:
    p = os.path.join(PKI, fn)
    exists = os.path.isfile(p)
    size = os.path.getsize(p) if exists else 0
    print('  %s: %s' % (fn, 'OK (%d bytes)' % size if exists else 'MISSING'))

# 3. Save correct PKI to DB
print()
print('Step 3: Save original PKI to DB ...')
database.save_ssl_vpn_config(
    pki_dir=PKI,
    ca_cert=read('%s/ca.crt' % PKI),
    server_cert=read('%s/server.crt' % PKI),
    server_key=read('%s/server.key' % PKI),
    dh_params=read('%s/dh.pem' % PKI),
    ta_key=read('%s/ta.key' % PKI),
    port=1194, protocol='udp',
    server_subnet='10.8.0.0', server_netmask='255.255.255.0',
    dns1='1.1.1.1', dns2='8.8.8.8',
    cipher='AES-256-GCM', auth='SHA256', tls_version='1.2',
    compress=0, status='Ready'
)
cfg = database.get_ssl_vpn_config()
ta_in_db = cfg.get('ta_key', '')
ta_on_disk = read('%s/ta.key' % PKI)
ta_match = ta_in_db.strip() == ta_on_disk.strip()
print('  ta_key in DB matches disk file:', ta_match)

# 4. Write server config
print()
print('Step 4: Write server config ...')
ok, msg = ssl_vpn.write_server_config()
print('  Result:', ok, msg)

# 5. Write auth scripts
print()
print('Step 5: Write auth scripts ...')
os.makedirs('/etc/aegisguard', exist_ok=True)

auth_sh = '#!/bin/bash\n/usr/bin/python3 /etc/aegisguard/vpn_auth_check.py "$1"\n'

auth_check = '''#!/usr/bin/env python3
import sys, sqlite3, hashlib, hmac

DB = '/opt/aegisguard/firewall.db'

try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

try:
    with open(sys.argv[1]) as f:
        lines = f.read().splitlines()
    username = lines[0] if lines else ""
    password = lines[1] if len(lines) > 1 else ""

    conn = sqlite3.connect(DB)
    row = conn.execute(
        "SELECT password_hash, enabled FROM vpn_users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()
    if not row or not row[1]:
        sys.exit(1)
    phash = row[0]
    if not phash or ":" not in phash:
        sys.exit(1)
    if phash.startswith("bcrypt:"):
        if not _BCRYPT_OK:
            sys.exit(1)
        sys.exit(0 if _bcrypt.checkpw(password.encode(), phash[7:].encode()) else 1)
    else:
        parts = phash.split(":", 2)
        if len(parts) != 3:
            sys.exit(1)
        _, salt, stored = parts
        h = hashlib.sha256(("%s%s" % (salt, password)).encode()).hexdigest()
        sys.exit(0 if hmac.compare_digest(h, stored) else 1)
except Exception:
    sys.exit(1)
'''

with open('/etc/aegisguard/vpn-auth.sh', 'w') as f:
    f.write(auth_sh)
with open('/etc/aegisguard/vpn_auth_check.py', 'w') as f:
    f.write(auth_check)
os.chmod('/etc/aegisguard/vpn-auth.sh', 0o755)
os.chmod('/etc/aegisguard/vpn_auth_check.py', 0o755)
print('  Auth scripts written OK')

# 6. Copy server config to systemd location
print()
print('Step 6: Copy server config to systemd location ...')
os.makedirs('/etc/openvpn/server', exist_ok=True)
shutil.copy(ssl_vpn.SERVER_CONF, '/etc/openvpn/server/server.conf')
print('  Copied:', ssl_vpn.SERVER_CONF, '->', '/etc/openvpn/server/server.conf')

# Verify ta.key in server.conf matches PKI
sc = open('/etc/openvpn/server/server.conf').read()
if ta_on_disk.strip() in sc:
    print('  ta.key in server.conf: MATCHES disk (good)')
else:
    print('  ta.key in server.conf: MISMATCH - something is wrong!')

# 7. Start server
print()
print('Step 7: Start OpenVPN server ...')
subprocess.run('systemctl enable --now openvpn-server@server', shell=True)
time.sleep(5)
r = subprocess.run('systemctl is-active openvpn-server@server', shell=True, capture_output=True, text=True)
status = r.stdout.strip()
print('  Status:', status)
if status != 'active':
    r2 = subprocess.run('journalctl -u openvpn-server@server -n 25 --no-pager', shell=True, capture_output=True, text=True)
    print(r2.stdout[-2000:])
else:
    r2 = subprocess.run('ip addr show tun0', shell=True, capture_output=True, text=True)
    print('  tun0:', r2.stdout.strip() or 'not found')

# 8. Ensure VPN user exists
print()
print('Step 8: Setup VPN user ...')
# Remove duplicate 'Stelios' user if exists
for u in database.get_vpn_users():
    print('  Existing user:', u['username'])
    if u['username'] == 'Stelios':
        # delete via DB directly
        import sqlite3 as _sq
        conn2 = _sq.connect('/opt/aegisguard/firewall.db')
        conn2.execute('DELETE FROM vpn_users WHERE username=?', ('Stelios',))
        conn2.commit()
        conn2.close()
        print('  Deleted duplicate user: Stelios')

u = database.get_vpn_user_by_username('stelios')
if not u:
    ph = hash_password('Balloteli1997')
    database.add_vpn_user('stelios', ph, full_name='Stelios', enabled=1)
    u = database.get_vpn_user_by_username('stelios')
    print('  Created user: stelios')
else:
    print('  User stelios: exists (id=%s)' % u.get('id'))

# 9. Generate .ovpn
print()
print('Step 9: Generate .ovpn ...')
config_path, content = ssl_vpn.generate_user_config(u, server_ip='2.84.117.79')
print('  Config path:', config_path)
if config_path and os.path.isfile(config_path):
    shutil.copy(config_path, '/tmp/stelios-final.ovpn')
    print('  Also saved to: /tmp/stelios-final.ovpn')
    size = os.path.getsize(config_path)
    print('  File size:', size, 'bytes')
else:
    print('  ERROR: config not generated!')
    print('  content length:', len(content) if content else 0)

# 10. Verify ta.key matches between server and client
print()
print('Step 10: Verify ta.key match ...')
if content:
    def extract_block(text, tag):
        lines = text.split('\n')
        in_block = False
        result = []
        for l in lines:
            if '<%s>' % tag in l:
                in_block = True
                continue
            if '</%s>' % tag in l:
                break
            if in_block and l.strip() and not l.startswith('#'):
                result.append(l.strip())
        return '\n'.join(result)

    sc = open('/etc/openvpn/server/server.conf').read()
    server_ta = extract_block(sc, 'tls-auth')
    client_ta = extract_block(content, 'tls-auth')
    sh = hashlib.md5(server_ta.encode()).hexdigest()
    ch = hashlib.md5(client_ta.encode()).hexdigest()
    print('  Server ta.key md5:', sh)
    print('  Client ta.key md5:', ch)
    print('  MATCH:', sh == ch)
    if sh != ch:
        print('  WARNING: ta.key mismatch! This will cause TLS auth failures.')

print()
print('=== DONE ===')
print('Download /tmp/stelios-final.ovpn and import to OpenVPN Connect on phone')
print('Username: stelios')
print('Password: Balloteli1997')
