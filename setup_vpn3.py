import sys, os, subprocess
os.chdir('/opt/aegisguard')
sys.path.insert(0, '/opt/aegisguard')
from db import database
from core import ssl_vpn
from core.mfa import hash_password

PKI = '/etc/openvpn/aegisguard-pki'

def read(p):
    try:
        with open(p) as f: return f.read()
    except Exception as e:
        print(f'  WARN: cannot read {p}: {e}')
        return ''

# 1. Save PKI to DB
print('Step 1: Saving PKI to DB...')
database.save_ssl_vpn_config(
    pki_dir=PKI,
    ca_cert=read(f'{PKI}/ca.crt'),
    server_cert=read(f'{PKI}/server.crt'),
    server_key=read(f'{PKI}/server.key'),
    dh_params=read(f'{PKI}/dh.pem'),
    ta_key=read(f'{PKI}/ta.key'),
    port=1194,
    protocol='udp',
    server_subnet='10.8.0.0',
    server_netmask='255.255.255.0',
    dns1='10.8.0.1',
    dns2='1.1.1.1',
    cipher='AES-256-GCM',
    auth='SHA256',
    tls_version='1.2',
    compress=1,
    status='Running'
)
cfg = database.get_ssl_vpn_config()
print(f'  ca_cert saved: {bool(cfg.get("ca_cert"))}')
print(f'  ta_key saved:  {bool(cfg.get("ta_key"))}')
print(f'  dh_params saved: {bool(cfg.get("dh_params"))}')

# 2. Write server config (username/password auth via script)
print('\nStep 2: Writing server config with user/password auth...')
ok, msg = ssl_vpn.write_server_config()
print(f'  {msg}')

# 3. Write auth script (fix DB path)
print('\nStep 3: Writing auth scripts...')
os.makedirs('/etc/aegisguard', exist_ok=True)

auth_sh = """#!/bin/bash
/usr/bin/python3 /etc/aegisguard/vpn_auth_check.py "$1"
"""
auth_check = """#!/usr/bin/env python3
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
    username = lines[0] if lines else ''
    password = lines[1] if len(lines) > 1 else ''

    conn = sqlite3.connect(DB)
    row = conn.execute(
        'SELECT password_hash, enabled FROM vpn_users WHERE username=?',
        (username,)
    ).fetchone()
    conn.close()
    if not row or not row[1]:
        sys.exit(1)
    phash = row[0]
    if not phash or ':' not in phash:
        sys.exit(1)
    if phash.startswith('bcrypt:'):
        if not _BCRYPT_OK:
            sys.exit(1)
        sys.exit(0 if _bcrypt.checkpw(password.encode(), phash[7:].encode()) else 1)
    else:
        parts = phash.split(':', 2)
        if len(parts) != 3:
            sys.exit(1)
        _, salt, stored = parts
        h = hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()
        sys.exit(0 if hmac.compare_digest(h, stored) else 1)
except Exception:
    sys.exit(1)
"""
with open('/etc/aegisguard/vpn-auth.sh', 'w') as f: f.write(auth_sh)
with open('/etc/aegisguard/vpn_auth_check.py', 'w') as f: f.write(auth_check)
os.chmod('/etc/aegisguard/vpn-auth.sh', 0o755)
os.chmod('/etc/aegisguard/vpn_auth_check.py', 0o755)
print('  Auth scripts written OK')

# 4. Add VPN user
print('\nStep 4: Adding VPN user "stelios"...')
existing = database.get_vpn_user_by_username('stelios')
if existing:
    print('  User "stelios" already exists, skipping')
else:
    pw_hash = hash_password('Balloteli1997')
    database.add_vpn_user(
        username='stelios',
        password_hash=pw_hash,
        full_name='Stelios',
        enabled=1
    )
    print('  User "stelios" added with password Balloteli1997')

# 5. Generate .ovpn for user
print('\nStep 5: Generating .ovpn for user "stelios"...')
user = database.get_vpn_user_by_username('stelios')
wan_ip = database.get_setting('wan_ip', '')
if not wan_ip:
    database.set_setting('wan_ip', '2.84.117.79')
    wan_ip = '2.84.117.79'
print(f'  WAN IP: {wan_ip}')
config_path, content = ssl_vpn.generate_user_config(user, server_ip=wan_ip)
print(f'  Config: {config_path}')
# Copy to /tmp for easy download
import shutil
shutil.copy(config_path, '/tmp/stelios.ovpn')
print(f'  Also at: /tmp/stelios.ovpn')

# 6. Restart OpenVPN with new config
print('\nStep 6: Restarting OpenVPN...')
ret = subprocess.run('systemctl restart openvpn-server@server', shell=True, capture_output=True, text=True)
import time; time.sleep(4)
ret2 = subprocess.run('systemctl is-active openvpn-server@server', shell=True, capture_output=True, text=True)
print(f'  Status: {ret2.stdout.strip()}')
if ret2.stdout.strip() != 'active':
    ret3 = subprocess.run('journalctl -u openvpn-server@server -n 10 --no-pager', shell=True, capture_output=True, text=True)
    print(ret3.stdout[-1000:])

print('\nDONE.')
print('Users can now download their .ovpn from the Web UI: VPN → Users → Download Config')
