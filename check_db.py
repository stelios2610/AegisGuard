import sqlite3

conn = sqlite3.connect('/opt/aegisguard/firewall.db')
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('Tables:', [t[0] for t in tables])

if any(t[0] == 'vpn_users' for t in tables):
    users = conn.execute("SELECT id, username, enabled FROM vpn_users").fetchall()
    print('VPN users:', users)
else:
    print('vpn_users table does not exist')

conn.close()
