import sys, os, subprocess, sqlite3, time
os.chdir('/opt/fguard')
sys.path.insert(0, '/opt/fguard')

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()

print('=== Security Check & Fix ===')
print()

# 1. Check rules table for blocked IPs
print('--- DB: rules table content ---')
conn = sqlite3.connect('/opt/fguard/firewall.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

cur.execute("PRAGMA table_info(rules)")
cols = [r[1] for r in cur.fetchall()]
print('rules columns:', cols)

cur.execute("SELECT * FROM rules LIMIT 20")
rows = cur.fetchall()
for r in rows:
    print(' ', dict(r))

# Check settings for blocked IPs
print()
print('--- DB: settings with IP/block ---')
cur.execute("SELECT key, value FROM settings WHERE key LIKE '%block%' OR key LIKE '%geo%' OR key LIKE '%country%'")
for r in cur.fetchall():
    print(' ', r[0], '=', r[1][:100] if r[1] else None)

# Check blocked_countries
cur.execute("SELECT value FROM settings WHERE key='blocked_countries'")
bc = cur.fetchone()
print('blocked_countries:', bc[0] if bc else 'NOT SET')

# 2. Remove 8.8.8.8 from rules table if present
print()
print('--- Fix: Remove 8.8.8.8 and 1.1.1.1 from rules table ---')
for ip in ['8.8.8.8', '1.1.1.1']:
    for col in cols:
        if 'ip' in col.lower() or 'src' in col.lower() or 'source' in col.lower() or 'addr' in col.lower():
            cur.execute("SELECT count(*) FROM rules WHERE %s=?" % col, (ip,))
            cnt = cur.fetchone()[0]
            if cnt:
                cur.execute("DELETE FROM rules WHERE %s=?" % col, (ip,))
                print('  Deleted %d rows where %s=%s' % (cnt, col, ip))

# Also check for IPS blocks in any table
for ip in ['8.8.8.8', '1.1.1.1']:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for (tname,) in cur.fetchall():
        try:
            cur.execute("SELECT count(*) FROM %s WHERE instr(cast(value as text), ?) > 0 OR instr(cast(action as text), ?) > 0" % tname, (ip, ip))
        except:
            pass

conn.commit()
conn.close()

# 3. Remove from iptables
print()
print('--- Fix: Remove 8.8.8.8 from iptables INPUT ---')
# Delete all rules matching 8.8.8.8 from INPUT
out, _ = sh('iptables -L INPUT -n --line-numbers')
lines = out.split('\n')
to_delete = []
for line in lines:
    if '8.8.8.8' in line or '1.1.1.1' in line:
        num = line.strip().split()[0]
        if num.isdigit():
            to_delete.append(int(num))

# Delete from highest to lowest (avoid number shifting)
for num in sorted(to_delete, reverse=True):
    ok, err = sh('iptables -D INPUT %d' % num)
    print('  Deleted INPUT rule %d: %s' % (num, 'ok' if not err else err))

# 4. Reconnect FGUARD_INPUT to INPUT chain
print()
print('--- Fix: Reconnect FGUARD_INPUT ---')
out, _ = sh('iptables -L INPUT -n | grep FGUARD')
if 'FGUARD_INPUT' in out:
    print('  FGUARD_INPUT already in INPUT chain - ok')
else:
    # Insert after the WAN DROP rules (ens1-specific), before the ACCEPT all from LAN
    # Find position of first ACCEPT rule
    out, _ = sh('iptables -L INPUT -n --line-numbers')
    pos = 5  # default
    for line in out.split('\n'):
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1] == 'ACCEPT':
            pos = int(parts[0])
            break
    ok, err = sh('iptables -I INPUT %d -j FGUARD_INPUT' % pos)
    print('  Inserted FGUARD_INPUT at position %d: %s' % (pos, 'ok' if not err else err))

# 5. Add "safe IPs" to IPS whitelist (prevent 8.8.8.8/1.1.1.1 from being auto-blocked)
print()
print('--- Fix: Add DNS servers to IPS safe list ---')
conn = sqlite3.connect('/opt/fguard/firewall.db')
# Check if there's a whitelist/safe_ips setting
cur = conn.cursor()
cur.execute("SELECT value FROM settings WHERE key='ips_safe_ips'")
row = cur.fetchone()
import json
safe = json.loads(row[0]) if row and row[0] else []
print('  Current safe IPs:', safe)
for ip in ['8.8.8.8', '1.1.1.1', '8.8.4.4', '9.9.9.9']:
    if ip not in safe:
        safe.append(ip)
conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ips_safe_ips', ?)", (json.dumps(safe),))
conn.commit()
conn.close()
print('  Safe IPs updated:', safe)

# 6. Show final status
print()
print('--- Final: INPUT chain ---')
out, _ = sh('iptables -L INPUT -n --line-numbers')
print(out)

print()
print('--- Final: FGUARD_INPUT chain ---')
out, _ = sh('iptables -L FGUARD_INPUT -n --line-numbers')
print(out)

print()
print('--- Final: Blocked countries ---')
conn = sqlite3.connect('/opt/fguard/firewall.db')
cur = conn.cursor()
cur.execute("SELECT value FROM settings WHERE key='blocked_countries'")
bc = cur.fetchone()
print('blocked_countries:', bc[0] if bc else 'NOT SET (geoblock disabled)')
conn.close()

print()
print('=== Done ===')
