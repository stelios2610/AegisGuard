import sys, os, subprocess, sqlite3, time
os.chdir('/opt/aegisguard')
sys.path.insert(0, '/opt/aegisguard')

def ipt(args):
    r = subprocess.run(['iptables'] + args, capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout.strip()

print('=== Fix: Restore Internet Access ===')
print()

# Step 1: Remove bad INPUT rules by number (top to bottom, re-index after each)
# Current order: 1=8.8.8.8, 2=1.1.1.1, 3=ssh/22, 4=udp/53, 5=tcp/53, 6=443, 7=80, 8=8080

print('Step 1: Remove broken iptables INPUT rules ...')

# Delete rule 1 (8.8.8.8)
ok, msg = ipt(['-D', 'INPUT', '1'])
print('  Removed 8.8.8.8 block:', ok, msg or 'ok')

# Delete rule 1 again (now 1.1.1.1)
ok, msg = ipt(['-D', 'INPUT', '1'])
print('  Removed 1.1.1.1 block:', ok, msg or 'ok')

# Rule 1 is now SSH/22 — KEEP IT, delete rule 2 onwards
# Rule 2 = udp/53
ok, msg = ipt(['-D', 'INPUT', '2'])
print('  Removed udp/53 block:', ok, msg or 'ok')

# Rule 2 = tcp/53
ok, msg = ipt(['-D', 'INPUT', '2'])
print('  Removed tcp/53 block:', ok, msg or 'ok')

# Rule 2 = tcp/443
ok, msg = ipt(['-D', 'INPUT', '2'])
print('  Removed tcp/443 block:', ok, msg or 'ok')

# Rule 2 = tcp/80
ok, msg = ipt(['-D', 'INPUT', '2'])
print('  Removed tcp/80 block:', ok, msg or 'ok')

# Rule 2 = tcp/8080
ok, msg = ipt(['-D', 'INPUT', '2'])
print('  Removed tcp/8080 block:', ok, msg or 'ok')

# Step 2: Add back WAN-only port blocks (block from ens1 only, not LAN)
print()
print('Step 2: Add proper WAN-only protections ...')

# Block web UI (8080) from WAN only
ok, msg = ipt(['-I', 'INPUT', '2', '-i', 'ens1', '-p', 'tcp', '--dport', '8080', '-j', 'DROP'])
print('  Block 8080 from WAN:', ok, msg or 'ok')

# Block external DNS queries to server from WAN only
ok, msg = ipt(['-I', 'INPUT', '2', '-i', 'ens1', '-p', 'udp', '--dport', '53', '-j', 'DROP'])
print('  Block udp/53 from WAN:', ok, msg or 'ok')
ok, msg = ipt(['-I', 'INPUT', '2', '-i', 'ens1', '-p', 'tcp', '--dport', '53', '-j', 'DROP'])
print('  Block tcp/53 from WAN:', ok, msg or 'ok')

# Step 3: Remove 8.8.8.8 and 1.1.1.1 from AegisGuard DB
print()
print('Step 3: Remove 8.8.8.8 and 1.1.1.1 from DB ...')
conn = sqlite3.connect('/opt/aegisguard/firewall.db')
cur = conn.cursor()

# Find what table blocked IPs are in
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]
print('  Tables:', tables)

deleted = 0
for table in tables:
    try:
        cur.execute("PRAGMA table_info(%s)" % table)
        cols = [r[1] for r in cur.fetchall()]
        if any(c in cols for c in ['ip', 'ip_address', 'source_ip', 'address']):
            ip_col = next(c for c in ['ip', 'ip_address', 'source_ip', 'address'] if c in cols)
            cur.execute("SELECT count(*) FROM %s WHERE %s IN ('8.8.8.8','1.1.1.1')" % (table, ip_col))
            cnt = cur.fetchone()[0]
            if cnt:
                cur.execute("DELETE FROM %s WHERE %s IN ('8.8.8.8','1.1.1.1')" % (table, ip_col))
                print('  Deleted %d rows from %s.%s' % (cnt, table, ip_col))
                deleted += cnt
    except Exception as e:
        pass

conn.commit()
conn.close()
if deleted == 0:
    print('  No entries found (may have been removed already)')

# Step 4: Restart dnsmasq
print()
print('Step 4: Restart dnsmasq ...')
subprocess.run('systemctl restart dnsmasq', shell=True)
time.sleep(3)
status = sh('systemctl is-active dnsmasq')
print('  dnsmasq status:', status)
if status != 'active':
    print(sh('journalctl -u dnsmasq -n 10 --no-pager'))

# Step 5: Test DNS and connectivity
print()
print('Step 5: Test connectivity ...')
# Test DNS
r = subprocess.run(['dig', '+short', 'google.com', '@8.8.8.8', '+time=3'], capture_output=True, text=True)
if r.stdout.strip():
    print('  DNS via 8.8.8.8: OK ->', r.stdout.strip().split()[0])
else:
    print('  DNS via 8.8.8.8: FAIL ->', r.stderr.strip() or 'no response')

r = subprocess.run(['dig', '+short', 'google.com', '@127.0.0.1', '+time=3'], capture_output=True, text=True)
if r.stdout.strip():
    print('  DNS via dnsmasq (127.0.0.1): OK ->', r.stdout.strip().split()[0])
else:
    print('  DNS via dnsmasq: FAIL ->', r.stderr.strip() or 'no response')

# Test HTTP
r = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5', 'http://google.com'],
                   capture_output=True, text=True)
print('  HTTP google.com:', r.stdout.strip())

# Step 6: Show final INPUT chain (first 12 rules)
print()
print('Step 6: Final INPUT chain (first 12 rules) ...')
print(sh('iptables -L INPUT -n --line-numbers | head -15'))

print()
print('=== DONE ===')
print('If dnsmasq shows active and DNS tests pass, internet should work.')
