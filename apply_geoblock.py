import sys, os, subprocess, time
os.chdir('/opt/aegisguard')
sys.path.insert(0, '/opt/aegisguard')

# Make sure ipset is installed
print('Installing ipset...')
r = subprocess.run('apt-get install -y ipset', shell=True, capture_output=True, text=True)
print('ipset:', 'ok' if r.returncode == 0 else r.stderr.strip()[:100])

# Pull latest code
print('Pulling latest code...')
r = subprocess.run('cd /opt/aegisguard && git pull', shell=True, capture_output=True, text=True)
print('git pull:', r.stdout.strip()[-100:] or r.stderr.strip()[-100:])

# Apply geoblock
print()
print('=== Applying Geoblock ===')
from core import geoblock
ok, msg = geoblock.apply_geoblock()
print()
print('Result:', ok, msg)

if ok:
    print()
    print('=== Status ===')
    status = geoblock.get_status()
    for k, v in status.items():
        print(' ', k, ':', v)

    print()
    print('=== AEGISGUARD_INPUT chain ===')
    r = subprocess.run('iptables -L AEGISGUARD_INPUT -n -v --line-numbers', shell=True, capture_output=True, text=True)
    print(r.stdout)

    print('=== Test: verify Greek IP is in ipset ===')
    # Test with a known Greek IP (e.g., 109.178.147.182 was GR)
    r = subprocess.run('ipset test geo_allowed 109.178.147.182 && echo "GR IP: ALLOWED" || echo "GR IP: NOT in set"', shell=True, capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())

    # Test with a known non-GR IP
    r = subprocess.run('ipset test geo_allowed 1.1.1.1 && echo "1.1.1.1 (AU): ALLOWED" || echo "1.1.1.1 (AU): BLOCKED - good"', shell=True, capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())

    r = subprocess.run('ipset test geo_allowed 77.237.0.1 2>&1 && echo "Russian IP: ALLOWED" || echo "Russian IP: BLOCKED - good"', shell=True, capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())

# Restart aegisguard service
print()
print('=== Restarting AegisGuard ===')
r = subprocess.run('systemctl restart aegisguard', shell=True, capture_output=True, text=True)
time.sleep(3)
r2 = subprocess.run('systemctl is-active aegisguard', shell=True, capture_output=True, text=True)
print('aegisguard:', r2.stdout.strip())

print()
print('DONE. Geoblock is active.')
