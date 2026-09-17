import sys, os, subprocess
os.chdir('/opt/fguard')
sys.path.insert(0, '/opt/fguard')

# Reload module with fixed interface detection
import importlib
from core import geoblock
importlib.reload(geoblock)

# Reset cached value
geoblock.WAN_IFACE = None
wan = geoblock._get_wan_iface()
print('WAN interface detected:', wan)

# Re-apply chain rules with correct interface
geoblock._apply_chain_rules(wan)
print('Chain rebuilt with WAN =', wan)

# Show result
r = subprocess.run('iptables -L FGUARD_INPUT -n -v --line-numbers', shell=True, capture_output=True, text=True)
print()
print(r.stdout)

# Verify geoblock works on correct interface
print('Test: GR IP 5.59.0.1 (should be ALLOWED):')
r = subprocess.run('ipset test geo_allowed 5.59.0.1 2>&1 && echo ALLOWED || echo BLOCKED', shell=True, capture_output=True, text=True)
print(' ', r.stdout.strip())

print('Test: Russian IP 77.237.0.1 (should be BLOCKED):')
r = subprocess.run('ipset test geo_allowed 77.237.0.1 2>&1 && echo ALLOWED || echo BLOCKED', shell=True, capture_output=True, text=True)
print(' ', r.stdout.strip())

print('Test: Greek phone IP 109.178.147.182 (should be ALLOWED):')
r = subprocess.run('ipset test geo_allowed 109.178.147.182 2>&1 && echo ALLOWED || echo BLOCKED', shell=True, capture_output=True, text=True)
print(' ', r.stdout.strip())

# Save iptables
subprocess.run('netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null', shell=True)
print()
print('Done. Geoblock active on', wan)
