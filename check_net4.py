import paramiko, time, sys

host = "10.0.0.1"
user = "stelios"
pw = "Balloteli1997"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host, username=user, password=pw, timeout=10)

def run(cmd, wait=3):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(f"echo {pw} | sudo -S {cmd} 2>&1")
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def run_plain(cmd, wait=2):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(cmd)
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

# Check iptables-save and netfilter-persistent
pr("netfilter-persistent / iptables-save", run("dpkg -l netfilter-persistent iptables-persistent 2>/dev/null || echo NOT_INSTALLED", 2))
pr("iptables-save file exists?", run("ls -la /etc/iptables/ 2>/dev/null || echo NO_DIR", 1))
pr("iptables.rules content", run("cat /etc/iptables/rules.v4 2>/dev/null || echo NO_FILE", 1))

# Check rp_filter (reverse path filtering - can block asymmetric traffic)
pr("rp_filter", run("sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.eth0.rp_filter net.ipv4.conf.eth1.rp_filter", 2))

# CRITICAL: Test forwarding directly - try to forward ICMP from eth1 to internet
# Inject a ping "as if" from client
pr("Test: ping 8.8.8.8 THROUGH server (should use NAT)", run_plain("ping -c 3 -I eth1 8.8.8.8 2>&1 || echo FAILED", 6))

# Current FORWARD counters
pr("FORWARD chain counters NOW", run("iptables -L FORWARD -n -v --line-numbers", 2))

# Check if rules were loaded by a service or by AegisGuard code
pr("Saved iptables rules (iptables-save)", run("iptables-save | head -60", 2))

# Check if netplan has any routing
pr("Netplan config", run("cat /etc/netplan/*.yaml 2>/dev/null || echo NO_NETPLAN", 1))

# Explicitly try to connect from 10.0.0.187 perspective
# by running a traceroute to see where packets go
pr("traceroute to 8.8.8.8 from server", run_plain("traceroute -n -m 3 8.8.8.8 2>&1 || true", 6))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
