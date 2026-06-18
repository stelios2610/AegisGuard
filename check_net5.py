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

# 1. Route lookup: what path would a packet from 10.0.0.187 to 8.8.8.8 take?
pr("Route: 10.0.0.187 → 8.8.8.8", run_plain("ip route get 8.8.8.8 from 10.0.0.187", 1))
pr("Route: 10.0.0.187 → 1.1.1.1", run_plain("ip route get 1.1.1.1 from 10.0.0.187", 1))

# 2. Disable rp_filter temporarily and test
pr("Disable rp_filter (test)", run("sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eth0.rp_filter=0 net.ipv4.conf.eth1.rp_filter=0", 2))

# 3. Add LOG rule to FORWARD to catch packets
pr("Add LOG to FORWARD", run("iptables -I FORWARD 1 -j LOG --log-prefix 'FW-DEBUG: ' --log-level 4", 1))

# 4. Test: try to simulate a forwarded packet by adding a temp IP
pr("Add temp IP on eth1 (simulate client)", run("ip addr add 10.0.0.250/24 dev eth1 2>/dev/null; true", 1))

# 5. Ping 8.8.8.8 as if from a LAN client (from 10.0.0.250 on eth1)
pr("Ping 8.8.8.8 from 10.0.0.250 (LAN sim)", run_plain("ping -c 3 -I 10.0.0.250 8.8.8.8 2>&1 || echo FAILED", 6))

# 6. Check FORWARD counters
pr("FORWARD after test", run("iptables -L FORWARD -n -v --line-numbers", 2))

# 7. Check kernel log for FW-DEBUG
pr("Kernel log FW-DEBUG", run("dmesg | grep FW-DEBUG | tail -20", 1))

# 8. Now try normal ping (server's default route)
pr("Normal ping 8.8.8.8 (server)", run_plain("ping -c 3 8.8.8.8 2>&1", 5))

# 9. Remove temp IP and LOG rule
print("Cleaning up...")
run("ip addr del 10.0.0.250/24 dev eth1 2>/dev/null; true", 1)
run("iptables -D FORWARD 1 2>/dev/null; true", 1)

# 10. Make rp_filter=1 (loose) persistent
pr("Set rp_filter=1 (loose, permanent)", run("sysctl -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.eth0.rp_filter=1 net.ipv4.conf.eth1.rp_filter=1", 2))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
