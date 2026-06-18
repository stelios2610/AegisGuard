import paramiko, time

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

print("=== ip_forward ===")
print(run_plain("cat /proc/sys/net/ipv4/ip_forward", 1))

print("=== MASQUERADE rule ===")
print(run("iptables -t nat -L POSTROUTING -n -v", 2))

print("=== FORWARD chain ===")
print(run("iptables -L FORWARD -n -v --line-numbers", 2))

print("=== ARP - is 10.0.0.187 visible? ===")
print(run_plain("ip neigh show dev eth1", 1))

print("=== Can server ping client? ===")
print(run_plain("ping -c 2 -W 2 10.0.0.187", 5))

print("=== dnsmasq status ===")
print(run_plain("systemctl is-active dnsmasq", 1))
print(run("systemctl status dnsmasq --no-pager -n 10", 3))

print("=== DHCP leases ===")
print(run("cat /var/lib/misc/dnsmasq.leases 2>/dev/null || cat /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null || echo 'no leases file'", 2))

print("=== Network interfaces ===")
print(run_plain("ip addr show eth0 eth1", 2))

print("=== Routes ===")
print(run_plain("ip route show", 1))

print("=== sysctl.d file ===")
print(run("cat /etc/sysctl.d/99-aegisguard.conf", 1))

# Test: simulate forwarding a packet from LAN
print("=== tcpdump test: any traffic from 10.0.0.187? (3 sec) ===")
print(run("timeout 3 tcpdump -n -c 10 host 10.0.0.187 2>&1 || true", 5))

c.close()
print("=== DONE ===")
