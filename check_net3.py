import paramiko, time, sys, io

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
    raw = chan.recv(65535)
    return raw.decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode("utf-8"))
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()

pr("DHCP leases", run("cat /var/lib/misc/dnsmasq.leases 2>/dev/null || cat /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null || echo NO_FILE", 2))

pr("dnsmasq config", run("cat /etc/dnsmasq.conf 2>/dev/null; cat /etc/dnsmasq.d/*.conf 2>/dev/null || true", 2))

pr("dnsmasq logs last 20", run("journalctl -u dnsmasq -n 20 --no-pager 2>/dev/null || echo no_journal", 3))

pr("ARP table full", run("arp -n", 1))

pr("tcpdump on eth1 - 5 seconds", run("timeout 5 tcpdump -n -i eth1 not port 22 -c 20 2>&1 || true", 7))

pr("sysctl.d aegisguard", run("cat /etc/sysctl.d/99-aegisguard.conf", 1))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
