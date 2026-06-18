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
    out = chan.recv(65535)
    return out.decode("utf-8", errors="replace")

def run_plain(cmd, wait=2):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(cmd)
    time.sleep(wait)
    out = chan.recv(65535)
    return out.decode("utf-8", errors="replace")

print("\n=== INTERFACES ===")
print(run_plain("ip addr show", 2))

print("\n=== ROUTING TABLE ===")
print(run_plain("ip route show", 2))

print("\n=== IP FORWARDING ===")
print(run_plain("cat /proc/sys/net/ipv4/ip_forward", 1))

print("\n=== IPTABLES FILTER ===")
print(run("iptables -L -n -v --line-numbers", 4))

print("\n=== IPTABLES NAT ===")
print(run("iptables -t nat -L -n -v", 3))

print("\n=== PING GATEWAY ===")
print(run_plain("ping -c 3 192.168.100.1", 5))

print("\n=== PING INTERNET ===")
print(run_plain("ping -c 3 8.8.8.8", 5))

print("\n=== DNS TEST ===")
print(run_plain("nslookup google.com 8.8.8.8", 3))

print("\n=== AEGISGUARD STATUS ===")
print(run_plain("systemctl is-active aegisguard nginx fail2ban", 2))

print("\n=== AEGISGUARD LOGS LAST 40 ===")
print(run("journalctl -u aegisguard -n 40 --no-pager", 3))

print("\n=== SYSCTL FORWARDING ===")
print(run("sysctl net.ipv4.ip_forward net.ipv4.conf.all.forwarding", 2))

c.close()
print("\n=== DONE ===")
