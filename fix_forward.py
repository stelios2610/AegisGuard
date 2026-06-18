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

# 1. Enable ip_forward now (runtime)
print("=== Enable ip_forward now ===")
print(run("sysctl -w net.ipv4.ip_forward=1", 2))
print(run("sysctl -w net.ipv4.conf.all.forwarding=1", 2))

# 2. Persist it via sysctl.d
print("=== Write persistent sysctl config ===")
sysctl_content = "net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.forwarding = 1\n"
sftp = c.open_sftp()
with sftp.open("/tmp/99-aegisguard-forward.conf", "w") as f:
    f.write(sysctl_content)
sftp.close()
print(run("mv /tmp/99-aegisguard-forward.conf /etc/sysctl.d/99-aegisguard.conf", 2))
print(run("chmod 644 /etc/sysctl.d/99-aegisguard.conf", 1))
print(run("sysctl -p /etc/sysctl.d/99-aegisguard.conf", 2))

# 3. Verify
print("=== Verify ip_forward ===")
print(run("sysctl net.ipv4.ip_forward", 1))

# 4. Test internet from server
print("=== Test LAN client would forward (ping 8.8.8.8 from server) ===")
chan = c.get_transport().open_session()
chan.get_pty()
chan.exec_command("ping -c 3 8.8.8.8")
time.sleep(5)
print(chan.recv(65535).decode("utf-8", errors="replace"))

c.close()
print("=== DONE ===")
