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

script = """
with open('/etc/nginx/nginx.conf', 'r') as f:
    c = f.read()
c = c.replace('server_tokens build;', 'server_tokens off;')
c = c.replace('server_tokens on;', 'server_tokens off;')
with open('/etc/nginx/nginx.conf', 'w') as f:
    f.write(c)
print('Done')
"""

sftp = c.open_sftp()
with sftp.open("/tmp/fix_tokens.py", "w") as f:
    f.write(script.encode())
sftp.close()

print(run("python3 /tmp/fix_tokens.py", 2))
print(run("systemctl reload nginx && echo 'nginx reloaded OK'", 3))
print(run("curl -sk -I https://10.0.0.1:8080/ | grep -i server || echo 'Server header hidden'", 3))

c.close()
