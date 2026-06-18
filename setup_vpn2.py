import sys, os, subprocess
PKI = '/etc/openvpn/aegisguard-pki'
PUBLIC_IP = '2.84.117.79'

print('Generating DH params (takes ~30-60 sec)...')
ret = subprocess.run(['openssl', 'dhparam', '-out', f'{PKI}/dh.pem', '2048'],
                     capture_output=True, text=True, timeout=180)
print('DH:', 'OK' if ret.returncode == 0 else ret.stderr[-200:])

print('Generating TLS-Auth key...')
ret = subprocess.run(['openvpn', '--genkey', '--secret', f'{PKI}/ta.key'],
                     capture_output=True, text=True, timeout=10)
print('TA:', 'OK' if ret.returncode == 0 else ret.stderr)

def read(p):
    with open(p) as f:
        return f.read()

print('\nWriting server config...')
server_conf = (
    "port 1194\nproto udp\ndev tun\n"
    "<ca>\n" + read(f'{PKI}/ca.crt') + "</ca>\n"
    "<cert>\n" + read(f'{PKI}/server.crt') + "</cert>\n"
    "<key>\n" + read(f'{PKI}/server.key') + "</key>\n"
    "<dh>\n" + read(f'{PKI}/dh.pem') + "</dh>\n"
    "<tls-auth>\n" + read(f'{PKI}/ta.key') + "</tls-auth>\n"
    "key-direction 0\n"
    "server 10.8.0.0 255.255.255.0\n"
    'push "redirect-gateway def1 bypass-dhcp"\n'
    'push "dhcp-option DNS 10.8.0.1"\n'
    "keepalive 10 120\n"
    "cipher AES-256-GCM\nauth SHA256\ntls-version-min 1.2\n"
    "compress lz4-v2\n"
    'push "compress lz4-v2"\n'
    "user nobody\ngroup nogroup\n"
    "persist-key\npersist-tun\n"
    "status /var/log/openvpn-status.log\n"
    "log-append /var/log/openvpn.log\nverb 3\n"
)
os.makedirs('/etc/openvpn/server', exist_ok=True)
with open('/etc/openvpn/server/server.conf', 'w') as f:
    f.write(server_conf)
print('Server config: OK')

print('\nWriting client .ovpn...')
client_ovpn = (
    "client\ndev tun\nproto udp\n"
    f"remote {PUBLIC_IP} 1194\n"
    "resolv-retry infinite\nnobind\n"
    "persist-key\npersist-tun\n"
    "remote-cert-tls server\n"
    "cipher AES-256-GCM\nauth SHA256\ntls-version-min 1.2\n"
    "compress lz4-v2\nverb 3\nkey-direction 1\n"
    "<ca>\n" + read(f'{PKI}/ca.crt') + "</ca>\n"
    "<cert>\n" + read(f'{PKI}/client.crt') + "</cert>\n"
    "<key>\n" + read(f'{PKI}/client.key') + "</key>\n"
    "<tls-auth>\n" + read(f'{PKI}/ta.key') + "</tls-auth>\n"
)
with open('/tmp/aegisguard-mobile.ovpn', 'w') as f:
    f.write(client_ovpn)
print('Client .ovpn: OK')

print('\nAdding iptables rules...')
for r in [
    'iptables -A FORWARD -i tun0 -j ACCEPT',
    'iptables -A FORWARD -o tun0 -j ACCEPT',
    'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens1 -j MASQUERADE',
]:
    ret = subprocess.run(r, shell=True, capture_output=True, text=True)
    print('  OK:', r if ret.returncode == 0 else ret.stderr.strip())

subprocess.run('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)

print('\nStarting OpenVPN...')
ret = subprocess.run('systemctl enable --now openvpn-server@server', shell=True, capture_output=True, text=True)
import time; time.sleep(4)
ret2 = subprocess.run('systemctl is-active openvpn-server@server', shell=True, capture_output=True, text=True)
print('Status:', ret2.stdout.strip())
if ret2.stdout.strip() != 'active':
    ret3 = subprocess.run('journalctl -u openvpn-server@server -n 15 --no-pager', shell=True, capture_output=True, text=True)
    print(ret3.stdout[-1500:])
else:
    print('OpenVPN server is RUNNING!')
    subprocess.run('ip addr show tun0', shell=True)
