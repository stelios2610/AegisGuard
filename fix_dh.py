import re

with open("/opt/aegisguard/pki/ssl-vpn/dh.pem") as f:
    new_dh = f.read().strip()

with open("/opt/aegisguard/ssl-vpn-server.conf") as f:
    conf = f.read()

new_block = "<dh>\n" + new_dh + "\n</dh>"
conf = re.sub(r"<dh>.*?</dh>", new_block, conf, flags=re.DOTALL)

with open("/opt/aegisguard/ssl-vpn-server.conf", "w") as f:
    f.write(conf)

print("DH replaced. Size:", len(new_dh), "chars")
