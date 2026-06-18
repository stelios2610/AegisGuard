import requests, urllib3, re
urllib3.disable_warnings()

# Login first
s = requests.Session()
r = s.post("https://10.0.0.1:8080/login",
    data={"username":"admin","password":"admin"},
    verify=False, allow_redirects=True)

# Get network page
r = s.get("https://10.0.0.1:8080/network", verify=False)
html = r.text

# Find Edit button and IFACES_DATA
edit_btn = re.findall(r'<button[^>]*onclick[^>]*editIface[^>]*>[^<]*Edit[^<]*</button>', html)
ifaces_data = re.findall(r'const IFACES_DATA = (.+?);', html)

print("=== EDIT BUTTONS ===")
for b in edit_btn:
    print(b[:200])

print("\n=== IFACES_DATA ===")
for d in ifaces_data:
    print(d[:300])

print("\n=== Status:", r.status_code)
