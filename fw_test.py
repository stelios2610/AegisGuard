import sys,json,urllib.request,urllib.parse,ssl,http.cookiejar
sys.path.insert(0,'/opt/aegisguard')
ctx=ssl.create_default_context()
ctx.check_hostname=False
ctx.verify_mode=ssl.CERT_NONE
jar=http.cookiejar.CookieJar()
opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar))
opener.open('https://127.0.0.1:8080/login',urllib.parse.urlencode({'username':'admin','password':'Balloteli1997','next':'/'}).encode())

def get(p): return json.loads(opener.open('https://127.0.0.1:8080'+p).read())
def post(p,d=None):
    req=urllib.request.Request('https://127.0.0.1:8080'+p,data=json.dumps(d or {}).encode(),headers={'Content-Type':'application/json'},method='POST')
    return json.loads(opener.open(req).read())
def put(p,d=None):
    req=urllib.request.Request('https://127.0.0.1:8080'+p,data=json.dumps(d or {}).encode(),headers={'Content-Type':'application/json'},method='PUT')
    return json.loads(opener.open(req).read())
def delete(p):
    req=urllib.request.Request('https://127.0.0.1:8080'+p,method='DELETE')
    return json.loads(opener.open(req).read())

ok=0
tests=[
 ('GET all rules',       lambda: get('/api/rules')),
 ('GET fw-status',       lambda: get('/api/settings/fw-status')),
 ('Add ALLOW rule',      lambda: post('/api/rules',{'name':'Test-Allow','action':'ALLOW','direction':'IN','protocol':'TCP','local_ip':'','remote_ip':'','local_port':'','remote_port':'9999','enabled':1,'priority':100,'description':'test','interface':'','log_match':0})),
 ('Add BLOCK rule',      lambda: post('/api/rules',{'name':'Test-Block','action':'BLOCK','direction':'IN','protocol':'TCP','local_ip':'','remote_ip':'1.2.3.4','local_port':'','remote_port':'','enabled':1,'priority':90,'description':'test','interface':'','log_match':0})),
 ('Sync all rules',      lambda: post('/api/rules/sync')),
 ('Block IP quick',      lambda: post('/api/blocked/ip',{'ip':'5.6.7.8'})),
 ('Block domain quick',  lambda: post('/api/blocked/domain',{'domain':'bad.example.com'})),
 ('Clear all rules check',lambda: get('/api/settings/fw-status')),
]
for name,fn in tests:
    try:
        r=fn()
        ok+=1
        print('OK   '+name+': '+str(r)[:120])
    except Exception as e:
        print('FAIL '+name+': '+str(e)[:120])

print('\n--- Toggle / Update / Delete ---')
try:
    rules=get('/api/rules')
    test_rules=[r for r in rules if r.get('description')=='test']
    print('Found '+str(len(test_rules))+' test rules')
    for r in test_rules:
        rid=str(r['id'])
        tr=post('/api/rules/'+rid+'/toggle')
        print('Toggle '+rid+': '+str(tr))
        up=put('/api/rules/'+rid,{'name':r['name'],'action':r['action'],'direction':r['direction'],'protocol':r.get('protocol','ANY'),'local_ip':r.get('local_ip',''),'remote_ip':r.get('remote_ip',''),'local_port':r.get('local_port',''),'remote_port':r.get('remote_port',''),'enabled':r.get('enabled',1),'priority':r.get('priority',100),'description':'test-updated','interface':r.get('interface',''),'log_match':r.get('log_match',0)})
        print('Update '+rid+': '+str(up))
        dr=delete('/api/rules/'+rid)
        print('Delete '+rid+': '+str(dr))
        ok+=3
    # clean block IP rule
    for r in get('/api/rules'):
        if 'Block-IP:5.6.7.8' in r.get('name',''):
            delete('/api/rules/'+str(r['id']))
            print('Cleaned block IP rule')
except Exception as e:
    print('ERROR: '+str(e))

# Check iptables actually has rules
import subprocess
out=subprocess.run(['iptables','-L','AEGISGUARD_INPUT','-n','--line-numbers'],capture_output=True,text=True)
print('\n--- iptables AEGISGUARD_INPUT ---')
print(out.stdout[:500] if out.stdout else out.stderr[:200])

total=len(tests)+6
print('\n'+str(ok)+'/'+str(total)+' passing')
