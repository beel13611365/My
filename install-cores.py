import json, urllib.request, tarfile, zipfile, io, os
headers={'User-Agent':'Nexora-Panel-Builder','Accept':'application/vnd.github+json'}
def release(repo):
    req=urllib.request.Request('https://api.github.com/repos/'+repo+'/releases/latest',headers=headers)
    with urllib.request.urlopen(req,timeout=30) as r: return json.load(r)
def fetch(url):
    req=urllib.request.Request(url,headers={'User-Agent':'Nexora-Panel-Builder'})
    with urllib.request.urlopen(req,timeout=90) as r: return r.read()
x=release('XTLS/Xray-core')
xa=next(a for a in x['assets'] if a['name']=='Xray-linux-64.zip')
with zipfile.ZipFile(io.BytesIO(fetch(xa['browser_download_url']))) as z:
    open('/usr/local/bin/xray','wb').write(z.read('xray'))
s=release('SagerNet/sing-box')
sa=next(a for a in s['assets'] if a['name'].endswith('linux-amd64.tar.gz') and 'debug' not in a['name'])
with tarfile.open(fileobj=io.BytesIO(fetch(sa['browser_download_url'])),mode='r:gz') as t:
    member=next(m for m in t.getmembers() if m.name.endswith('/sing-box') and m.isfile())
    open('/usr/local/bin/sing-box','wb').write(t.extractfile(member).read())
os.chmod('/usr/local/bin/xray',0o755)
os.chmod('/usr/local/bin/sing-box',0o755)
