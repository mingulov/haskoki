#!/usr/bin/env python3
"""Container desktop and a dependency-free synchronous Marionette acceptance client."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback

OUT=Path('/out')
CLIENT='/opt/haskoki-p11-kit/p11-kit-client.so'
NSS_MODULE=CLIENT
processes=[]

def command(*args, check=True):
    result=subprocess.run(args,text=True,capture_output=True,check=check,timeout=60)
    with (OUT/'setup.log').open('a') as log:
        log.write('$ '+repr(args)+'\n'+result.stdout+result.stderr)
    return result.stdout

def spawn(name, *args):
    log=(OUT/(name+'.log')).open('ab')
    proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT)
    log.close(); processes.append(proc); return proc

def wait_port(port, timeout=40):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try: return socket.create_connection(('127.0.0.1',port),timeout=1)
        except OSError: time.sleep(.2)
    raise TimeoutError('port '+str(port))

def profile(name, automatic=False):
    p=OUT/name; p.mkdir(mode=0o700)
    command('certutil','-N','--empty-password','-d','sql:'+str(p))
    command('certutil','-A','-d','sql:'+str(p),'-n','Disposable Haskoki CA','-t','C,,','-i','/out/ca.pem')
    command('modutil','-dbdir','sql:'+str(p),'-add','Haskoki demo','-libfile',NSS_MODULE,'-force')
    prefs={
        'browser.shell.checkDefaultBrowser':False,'browser.startup.homepage':'about:blank' if automatic else 'https://localhost:8443/',
        'browser.startup.page':1,'browser.aboutwelcome.enabled':False,'browser.startup.firstrunSkipsHomepage':False,
        'datareporting.policy.dataSubmissionEnabled':False,'toolkit.telemetry.reportingpolicy.firstRun':False,
        'security.default_personal_cert':'Select Automatically' if automatic else 'Ask Every Time',
        'security.tls.enable_0rtt_data':False,'network.proxy.type':0,
        'marionette.port':2828,'remote.active-protocols':1,
    }
    (p/'user.js').write_text(''.join('user_pref('+json.dumps(k)+','+json.dumps(v)+');\n' for k,v in prefs.items()))
    return p

class Marionette:
    # Mozilla's length-prefixed JSON protocol v3, synchronous request/response.
    def __init__(self):
        self.sock=wait_port(2828)
        self.sock.settimeout(45)
        self.sequence=0
        self.greeting=self.receive()
        self.call('WebDriver:NewSession',{'capabilities':{'alwaysMatch':{'acceptInsecureCerts':False}}})
    def receive(self):
        length=b''
        while True:
            c=self.sock.recv(1)
            if not c: raise EOFError('Marionette closed while reading length')
            if c==b':': break
            length+=c
            if len(length)>12: raise ValueError('invalid Marionette length')
        remaining=int(length); chunks=[]
        while remaining:
            chunk=self.sock.recv(remaining)
            if not chunk: raise EOFError('Marionette closed while reading frame')
            chunks.append(chunk); remaining-=len(chunk)
        return json.loads(b''.join(chunks))
    def call(self, name, args=None):
        self.sequence+=1
        payload=json.dumps([0,self.sequence,name,args or {}]).encode()
        self.sock.sendall(str(len(payload)).encode()+b':'+payload)
        result=self.receive()
        if result[0]!=1 or result[1]!=self.sequence: raise ValueError('unexpected Marionette response')
        if result[2]: raise RuntimeError(json.dumps(result[2]))
        return result[3]
    def script(self, script, chrome=False):
        self.call('Marionette:SetContext',{'value':'chrome' if chrome else 'content'})
        if chrome: script='return (async()=>{'+script+'})();'
        result=self.call('WebDriver:ExecuteScript',{'script':script,'args':[],'newSandbox':True,'sandbox':'default','line':0,'filename':'haskoki-acceptance'})
        return result.get('value',result)
    def quit(self):
        try: self.call('Marionette:Quit',{'flags':['eForceQuit']})
        finally: self.sock.close()

def launch(p, name):
    proc=spawn(name,'firefox-esr','--no-remote','--profile',str(p),'--marionette','--remote-allow-system-access','about:blank')
    return proc,Marionette()

def desktop_screenshot(path):
    """Capture the Xvfb root without adding a host or Python imaging dependency."""
    import ctypes as c
    import struct
    import zlib
    class XImage(c.Structure):
        _fields_=[('width',c.c_int),('height',c.c_int),('xoffset',c.c_int),('format',c.c_int),('data',c.c_void_p),('byte_order',c.c_int),('bitmap_unit',c.c_int),('bitmap_bit_order',c.c_int),('bitmap_pad',c.c_int),('depth',c.c_int),('bytes_per_line',c.c_int),('bits_per_pixel',c.c_int)]
    x=c.CDLL('libX11.so.6')
    x.XOpenDisplay.restype=c.c_void_p
    d=x.XOpenDisplay(None)
    if not d: raise RuntimeError('X display unavailable')
    x.XDefaultRootWindow.argtypes=[c.c_void_p]; x.XDefaultRootWindow.restype=c.c_ulong
    x.XGetImage.argtypes=[c.c_void_p,c.c_ulong,c.c_int,c.c_int,c.c_uint,c.c_uint,c.c_ulong,c.c_int]
    x.XGetImage.restype=c.POINTER(XImage)
    image=x.XGetImage(d,x.XDefaultRootWindow(d),0,0,1280,900,0xffffffffffffffff,2)
    try:
        im=image.contents
        assert im.bits_per_pixel==32 and im.byte_order==0
        raw=c.string_at(im.data,im.bytes_per_line*im.height)
        scan=bytearray()
        for row in range(im.height):
            scan.append(0)
            line=raw[row*im.bytes_per_line:row*im.bytes_per_line+im.width*4]
            for col in range(0,len(line),4): scan.extend((line[col+2],line[col+1],line[col]))
        def chunk(kind,data): return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data))
        path.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',im.width,im.height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(scan))+chunk(b'IEND',b''))
    finally:
        x.XDestroyImage.argtypes=[c.POINTER(XImage)]; x.XDestroyImage(image)
        x.XCloseDisplay.argtypes=[c.c_void_p]; x.XCloseDisplay(d)

def setup():
    os.umask(0o077)
    (OUT/'home').mkdir(mode=0o700,exist_ok=True)
    command('dpkg-query','-W','firefox-esr','libnss3','libnss3-tools','p11-kit','opensc-pkcs11','nginx','novnc','x11vnc','xvfb')
    (OUT/'browser-versions.txt').write_text(command('dpkg-query','-W'))
    import hashlib
    source=Path('/opt/haskoki-p11-kit/source.txt').read_text()
    client_hash=hashlib.sha256(Path(CLIENT).read_bytes()).hexdigest()
    (OUT/'p11-kit-client.txt').write_text(source+'client-sha256 '+client_hash+'\n'+Path('/opt/haskoki-p11-kit/ldd.txt').read_text())
    nginx='''pid /out/nginx.pid;
error_log /out/nginx-error.log info;
events {}
http {
  log_format evidence '$ssl_client_verify|$ssl_client_s_dn|$ssl_client_fingerprint|$status|$request_uri|$ssl_protocol';
  access_log /out/nginx-access.log evidence;
  client_body_temp_path /out/nginx-body;
  proxy_temp_path /out/nginx-proxy;
  fastcgi_temp_path /out/nginx-fastcgi;
  uwsgi_temp_path /out/nginx-uwsgi;
  scgi_temp_path /out/nginx-scgi;
  server {
    listen 8443 ssl;
    server_name localhost;
    ssl_certificate /out/server.pem;
    ssl_certificate_key /out/server.key;
    ssl_client_certificate /out/ca.pem;
    ssl_verify_client on;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache off;
    ssl_session_tickets off;
    location / {
      default_type text/html;
      return 200 '<!doctype html><html lang="en"><meta charset="utf-8"><title>Haskoki client certificate accepted</title><style>body{font:18px/1.6 system-ui,sans-serif;max-width:760px;margin:64px auto;padding:0 28px;color:#1d2d26;background:#f7faf8}h1{font-size:36px;line-height:1.2;color:#20613e}pre{font:15px/1.7 monospace;background:#e8f2eb;border-left:4px solid #29834c;padding:22px;white-space:pre-wrap;overflow-wrap:anywhere}small{color:#4e6256}</style><main><small>Haskoki + Firefox</small><h1>Client certificate accepted</h1><p>Firefox authenticated to this local HTTPS site using the private key held by Haskoki.</p><pre>verify=$ssl_client_verify\\nsubject=$ssl_client_s_dn\\nfingerprint_sha1=$ssl_client_fingerprint\\nprotocol=$ssl_protocol\\n</pre><p>Open Firefox Settings → Privacy &amp; Security → Security Devices to inspect the Haskoki token, or View Certificates → Your Certificates to inspect its certificate.</p></main></html>';
    }
  }
}
'''
    (OUT/'nginx.conf').write_text(nginx)
    spawn('nginx','nginx','-p','/out/','-c','/out/nginx.conf','-g','daemon off;')
    wait_port(8443).close()
    spawn('xvfb','Xvfb',':99','-screen','0','1280x900x24','-nolisten','tcp')
    end=time.monotonic()+20
    while not Path('/tmp/.X11-unix/X99').exists():
        if time.monotonic()>end: raise TimeoutError('Xvfb')
        time.sleep(.1)
    spawn('x11vnc','x11vnc','-display',':99','-localhost','-forever','-shared','-nopw','-rfbport','5900')
    wait_port(5900).close()
    spawn('novnc','websockify','--web=/usr/share/novnc/','6080','localhost:5900')
    wait_port(6080).close()

def successful_signatures(log):
    """Only completed, nonempty one-shot/multipart signatures; exclude size queries."""
    import re
    completed=[]
    for function,block in re.findall(r'^\d+: (C_Sign(?:Final)?)\n(.*?)(?=^\d+: |\Z)',log,re.M|re.S):
        output=re.search(r'^\[out\] pSignature\[.*?\] ([0-9a-fA-F]+) / (\d+)$',block,re.M)
        if output and int(output[1],16)>0 and int(output[2])>0 and re.search(r'^Returned:\s+0 CKR_OK$',block,re.M):
            completed.append({'function':function,'bytes':int(output[2])})
    return completed

def missing_client_denial(access):
    return any(line.split('|')[:5]==['NONE','-','-','400','/?absent'] for line in access.splitlines())

def require_empty_internal_keys(p, filename):
    result=subprocess.run(['certutil','-K','-d','sql:'+str(p),'-h','internal'],text=True,capture_output=True,timeout=20)
    (OUT/filename).write_text(result.stdout+result.stderr)
    expected=['certutil: Checking token "NSS Certificate DB" in slot "NSS User Private Key and Certificate Services"','certutil: no keys found']
    assert result.returncode==255 and result.stdout.splitlines()==expected and not result.stderr, result

def acceptance():
    report={'passed':False,'token_image':os.environ.get('HASKOKI_TOKEN_IMAGE'),'checks':{},'transport':'Firefox -> p11-kit-client -> p11-kit server -> OpenSC spy -> Haskoki','client_key_origin':'generated in Haskoki; public key matched before certificate import'}
    try:
        report['p11_kit_client']=(OUT/'p11-kit-client.txt').read_text()
        report['module_sha256']=(OUT/'module.sha256').read_text().split()[0]
        report['spki_match']=(OUT/'spki-match.txt').read_text()
        p=profile('test-profile',True)
        (OUT/'nss-modules.txt').write_text(command('modutil','-dbdir','sql:'+str(p),'-list'))
        (OUT/'nss-token-certs.txt').write_text(command('certutil','-L','-d','sql:'+str(p),'-h','all'))
        require_empty_internal_keys(p,'nss-internal-keys.txt')
        proc,m=launch(p,'firefox-positive')
        (OUT/'browser.ready').touch()
        report['marionette']=m.greeting
        info=m.script("const ms=await Components.classes['@mozilla.org/security/pkcs11moduledb;1'].getService(Components.interfaces.nsIPKCS11ModuleDB).listModules();return ms.map(m=>({name:m.name,libName:m.libName,slots:m.slots.map(s=>({name:s.name,token:s.tokenName}))}));",True)
        report['modules']=info
        assert any(x['name']=='Haskoki demo' and x['libName']==NSS_MODULE for x in info), info
        # ESR 153 token snapshots deliberately expose login(), not checkPassword().
        # Drive the real Firefox prompt using its common-dialog-loaded observer.
        def login(pin):
            m.script("""
window.haskokiPin=null;
const db=Components.classes['@mozilla.org/security/pkcs11moduledb;1'].getService(Components.interfaces.nsIPKCS11ModuleDB);
const token=(await db.listModules()).find(m=>m.name=='Haskoki demo').slots[0].getToken();
let prompts=[];
const observer={observe(win){
 prompts.push(win.document.getElementById('infoBody').textContent);
 win.document.getElementById('password1Textbox').value=PIN_VALUE;
 win.setTimeout(()=>{const d=win.document.getElementById('commonDialog'); if(prompts.length>1) d.cancelDialog(); else d.acceptDialog();},500);
}};
Services.obs.addObserver(observer,'common-dialog-loaded');
setTimeout(async()=>{
 let result;
 try {result=await token.login();} catch(e) {result=String(e);}
 finally {Services.obs.removeObserver(observer,'common-dialog-loaded');}
 const fresh=(await db.listModules()).find(m=>m.name=='Haskoki demo').slots[0].getToken();
 window.haskokiPin={result,prompts,loggedIn:fresh.isLoggedIn};
},100);
return true;
""".replace('PIN_VALUE',json.dumps(pin)),True)
            time.sleep(2)
            for attempt in range(30):
                result=m.script('return window.haskokiPin;',True)
                if result is not None: return result
                time.sleep(.2)
            raise TimeoutError('Firefox PIN dialog did not finish')
        pin=login('0000'); report['wrong_pin']=pin
        assert pin['loggedIn'] is False and pin['prompts'], pin
        assert 'CKR_PIN_INCORRECT' in (OUT/'pkcs11-spy.log').read_text(), 'wrong PIN did not reach token'
        report['checks']['wrong_pin_rejected']=True
        good=login('1234'); report['right_pin']=good
        assert good['loggedIn'] is True and good['prompts'], good
        report['checks']['right_pin_accepted']=True
        certs=m.script("""
const db=Components.classes['@mozilla.org/security/x509certdb;1'].getService(Components.interfaces.nsIX509CertDB);
return Array.from(db.getCerts()).filter(c=>c.tokenName=='haskoki-demo' || c.commonName=='Haskoki disposable demo CA').map(c=>({name:c.commonName,sha256:c.sha256Fingerprint,sha1:c.sha1Fingerprint,token:c.tokenName,type:c.certType}));
""",True)
        report['certificates']=certs
        expected=next(x.split('=',1)[1] for x in (OUT/'client-identity.txt').read_text().splitlines() if 'Fingerprint=' in x)
        cert=next(c for c in certs if c['sha256'].upper()==expected.upper())
        assert cert['type'] & 2 and cert['token']=='haskoki-demo', cert
        report['checks']['module_and_token_certificate']=True
        m.call('Marionette:SetContext',{'value':'content'})
        m.call('WebDriver:Navigate',{'url':'https://localhost:8443/?positive'})
        body=m.script('return document.body.innerText;')
        report['authenticated_page']=body
        time.sleep(.5)
        desktop_screenshot(OUT/'authenticated-desktop.png')
        expected_sha1=(OUT/'client-sha1.txt').read_text().split('=',1)[1].strip().replace(':','').lower()
        assert 'verify=SUCCESS' in body and 'subject=CN=Haskoki Firefox demo' in body and 'fingerprint_sha1='+expected_sha1 in body, body
        screenshot=m.call('WebDriver:TakeScreenshot',{'id':None,'highlights':[],'full':True})
        (OUT/'authenticated.png').write_bytes(base64.b64decode(screenshot['value']))
        report['checks']['server_verified_identity']=True
        # Inspect real UI rows, then retain the visible managers for review.
        m.script("window.haskokiDevices=window.openDialog('chrome://pippki/content/device_manager.xhtml','','chrome,centerscreen,resizable'); return true;",True)
        time.sleep(1)
        devices=m.script("""
const w=window.haskokiDevices, doc=w.document;
const rows=Array.from(doc.querySelectorAll('#device_list treecell')).map(c=>c.getAttribute('label'));
const item=Array.from(doc.querySelectorAll('#device_list treeitem')).find(i=>i.slotObject?.tokenName=='haskoki-demo');
if(item){const tree=doc.getElementById('device_tree'); tree.view.selection.select(tree.view.getIndexOfItem(item)); tree.dispatchEvent(new w.Event('select'));}
return {rows,selectedToken:item?.slotObject.tokenName};
""",True)
        report['security_devices_ui']=devices
        assert 'Haskoki demo' in devices['rows'] and devices['selectedToken']=='haskoki-demo', devices
        time.sleep(.5)
        desktop_screenshot(OUT/'security-devices.png')
        m.script("window.haskokiDevices.close(); window.haskokiCertificates=window.openDialog('chrome://pippki/content/certManager.xhtml','','chrome,centerscreen,resizable'); return true;",True)
        time.sleep(1)
        cert_ui=m.script("""
const doc=window.haskokiCertificates.document;
doc.getElementById('certmanagertabs').selectedTab=doc.getElementById('mine_tab');
const tree=doc.getElementById('user-tree'), view=tree.view;
for(let i=0;i<view.rowCount;i++) if(view.isContainer(i)&&!view.isContainerOpen(i)) view.toggleOpenState(i);
const rows=[];
for(let i=0;i<view.rowCount;i++){
 let name=view.getCellText(i,tree.columns.getNamedColumn('certcol'));
 let token=view.getCellText(i,tree.columns.getNamedColumn('tokencol'));
 rows.push({name,token}); if(name=='Haskoki Firefox demo')view.selection.select(i);
}
return {selectedTab:doc.getElementById('certmanagertabs').selectedTab.id,rows};
""",True)
        report['your_certificates_ui']=cert_ui
        assert cert_ui['selectedTab']=='mine_tab' and any(r['name']=='Haskoki Firefox demo' and r['token']=='haskoki-demo' for r in cert_ui['rows']), cert_ui
        time.sleep(.5)
        desktop_screenshot(OUT/'certificate-manager.png')
        report['checks']['visible_token_and_certificate_ui']=True
        m.quit(); proc.wait(timeout=20)
        require_empty_internal_keys(p,'nss-internal-keys-after.txt')
        report['checks']['internal_private_keys_absent']=True
        spy=(OUT/'pkcs11-spy.log').read_text()
        report['signatures']=successful_signatures(spy)
        report['successful_sign_calls']=len(report['signatures'])
        assert any(call['bytes']==64 for call in report['signatures']), 'no completed 64-byte token signature in spy log'
        report['checks']['token_signing']=True
        (OUT/'phase-stop-token').touch()
        end=time.monotonic()+60
        while not (OUT/'token.stopped').exists():
            if time.monotonic()>end: raise TimeoutError('host token stop acknowledgement')
            time.sleep(.2)
        # New profile, new process, no TLS sessions or PIN/certificate caches.
        absent=profile('absent-profile',True)
        proc,m=launch(absent,'firefox-absent')
        missing=m.script("const ms=await Components.classes['@mozilla.org/security/pkcs11moduledb;1'].getService(Components.interfaces.nsIPKCS11ModuleDB).listModules();return ms.flatMap(m=>m.slots.map(s=>s.tokenName));",True)
        report['absent_tokens']=missing
        assert 'haskoki-demo' not in missing, missing
        m.call('Marionette:SetContext',{'value':'content'})
        m.call('WebDriver:Navigate',{'url':'https://localhost:8443/?absent'})
        denied=m.script('return document.body.innerText;')
        report['absent_page']=denied
        assert 'No required SSL certificate was sent' in denied and 'verify=SUCCESS' not in denied, denied
        time.sleep(.5)
        access=(OUT/'nginx-access.log').read_text()
        assert missing_client_denial(access), access
        report['checks']['absent_token_rejected_fresh_browser']=True
        m.quit(); proc.wait(timeout=20)
        report['passed']=True
    except Exception as error:
        report['error']=str(error)
        try:
            time.sleep(.5)
            desktop_screenshot(OUT/'failure-desktop.png')
        except Exception: pass
        report['traceback']=traceback.format_exc()
    finally:
        (OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        (OUT/'test.done').touch()
    return report['passed']

def main():
    if sys.argv[1]=='test':
        try:
            setup()
            acceptance()
        except Exception as error:
            (OUT/'report.json').write_text(json.dumps({'passed':False,'error':str(error),'traceback':traceback.format_exc()},indent=2)+'\n')
            (OUT/'test.done').touch()
        # Host needs to read the report before removing the container.
        while True: time.sleep(1)
    else:
        setup()
        p=profile('profile')
        spawn('firefox','firefox-esr','--no-remote','--profile',str(p),'https://localhost:8443/')
        time.sleep(2)
        if processes[-1].poll() is not None: raise RuntimeError('Firefox exited during startup')
        (OUT/'browser.ready').touch()
        while True:
            if any(proc.poll() is not None for proc in processes): raise RuntimeError('desktop service exited')
            time.sleep(1)

if __name__=='__main__':
    try: main()
    finally:
        for proc in reversed(processes):
            if proc.poll() is None: proc.terminate()
