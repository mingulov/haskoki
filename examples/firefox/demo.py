#!/usr/bin/env python3
"""Run a disposable Haskoki-backed Firefox desktop. Host requires Python + Docker."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
TOKEN_IMAGE = 'ghcr.io/mingulov/haskoki-demo@sha256:2e0b73aacce0357fd8292608f1ac45cd8b81b6e3cf14c4dadba877c1fc801406'
BROWSER_IMAGE = 'haskoki-firefox-example:local'
LABEL = 'org.haskoki.firefox.run'

def docker(*args, check=True, timeout=120):
    return subprocess.run(['docker', *map(str,args)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, timeout=timeout)

def write(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, indent=2)+'\n')
    temp.replace(path)

def read_state(out):
    state = json.loads((out/'state.json').read_text())
    if state.get('out') != str(out) or not re.fullmatch('[a-f0-9]{32}', state.get('run_id','')):
        raise ValueError('invalid state ownership or output directory')
    if not isinstance(state.get('containers'), list) or not all(isinstance(c,str) for c in state['containers']):
        raise ValueError('invalid container state')
    return state

def remove_owned(out, state):
    # Validate the complete set before removing any. Names from state are untrusted.
    owned = []
    for name in state['containers']:
        inspected = docker('inspect', name, check=False)
        if inspected.returncode:
            if re.search(r'\bno such (?:object|container)\b',inspected.stderr,re.I):
                continue
            raise RuntimeError(inspected.stderr or 'container inspection failed')
        info = json.loads(inspected.stdout)[0]
        labels = info.get('Config',{}).get('Labels',{}) or {}
        mounts = info.get('Mounts',[])
        if labels.get(LABEL) != state['run_id'] or labels.get(LABEL+'.out') != str(out) or not any(m.get('Source') == str(out) and m.get('Destination') == '/out' for m in mounts):
            raise ValueError('container ownership validation failed: '+name)
        container_id=info.get('Id','')
        if not isinstance(container_id,str) or not re.fullmatch('[a-f0-9]{64}',container_id):
            raise ValueError('container ownership has no immutable container ID: '+name)
        owned.append((name,container_id))
    for name,container_id in owned:
        logs = docker('logs', container_id, check=False)
        (out/(name+'.log')).write_text(logs.stdout+logs.stderr)
        docker('rm','-f',container_id)
    state['stopped'] = True
    write(out/'state.json',state)

def port(value):
    try:
        number=int(value)
        if 1 <= number <= 65535: return number
    except ValueError: pass
    raise argparse.ArgumentTypeError('port must be between 1 and 65535')

def wait_file(out, name, container, timeout=120):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if (out/name).exists(): return
        if (out/'test.done').exists():
            report=json.loads((out/'report.json').read_text())
            raise RuntimeError('browser acceptance failed: '+report.get('error','unknown failure'))
        status=docker('inspect','-f','{{.State.Running}}',container)
        if status.stdout.strip() != 'true':
            logs=docker('logs',container,check=False)
            raise RuntimeError('container exited: '+logs.stdout+logs.stderr)
        time.sleep(.5)
    raise TimeoutError('waiting for '+name)

def start(args):
    out=Path(args.out or ('firefox-'+uuid.uuid4().hex[:8])).expanduser().absolute()
    # mkdir is atomic, and existing paths (including symlinks) are always refused.
    os.umask(0o077)
    out.mkdir(mode=0o700)
    out=out.resolve()
    run_id=uuid.uuid4().hex
    token='haskoki-firefox-'+run_id+'-token'
    browser='haskoki-firefox-'+run_id+'-browser'
    state={'run_id':run_id,'out':str(out),'containers':[], 'port':args.port,'token':token,'browser':browser,'token_image':args.token_image}
    write(out/'state.json',state)
    try:
        build=docker('build','--platform','linux/amd64','-t',BROWSER_IMAGE,HERE,check=False,timeout=1800)
        (out/'build.log').write_text(build.stdout+build.stderr)
        if build.returncode: raise RuntimeError('browser image build failed; see '+str(out/'build.log'))
        token_info=docker('image','inspect',args.token_image,check=False)
        if token_info.returncode:
            pulled=docker('pull',args.token_image,check=False,timeout=1800)
            (out/'token-pull.log').write_text(pulled.stdout+pulled.stderr)
            if pulled.returncode: raise RuntimeError('token image pull failed; see '+str(out/'token-pull.log'))
            token_info=docker('image','inspect',args.token_image)
        (out/'token-image.json').write_text(token_info.stdout)
        (out/'browser-image.json').write_text(docker('image','inspect',BROWSER_IMAGE).stdout)
        (out/'host-versions.txt').write_text(sys.version+'\n'+docker('version').stdout)
        uid=f'{os.getuid()}:{os.getgid()}'
        common=['-e','HASKOKI_TOKEN_IMAGE='+args.token_image,'--network','none','--user',uid,'--label',LABEL+'='+run_id,'--label',LABEL+'.out='+str(out),'-v',str(out)+':/out','-v',str(HERE)+':/example:ro']
        state['containers'].append(token); write(out/'state.json',state)
        docker('run','-d','--platform','linux/amd64','--name',token,*common,'--entrypoint','/bin/sh',args.token_image,'/example/token.sh')
        wait_file(out,'token.ready',token)
        state['containers'].append(browser); write(out/'state.json',state)
        # Browser has its own network namespace; only noVNC reaches the host.
        browser_common=[x for x in common]
        del browser_common[2:4]
        docker('run','-d','--platform','linux/amd64','--name',browser,*browser_common,'--shm-size','512m','-p',f'127.0.0.1:{args.port}:6080',BROWSER_IMAGE,'python3','/example/browser.py','test' if args.command=='test' else 'start')
        wait_file(out,'browser.ready',browser)
        if args.command=='test':
            wait_file(out,'phase-stop-token',browser,180)
            docker('stop','-t','10',token)
            (out/'token.stopped').touch()
            wait_file(out,'test.done',browser,180)
            report=json.loads((out/'report.json').read_text())
            if not report.get('passed'): raise RuntimeError('Firefox acceptance failed; see '+str(out/'report.json'))
            print('PASS: real Firefox acceptance; '+str(out/'report.json'))
            remove_owned(out,state)
        else:
            print(f'Firefox desktop: http://127.0.0.1:{args.port}/vnc.html?autoconnect=1&resize=scale\nDemo PIN: 1234\nArtifacts: {out}')
            print('Stop: '+shlex.join([sys.executable,str(HERE/'demo.py'),'stop','--out',str(out)]))
    except BaseException as error:
        if args.command=='test' and not (out/'report.json').exists():
            write(out/'report.json',{'passed':False,'stage':'launcher','error':str(error),'token_image':args.token_image})
        try: remove_owned(out,state)
        except Exception as error: print('Cleanup: '+str(error),file=sys.stderr)
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('start','test'):
        p=sub.add_parser(name); p.add_argument('--out'); p.add_argument('--port',type=port,default=6080); p.add_argument('--token-image',default=TOKEN_IMAGE,help='explicit candidate image override; recorded in artifacts')
    p=sub.add_parser('stop'); p.add_argument('--out',required=True)
    args=parser.parse_args()
    try:
        if args.command=='stop':
            out=Path(args.out).expanduser().resolve(); remove_owned(out,read_state(out)); print('Stopped; artifacts retained: '+str(out))
        else: start(args)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        print(str(error),file=sys.stderr)
        if isinstance(error,subprocess.CalledProcessError) and error.stderr: print(error.stderr,file=sys.stderr)
        return 1
    return 0

if __name__=='__main__': sys.exit(main())
