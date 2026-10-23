#!/usr/bin/env python3
"""Build-free behavioral checks; Docker is replaced only at the process boundary."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'examples/firefox/demo.py'

class Launcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        bindir = self.root / 'bin'
        bindir.mkdir()
        docker = bindir / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
if os.environ.get('FAKE_MISSING') and sys.argv[1]=='inspect':
 print('error: no such object: '+sys.argv[-1],file=sys.stderr);sys.exit(1)
if os.environ.get('FAKE_SUCCESS'):
 out=Path(os.environ['FAKE_OUT']); state=json.loads((out/'state.json').read_text())
 if sys.argv[1]=='inspect' and '-f' in sys.argv:
  token=sys.argv[-1].endswith('-token') or sys.argv[-1]=='d'*64
  dead_token=token and (os.environ.get('FAKE_DEAD_TOKEN_AT')=='token-ready' or (os.environ.get('FAKE_DEAD_TOKEN_AT')=='browser-ready' and (out/'browser.ready').exists()))
  dead_browser=not token and (os.environ.get('FAKE_DEAD_BROWSER') or (os.environ.get('FAKE_DONE_BROWSER_EXITED') and (out/'test.done').exists()))
  print('false' if dead_token or dead_browser else 'true');sys.exit(0)
 if sys.argv[1] == 'inspect':
  foreign=os.environ.get('FAKE_FOREIGN_TOKEN') if sys.argv[-1].endswith('-token') and (out/'phase-stop-token').exists() else ''
  print(json.dumps([{'Id':('c'*64 if sys.argv[-1].endswith('-browser') else 'd'*64),'Config': {'Labels': {'org.haskoki.firefox.run':'foreign' if foreign=='labels' else state['run_id'], 'org.haskoki.firefox.run.out':str(out)}},'Mounts':[{'Source':'/foreign' if foreign=='mount' else str(out),'Destination':'/out'}]}]))
 if sys.argv[1] == 'run':
  (out/('token.ready' if sys.argv[-1].endswith('token.sh') else 'browser.ready')).touch()
  if os.environ.get('FAKE_TEST') and sys.argv[-1]=='test':
   (out/'phase-stop-token').touch();(out/'report.json').write_text(json.dumps({'passed':True}))
 if sys.argv[1]=='stop': (out/'test.done').touch()
 sys.exit(0)
if sys.argv[1] == 'inspect':
 print(json.dumps([{'Config': {'Labels': {'org.haskoki.firefox.run': 'foreign'}}}]))
 sys.exit(0)
if sys.argv[1] in ('build','image','version'): sys.exit(0)
sys.exit(1)
''')
        docker.chmod(0o755)
        self.calls = self.root / 'calls'
        self.env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'], CALLS=str(self.calls))
    def run_demo(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], env=self.env, text=True, capture_output=True)
    def recorded(self):
        return [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []
    def test_existing_directory_is_refused_unchanged(self):
        out = self.root / 'existing'; out.mkdir(); (out/'keep').write_text('original')
        for action in ('start','test'):
            result = self.run_demo(action, '--out', str(out))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('exists', result.stderr)
        self.assertEqual(list(out.iterdir()), [out/'keep'])
        self.assertEqual((out/'keep').read_text(), 'original')
        self.assertEqual(self.recorded(), [])
    def test_invalid_ports_do_not_create_output_or_call_docker(self):
        for port in ('0', '65536', '-1', 'abc'):
            out = self.root / ('port'+port)
            result = self.run_demo('start', '--out', str(out), '--port', port)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('port', result.stderr.lower())
            self.assertFalse(out.exists())
        self.assertEqual(self.recorded(), [])
    def test_space_unicode_path_remains_one_mount_argument_on_start_failure(self):
        out = self.root / 'Firefox käyttäjä space'
        result = self.run_demo('start', '--out', str(out))
        self.assertNotEqual(result.returncode, 0)
        calls = self.recorded()
        runs = [x for x in calls if x[0] == 'run']
        self.assertTrue(runs, result.stderr)
        self.assertIn(str(out.resolve())+':/out', runs[0])
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)
        self.assertTrue((out/'state.json').exists())
    def test_cleanup_refuses_foreign_container_even_with_tampered_state(self):
        out = self.root/'run'; out.mkdir()
        (out/'state.json').write_text(json.dumps({'run_id': 'a'*32, 'out':str(out.resolve()), 'containers':['foreign'], 'port':6080}))
        result = self.run_demo('stop', '--out', str(out))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ownership', result.stderr.lower())
        self.assertFalse(any(x[0] in ('stop','rm') for x in self.recorded()))
    def test_loopback_publish_and_owned_cleanup_retain_artifacts(self):
        out=self.root/'käyttäjä desktop'
        self.env.update(FAKE_SUCCESS='1',FAKE_OUT=str(out.resolve()))
        result=self.run_demo('start','--out',str(out),'--port','6108')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('http://127.0.0.1:6108/',result.stdout)
        runs=[x for x in self.recorded() if x[0]=='run']
        self.assertEqual(len(runs),2)
        self.assertIn('127.0.0.1:6108:6080',runs[1])
        result=self.run_demo('stop','--out',str(out))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((out/'state.json').exists())
        self.assertTrue(json.loads((out/'state.json').read_text())['stopped'])
        removed=[x for x in self.recorded() if x[0]=='rm']
        self.assertEqual(removed,[['rm','-f','d'*64],['rm','-f','c'*64]])

    def test_negative_control_stops_validated_immutable_token_id(self):
        out=self.root/'test-stop'
        self.env.update(FAKE_SUCCESS='1',FAKE_TEST='1',FAKE_OUT=str(out.resolve()))
        result=self.run_demo('test','--out',str(out))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([c for c in self.recorded() if c[0]=='stop'],[['stop','-t','10','d'*64]])

    def test_negative_control_refuses_replaced_token_labels_or_mount(self):
        for mismatch in ('labels','mount'):
            with self.subTest(mismatch=mismatch):
                out=self.root/mismatch
                self.env.update(FAKE_SUCCESS='1',FAKE_TEST='1',FAKE_OUT=str(out.resolve()),FAKE_FOREIGN_TOKEN=mismatch)
                result=self.run_demo('test','--out',str(out))
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertIn('ownership',result.stderr)
                self.assertFalse(any(c[0]=='stop' for c in self.recorded()))
                self.calls.unlink()

    def test_token_ready_marker_requires_live_service(self):
        out=self.root/'dead-token'
        self.env.update(FAKE_SUCCESS='1',FAKE_OUT=str(out.resolve()),FAKE_DEAD_TOKEN_AT='token-ready')
        result=self.run_demo('start','--out',str(out))
        self.assertNotEqual(result.returncode,0)
        self.assertIn('container exited',result.stderr)
        self.assertNotIn('Firefox desktop:',result.stdout)
        self.assertEqual(len([c for c in self.recorded() if c[0]=='run']),1)

    def test_interactive_success_rechecks_token_after_browser_ready(self):
        out=self.root/'token-dies-while-browser-starts'
        self.env.update(FAKE_SUCCESS='1',FAKE_OUT=str(out.resolve()),FAKE_DEAD_TOKEN_AT='browser-ready')
        result=self.run_demo('start','--out',str(out))
        self.assertNotEqual(result.returncode,0)
        self.assertIn('container exited',result.stderr)
        self.assertNotIn('Firefox desktop:',result.stdout)
        self.assertEqual(len([c for c in self.recorded() if c[0]=='run']),2)

    def test_browser_ready_marker_requires_live_service(self):
        out=self.root/'dead-browser'
        self.env.update(FAKE_SUCCESS='1',FAKE_OUT=str(out.resolve()),FAKE_DEAD_BROWSER='1')
        result=self.run_demo('start','--out',str(out))
        self.assertNotEqual(result.returncode,0)
        self.assertIn('container exited',result.stderr)
        self.assertNotIn('Firefox desktop:',result.stdout)

    def test_terminal_test_receipt_may_outlive_browser(self):
        out=self.root/'completed-browser'
        self.env.update(FAKE_SUCCESS='1',FAKE_TEST='1',FAKE_OUT=str(out.resolve()),FAKE_DONE_BROWSER_EXITED='1')
        result=self.run_demo('test','--out',str(out))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads((out/'report.json').read_text())['passed'])

    def test_repeat_stop_accepts_actual_lowercase_missing_container_error(self):
        out=self.root/'missing';out.mkdir()
        (out/'state.json').write_text(json.dumps({'run_id':'a'*32,'out':str(out.resolve()),'containers':['gone'],'port':6080}))
        self.env['FAKE_MISSING']='1'
        result=self.run_demo('stop','--out',str(out))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads((out/'state.json').read_text())['stopped'])
        self.assertFalse(any(x[0]=='rm' for x in self.recorded()))

    def test_candidate_image_override_is_recorded_and_used(self):
        out=self.root/'candidate'
        self.env.update(FAKE_SUCCESS='1',FAKE_OUT=str(out.resolve()))
        result=self.run_demo('start','--out',str(out),'--token-image','example/haskoki:qualified-candidate')
        self.assertEqual(result.returncode,0,result.stderr)
        token_run=next(x for x in self.recorded() if x[0]=='run')
        self.assertIn('example/haskoki:qualified-candidate',token_run)
        self.assertEqual(json.loads((out/'state.json').read_text())['token_image'],'example/haskoki:qualified-candidate')

    def test_failed_acceptance_is_reported_before_phase_timeout(self):
        spec=importlib.util.spec_from_file_location('firefox_demo',SCRIPT)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        out=self.root/'failed'; out.mkdir()
        (out/'test.done').touch()
        (out/'report.json').write_text(json.dumps({'passed':False,'error':'specific NSS failure'}))
        with self.assertRaisesRegex(RuntimeError,'browser acceptance failed: specific NSS failure'):
            module.wait_file(out,'phase-stop-token','unused',timeout=1)

    def test_cleanup_rejects_state_from_another_directory(self):
        out = self.root/'run'; out.mkdir()
        (out/'state.json').write_text(json.dumps({'run_id':'a'*32,'out':'/someone/else','containers':['foreign'],'port':6080}))
        result = self.run_demo('stop', '--out', str(out))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.recorded(), [])

class SigningEvidence(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('firefox_browser',SCRIPT.with_name('browser.py'))
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
    def parse(self,text):
        self.assertTrue(callable(getattr(self.module,'successful_signatures',None)),'signing evidence parser missing')
        return self.module.successful_signatures(text)
    def test_completed_multipart_signature_counts(self):
        log="""10: C_SignUpdate
Returned:  0 CKR_OK
11: C_SignFinal
[in] hSession = 0x5
[out] pSignature[*pulSignatureLen] 0000123456789abc / 64
    00000000  01 02 03 04
Returned:  0 CKR_OK
12: C_CloseSession
Returned:  0 CKR_OK
"""
        self.assertEqual(self.parse(log),[{'function':'C_SignFinal','bytes':64}])
    def test_length_query_and_failed_call_do_not_count(self):
        log="""10: C_Sign
[in] pSignature = NULL
[out] *pulSignatureLen = 64
Returned:  0 CKR_OK
11: C_SignFinal
[out] pSignature[*pulSignatureLen] 0000123456789abc / 64
Returned:  150 CKR_BUFFER_TOO_SMALL
12: C_GetSessionInfo
Returned:  0 CKR_OK
"""
        self.assertEqual(self.parse(log),[])
    def test_absent_token_requires_the_matching_nginx_denial(self):
        check=getattr(self.module,'missing_client_denial',None)
        self.assertTrue(callable(check),'missing-client denial parser missing')
        for log,want in [
            ('NONE|-|-|400|/?absent|TLSv1.3\n',True),
            ('NONE|-|-|400|/favicon.ico|TLSv1.3\n',False),
            ('NONE|-|-|404|/?absent|TLSv1.3\n',False),
            ('FAILED:certificate verify failed|CN=other|abc|400|/?absent|TLSv1.3\n',False),
        ]:
            with self.subTest(log=log): self.assertEqual(check(log),want)

    def test_completed_one_shot_signature_counts(self):
        self.assertEqual(self.parse("10: C_Sign\n[out] pSignature[*pulSignatureLen] 0000123456789abc / 64\nReturned:  0 CKR_OK\n"),[{'function':'C_Sign','bytes':64}])

if __name__ == '__main__': unittest.main()
