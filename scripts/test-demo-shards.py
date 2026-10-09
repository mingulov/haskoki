#!/usr/bin/env python3
"""Phase selection and artifact gate behavior with small external boundaries."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / 'scripts/test-demo-image.sh'
HELPER = ROOT / 'scripts/demo-image-shards.py'
SOURCE = 'a' * 40
IMAGE = 'sha256:' + 'b' * 64
BASE_DIGEST = 'ubuntu@sha256:' + 'c' * 64
RUST = 'rust@sha256:' + 'd' * 64


class ShardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        # Inspect is a read-only daemon boundary. Every other Docker operation
        # fails, so accidental stage/build or wrong phase entry is observable.
        docker = self.bin / 'docker'
        docker.write_text('''#!/bin/sh
if [ "$1" = inspect ]; then
  case "$3" in
    '{{.Id}}') echo "$FIXTURE_IMAGE" ;;
    '{{.Size}}') echo 509000000 ;;
    '{{json .Config.Labels}}') echo "$FIXTURE_LABELS" ;;
    *) echo '[]' ;;
  esac
  exit 0
fi
printf 'boundary:%s\\n' "$*" >&2
exit 47
''')
        docker.chmod(0o755)
        self.labels = {'org.opencontainers.image.version': '0.3.0.0',
                       'org.opencontainers.image.revision': SOURCE,
                       'org.opencontainers.image.source': 'https://github.com/mingulov/haskoki'}
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}',
                        FIXTURE_IMAGE=IMAGE, FIXTURE_LABELS=json.dumps(self.labels),
                        HASKOKI_DEMO_IMAGE='fixture:owned', HASKOKI_DEMO_REVISION=SOURCE,
                        HASKOKI_DEMO_TEST_OUT=str(self.work / 'out'))
        self.archive = self.work / 'demo-image.tar.gz'
        config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                             'config': {'Labels': self.labels},
                             'rootfs': {'type': 'layers', 'diff_ids': []}}).encode()
        self.configid = 'sha256:' + hashlib.sha256(config).hexdigest()
        with tarfile.open(self.archive, 'w:gz') as saved:
            for name, raw in [('manifest.json', b'[{"Config":"config.json","Layers":[]}]'),
                              ('config.json', config)]:
                entry = tarfile.TarInfo(name)
                entry.size = len(raw)
                saved.addfile(entry, io.BytesIO(raw))
        self.identity = self.work / 'identity.json'
        self.expected = {'schema': 1, 'source': SOURCE, 'version': '0.3.0.0',
                         'imageid': IMAGE, 'configid': self.configid,
                         'archive_sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                         'base_digest': BASE_DIGEST, 'rust_digest': RUST}
        self.identity.write_text(json.dumps(self.expected))
        self.runs = self.work / 'runs'
        for phase in ('contracts', 'full', 'compare'):
            target = self.runs / phase
            target.mkdir(parents=True)
            (target / 'phase-receipt.json').write_text(json.dumps(
                dict(self.expected, phase=phase, result='success')))

    def driver(self, *args, **env):
        return subprocess.run(['sh', str(DRIVER), *args], env=dict(self.env, **env),
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def helper(self, operation, *extra):
        return subprocess.run(['python3', str(HELPER), operation,
                               '--identity', str(self.identity), '--archive', str(self.archive),
                               '--source', SOURCE, '--version', '0.3.0.0', *extra],
                              env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def gate(self, build='success', shards='success'):
        return self.helper('gate', '--runs', str(self.runs),
                           '--build-result', build, '--shards-result', shards)

    def workflow_step(self, name, **env):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        gate = text.split('  demo-image:\n', 1)[1].split('  publish:\n', 1)[0]
        step = gate.split('      - name: ' + name + '\n', 1)[1].split('      - name:', 1)[0]
        payload = textwrap.dedent(step.split('        run: |\n', 1)[1])
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', payload],
                              cwd=self.work, env=dict(self.env, GITHUB_SHA=SOURCE,
                              GITHUB_OUTPUT=str(self.work / 'outputs'), **env),
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_workflow_gate_only_promotes_after_real_receipt_validation(self):
        (self.work / 'haskoki.cabal').write_text('version: 0.3.0.0\n')
        (self.work / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
        (self.work / 'driver-out').symlink_to(self.runs, target_is_directory=True)
        candidate = self.work / 'candidate'
        candidate.mkdir()
        (candidate / 'demo-image.tar.gz').write_bytes(self.archive.read_bytes())
        (candidate / 'identity.json').write_text(self.identity.read_text())
        promoted = self.work / 'demo-image.tar.gz'
        # The source archive lives at this name in the test fixture; remove it
        # after staging to distinguish actual workflow promotion from setup.
        promoted.unlink()
        name = 'Verify complete same-source same-image qualification'
        result = self.workflow_step(name, BUILD_RESULT='success', SHARDS_RESULT='success')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(promoted.read_bytes(), (candidate / promoted.name).read_bytes())
        for output in ('imageid', 'configid', 'base_digest', 'rust_digest'):
            self.assertIn(f'{output}={self.expected[output]}', (self.work / 'outputs').read_text())
        promoted.unlink()
        (self.runs / 'full/phase-receipt.json').unlink()
        result = self.workflow_step(name, BUILD_RESULT='success', SHARDS_RESULT='success')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(promoted.exists(), 'unqualified bytes were promoted')

    def test_workflow_result_step_refuses_every_non_success_need(self):
        (self.work / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
        name = 'Fail closed on required job results'
        for status in ('failure', 'cancelled', 'skipped', ''):
            result = self.workflow_step(name, BUILD_RESULT='success', SHARDS_RESULT=status)
            self.assertNotEqual(result.returncode, 0, status)
        result = self.workflow_step(name, BUILD_RESULT='success', SHARDS_RESULT='success')
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_default_and_build_still_stage_the_bundle(self):
        for args in ((), ('all',), ('build',)):
            result = self.driver(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('staging bundle via make-release.sh', result.stdout)
            self.assertIn('scripts/make-release.sh', (self.work / 'out/stage-bundle.log').read_text())

    def test_failed_phase_removes_old_success_receipt(self):
        out = self.work / 'out'
        out.mkdir()
        receipt = out / 'phase-receipt.json'
        receipt.write_text('{"result":"success"}')
        result = self.driver('full')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(receipt.exists())

    def test_invalid_phase_is_refused_before_any_docker_work(self):
        result = self.driver('invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid phase', result.stdout)
        self.assertNotIn('boundary:', result.stdout)

    def test_extra_argument_is_refused(self):
        result = self.driver('full', 'ignored')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('usage:', result.stdout.lower())
        self.assertNotIn('boundary:', result.stdout)

    def test_test_phases_enter_their_actual_first_command_and_propagate_failure(self):
        for phase, command in [('contracts', 'demo'), ('full', 'check --mode direct --profile full'),
                               ('compare', 'compare')]:
            with self.subTest(phase=phase):
                result = self.driver(phase)
                self.assertNotEqual(result.returncode, 0)
                log = next((self.work / 'out').glob('*.log'))
                self.assertIn(f'{IMAGE} {command}', log.read_text())
                self.assertNotIn('staging bundle', result.stdout)
                self.assertFalse((self.work / 'out/phase-receipt.json').exists())
                log.unlink()

    def test_test_phase_needs_explicit_image(self):
        result = self.driver('full', HASKOKI_DEMO_IMAGE='')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HASKOKI_DEMO_IMAGE', result.stdout)
        self.assertNotIn('boundary:', result.stdout)

    def test_wrong_loaded_image_is_refused(self):
        result = self.helper('verify-image', '--image', 'fixture:owned')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.env['FIXTURE_IMAGE'] = 'sha256:' + 'e' * 64
        result = self.helper('verify-image', '--image', 'fixture:owned')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('image', result.stdout)

    def test_capture_and_receipt_keep_docker_id_distinct_from_configuration_digest(self):
        self.identity.unlink()
        result = self.helper('capture', '--image', 'fixture:owned',
                             '--base-digest', BASE_DIGEST, '--rust-digest', RUST)
        self.assertEqual(result.returncode, 0, result.stdout)
        identity = json.loads(self.identity.read_text())
        self.assertEqual(identity, self.expected)
        self.assertNotEqual(identity['imageid'], identity['configid'])
        output = self.work / 'new-receipt'
        result = self.helper('receipt', '--image', 'fixture:owned', '--phase', 'full', '--runs', str(output))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads((output / 'phase-receipt.json').read_text()),
                         dict(self.expected, phase='full', result='success'))

    def test_gate_accepts_exact_three_receipts_and_preserves_publisher_outputs(self):
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stdout)
        for name in ('imageid', 'configid', 'base_digest', 'rust_digest'):
            self.assertIn(f'{name}={self.expected[name]}', result.stdout)

    def test_gate_refuses_failed_cancelled_skipped_or_missing_job_results(self):
        for status in ('failure', 'cancelled', 'skipped', ''):
            for target in ('build', 'shards'):
                with self.subTest(status=status, target=target):
                    result = self.gate(**{target: status})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('required', result.stdout)

    def test_gate_refuses_missing_receipt(self):
        (self.runs / 'full/phase-receipt.json').unlink()
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('full', result.stdout)

    def test_gate_refuses_changed_identity_or_failed_receipt(self):
        path = self.runs / 'compare/phase-receipt.json'
        for key, value in [('imageid', 'sha256:' + 'e' * 64), ('source', 'f' * 40),
                           ('configid', 'sha256:' + 'e' * 64), ('phase', 'full'),
                           ('result', 'failure'), ('archive_sha256', 'e' * 64)]:
            with self.subTest(key=key):
                receipt = dict(self.expected, phase='compare', result='success')
                receipt[key] = value
                path.write_text(json.dumps(receipt))
                result = self.gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('compare', result.stdout)

    def test_archive_tamper_and_wrong_source_fail_closed(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('archive', result.stdout)
        self.identity.write_text(json.dumps(dict(self.expected, source='f' * 40)))
        result = self.helper('verify-archive')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('source', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
