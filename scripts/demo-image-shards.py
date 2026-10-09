#!/usr/bin/env python3
"""Bind three demo test receipts to one saved image; no registry or build calls."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# Reuse the publisher's saved-configuration parser and source-label policy.
_spec = importlib.util.spec_from_file_location('release_request', Path(__file__).with_name('release-request.py'))
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)
PHASES = ('contracts', 'full', 'compare')


def refuse(message):
    raise release.Refusal(message)


def archive_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def inspect(image, field):
    return subprocess.check_output(['docker', 'inspect', '--format', field, image], text=True).strip()


def check_results(build, shards):
    if build != 'success' or shards != 'success':
        refuse(f'required demo jobs must both succeed (build={build!r}, shards={shards!r})')


def read_identity(args):
    identity = json.loads(args.identity.read_text())
    if identity.get('schema') != 1:
        refuse('unsupported candidate identity schema')
    if identity.get('source') != args.source or identity.get('version') != args.version:
        refuse('candidate source/version differs from the selected source/version')
    if not re.fullmatch(r'[0-9a-f]{40}', args.source):
        refuse('candidate source must be an exact Git SHA')
    for name in ('imageid', 'configid'):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', identity.get(name, '')):
            refuse(f'candidate {name} missing or malformed')
    for name in ('base_digest', 'rust_digest'):
        if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', identity.get(name, '')):
            refuse(f'candidate {name} missing or malformed')
    if not re.fullmatch(r'[0-9a-f]{64}', identity.get('archive_sha256', '')):
        refuse('candidate archive hash missing or malformed')
    return identity


def verify_archive(args, identity):
    if archive_hash(args.archive) != identity['archive_sha256']:
        refuse('candidate archive hash differs from saved bytes')
    configid, config = release.archive_config(args.archive)
    if configid != identity['configid']:
        refuse('candidate archive configuration differs')
    release.check_labels({'sha': args.source, 'version': args.version},
                         config.get('config', {}).get('Labels') or {})


def verify_image(args, identity):
    imageid = inspect(args.image, '{{.Id}}')
    if imageid != identity['imageid']:
        refuse('loaded image id differs from candidate image')
    release.check_labels({'sha': args.source, 'version': args.version},
                         json.loads(inspect(imageid, '{{json .Config.Labels}}')))
    return imageid


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['capture', 'verify-archive', 'verify-image', 'receipt', 'check-results', 'gate'])
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--image')
    parser.add_argument('--source')
    parser.add_argument('--version')
    parser.add_argument('--base-digest')
    parser.add_argument('--rust-digest')
    parser.add_argument('--phase', choices=PHASES)
    parser.add_argument('--runs', type=Path)
    parser.add_argument('--build-result', default='')
    parser.add_argument('--shards-result', default='')
    args = parser.parse_args()
    try:
        if args.operation in ('check-results', 'gate'):
            check_results(args.build_result, args.shards_result)
        if args.operation == 'check-results':
            return
        for required in ('identity', 'archive', 'source', 'version'):
            if not getattr(args, required):
                refuse(f'--{required} is required')
        if args.operation == 'capture':
            if not args.image:
                refuse('--image is required')
            configid, _ = release.archive_config(args.archive)
            write_json(args.identity, {'schema': 1, 'source': args.source, 'version': args.version,
                                     'imageid': inspect(args.image, '{{.Id}}'), 'configid': configid,
                                     'archive_sha256': archive_hash(args.archive),
                                     'base_digest': args.base_digest or '', 'rust_digest': args.rust_digest or ''})
        identity = read_identity(args)
        verify_archive(args, identity)
        if args.operation in ('capture', 'verify-image', 'receipt'):
            if not args.image:
                refuse('--image is required')
            imageid = verify_image(args, identity)
            if args.operation == 'verify-image':
                print(imageid)
        if args.operation == 'receipt':
            if not args.phase or not args.runs:
                refuse('--phase and --runs are required')
            write_json(args.runs / 'phase-receipt.json', dict(identity, phase=args.phase, result='success'))
        if args.operation == 'gate':
            if not args.runs:
                refuse('--runs is required')
            for phase in PHASES:
                path = args.runs / phase / 'phase-receipt.json'
                if not path.is_file():
                    refuse(f'required {phase} shard receipt missing')
                receipt = json.loads(path.read_text())
                if receipt != dict(identity, phase=phase, result='success'):
                    refuse(f'{phase} shard identity/result differs from the candidate')
            # The caller promotes these exact archive bytes only after this returns.
            outputs = ''.join(f'{name}={identity[name]}\n' for name in
                              ('imageid', 'configid', 'base_digest', 'rust_digest'))
            print(outputs, end='')
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                    stream.write(outputs)
    except (release.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
