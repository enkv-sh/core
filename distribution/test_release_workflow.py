"""Local checks for automatic release source selection. HTTP is mocked."""

import base64
import hashlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/release.yml'
COMMIT = 'a' * 40
CLI_DER = bytes.fromhex('302a300506032b65700321003d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
PLUGIN_DER = bytes.fromhex('302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')


def inline_python(name):
    step = WORKFLOW.read_text().split('      - name: ' + name + '\n', 1)[1]
    script = step.split("          python3 - <<'", 1)[1]
    marker, body = script.split("'\n", 1)
    body = body.split('\n          ' + marker, 1)[0]
    return '\n'.join(line[10:] for line in body.splitlines())


def public_pem(der):
    return '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode() + '\n-----END PUBLIC KEY-----\n'


class CoreReleaseWorkflowTests(unittest.TestCase):
    def test_jobs_checkout_the_dispatch_source_and_the_saved_tools_revision(self):
        text = WORKFLOW.read_text().split('\njobs:\n', 1)[1]
        jobs = re.split(r'^  (\w+):\n', text, flags=re.M)
        for name, job in zip(jobs[1::2], jobs[2::2]):
            with self.subTest(job=name):
                tools_ref = 'steps.tools.outputs.commit' if name == 'prepare' else 'needs.prepare.outputs.tools_commit'
                checkouts = re.findall(r'uses: actions/checkout@[^\n]+\n        with:\n((?:          [^\n]+\n)+)', job)
                refs = {}
                for checkout in checkouts:
                    fields = dict(line.strip().split(': ', 1) for line in checkout.splitlines())
                    refs[fields['path']] = (fields.get('repository'), fields['ref'])
                self.assertEqual(refs, {
                    'source': (None, '${{ github.sha }}'),
                    'tools-source': ('enkv-sh/extensions', '${{ ' + tools_ref + ' }}'),
                })
                for value in re.findall(r'^          SOURCE_COMMIT: (.*)$', job, re.M):
                    self.assertEqual(value, '${{ github.sha }}')
        self.assertIn('tools_commit: ${{ steps.tools.outputs.commit }}', text)
        self.assertIn('>> "$RUNNER_TEMP/build/cli/evidence/native-environment.txt"', text)

    def test_dispatch_preflight(self):
        script = inline_python('Check owner release inputs')
        valid = dict(
            SOURCE_COMMIT=COMMIT, REF_PROTECTED='true',
            CLI_PUBLIC_KEY_PEM=public_pem(CLI_DER),
            PLUGIN_PUBLIC_KEY_PEM=public_pem(PLUGIN_DER),
            DEVELOPMENT_CLI_KEY='0' * 64, DEVELOPMENT_PLUGIN_KEY='0' * 64,
        )
        cases = {
            'valid': {},
            'unprotected': {'REF_PROTECTED': 'false'},
            'invalid-sha': {'SOURCE_COMMIT': 'main'},
            'invalid-key': {'CLI_PUBLIC_KEY_PEM': 'invalid'},
            'same-key': {'CLI_PUBLIC_KEY_PEM': public_pem(PLUGIN_DER)},
            'development-key': {'DEVELOPMENT_CLI_KEY': hashlib.sha256(PLUGIN_DER).hexdigest()},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    ['python3', '-I', '-c', script],
                    env={**os.environ, **valid, **changes}, capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode == 0, name == 'valid', result.stderr.decode())

    def test_extensions_branch_selection(self):
        script = compile(inline_python('Select protected extensions main once'), str(WORKFLOW), 'exec')
        cases = {
            'valid': {'name': 'main', 'protected': True, 'commit': {'sha': COMMIT}},
            'unprotected': {'name': 'main', 'protected': False, 'commit': {'sha': COMMIT}},
            'other-branch': {'name': 'other', 'protected': True, 'commit': {'sha': COMMIT}},
            'malformed-sha': {'name': 'main', 'protected': True, 'commit': {'sha': 'main'}},
            'multiple-shas': {'name': 'main', 'protected': True, 'commit': {'sha': COMMIT + '\n' + COMMIT}},
            'missing-branch': {},
        }
        for name, branch in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                response = io.StringIO(json.dumps(branch))
                with patch.dict(os.environ, RUNNER_TEMP=scratch), patch('urllib.request.urlopen', return_value=response) as request:
                    if name == 'valid':
                        exec(script, {})
                    else:
                        with self.assertRaises(SystemExit):
                            exec(script, {})
                self.assertEqual(request.call_args.args[0].full_url, 'https://api.github.com/repos/enkv-sh/extensions/branches/main')
                selected = Path(scratch) / 'release-tools/commit'
                self.assertEqual(selected.exists(), name == 'valid')
                if selected.exists():
                    self.assertEqual(selected.read_text(), COMMIT + '\n')
        with tempfile.TemporaryDirectory() as scratch, patch.dict(os.environ, RUNNER_TEMP=scratch), patch('urllib.request.urlopen', side_effect=urllib.error.URLError('unavailable')):
            with self.assertRaises(urllib.error.URLError):
                exec(script, {})
            self.assertFalse((Path(scratch) / 'release-tools/commit').exists())

    def test_saved_tools_commit(self):
        script = compile(inline_python('Check selected extensions commit'), str(WORKFLOW), 'exec')
        for value in [COMMIT + '\n', 'main\n', COMMIT, COMMIT + '\n' + COMMIT + '\n', None]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as scratch:
                directory = Path(scratch)
                (directory / 'release-tools').mkdir()
                if value is not None:
                    (directory / 'release-tools/commit').write_text(value)
                output = directory / 'outputs'
                with patch.dict(os.environ, RUNNER_TEMP=scratch, GITHUB_OUTPUT=str(output)):
                    if value == COMMIT + '\n':
                        exec(script, {})
                    else:
                        with self.assertRaises((SystemExit, FileNotFoundError)):
                            exec(script, {})
                self.assertEqual(output.exists(), value == COMMIT + '\n')
                if output.exists():
                    self.assertEqual(output.read_text(), 'commit=' + COMMIT + '\n')


if __name__ == '__main__':
    unittest.main()
