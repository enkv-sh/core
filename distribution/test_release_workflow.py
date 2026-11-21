"""Local checks for automatic release source selection. HTTP is mocked."""

import base64
import hashlib
import json
import os
import re
import runpy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/release.yml'
ACTION = WORKFLOW.parents[1] / 'actions/release-tools'
COMMIT = 'a' * 40
SOURCE = 'b' * 40
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
    def test_linux_build_installs_cmp_before_checking_go_mod(self):
        build = WORKFLOW.read_text().split('\n  build:\n', 1)[1].split('\n  sign:\n', 1)[0]
        setup, _, _ = build.partition('          cmp source/compositions/full/go.mod "$RUNNER_TEMP/bootstrap.go.mod"\n')
        self.assertNotEqual(setup, build, 'missing bootstrap go.mod comparison')
        packages = re.search(r'^          dnf install -y (.+)$', setup, re.M)
        self.assertIsNotNone(packages, 'missing Linux package installation')
        self.assertIn('diffutils', packages[1].split(), 'AlmaLinux supplies cmp in diffutils')

    def test_each_consumer_verifies_before_tools_checkout(self):
        workflow = WORKFLOW.read_text()
        blocks = re.split(r'^  (\w+):\n', workflow.split('\njobs:\n', 1)[1], flags=re.M)
        jobs = dict(zip(blocks[1::2], blocks[2::2]))
        self.assertEqual(set(jobs), {'select', 'record', 'prepare', 'build', 'sign', 'stage'})
        select = jobs['select']
        self.assertEqual(select.count("if: github.run_attempt == '1'"), 2)
        self.assertIn('commit: ${{ steps.select-tools.outputs.commit }}', select)
        self.assertIn('artifact_id: ${{ steps.upload.outputs.artifact-id }}', select)
        self.assertIn('id: upload\n        if: github.run_attempt', select)
        self.assertIn('name: release-tools-commit', select)
        self.assertIn('path: ${{ runner.temp }}/release-tools/commit', select)
        self.assertIn('needs: select\n', jobs['record'])
        self.assertIn("github.run_attempt == '1' && format('Release tools {0} {1}', needs.select.outputs.commit, needs.select.outputs.artifact_id)", jobs['record'])
        self.assertIn('needs: record\n', jobs['prepare'])
        action = (ACTION / 'action.yml').read_text()
        self.assertIn('value: ${{ steps.verify.outputs.commit }}', action)
        self.assertIn('artifact-ids: ${{ steps.decision.outputs.artifact_id }}', action)
        self.assertIn('EXPECTED_COMMIT: ${{ steps.decision.outputs.commit }}', action)
        self.assertIn('merge-multiple: true', action)
        self.assertIn('path: ${{ runner.temp }}/verified-release-tools', action)
        self.assertLess(action.index('decision.py" lookup'), action.index('actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'))
        self.assertLess(action.index('artifact-ids:'), action.index('decision.py" verify'))
        self.assertNotIn('name: release-tools-commit', action)
        for name in ['prepare', 'build', 'sign', 'stage']:
            with self.subTest(job=name):
                job = jobs[name]
                verify = 'uses: ./source/.github/actions/release-tools'
                self.assertEqual(job.count(verify), 1)
                self.assertIn('ref: ${{ github.sha }}\n          path: source', job)
                self.assertLess(job.index('path: source\n'), job.index(verify))
                self.assertLess(job.index(verify), job.index('repository: enkv-sh/extensions'))
                self.assertIn('ref: ${{ steps.tools.outputs.commit }}\n          path: tools-source', job)
                self.assertLess(job.index(verify), job.index('Build reviewed release tools'))
                self.assertIn('actions: read', job)
        self.assertLess(jobs['sign'].index(verify), jobs['sign'].index('secrets.CLI_SIGNING_KEY_PEM'))
        self.assertIn('TOOLS_COMMIT: ${{ steps.tools.outputs.commit }}', jobs['build'])

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
        name = 'Select protected extensions main once'
        step = WORKFLOW.read_text().split('      - name: ' + name + '\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('        env:\n          GH_TOKEN: ${{ github.token }}\n', step)
        script = compile(inline_python(name), str(WORKFLOW), 'exec')
        valid = {'name': 'main', 'protected': True, 'commit': {'sha': COMMIT}}
        cases = {
            'valid': (200, valid),
            'unprotected': (200, {**valid, 'protected': False}),
            'other-branch': (200, {**valid, 'name': 'other'}),
            'malformed-sha': (200, {**valid, 'commit': {'sha': 'main'}}),
            'multiple-shas': (200, {**valid, 'commit': {'sha': COMMIT + '\n' + COMMIT}}),
            'missing-branch': (200, {}),
            'rate-limited': (403, valid),
            'redirect': (302, valid),
        }
        for name, (status, branch) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                with patch.dict(os.environ, RUNNER_TEMP=scratch, GH_TOKEN='test-job-token', GITHUB_OUTPUT=str(Path(scratch) / 'outputs')), patch('http.client.HTTPSConnection') as connect:
                    connection = connect.return_value
                    response = connection.getresponse.return_value
                    response.status = status
                    response.read.return_value = json.dumps(branch).encode()
                    if name == 'valid':
                        exec(script, {})
                    elif status != 200:
                        with self.assertRaisesRegex(SystemExit, 'HTTP ' + str(status)):
                            exec(script, {})
                    else:
                        with self.assertRaises(SystemExit):
                            exec(script, {})
                connect.assert_called_once_with('api.github.com', timeout=30)
                connection.request.assert_called_once()
                args, kwargs = connection.request.call_args
                self.assertEqual(args, ('GET', '/repos/enkv-sh/extensions/branches/main'))
                self.assertEqual(kwargs['headers']['Authorization'], 'Bearer test-job-token')
                connection.close.assert_called_once_with()
                selected = Path(scratch) / 'release-tools/commit'
                self.assertEqual(selected.exists(), name == 'valid')
                if selected.exists():
                    self.assertEqual(selected.read_text(), COMMIT + '\n')
                    self.assertEqual((Path(scratch) / 'outputs').read_text(), 'commit=' + COMMIT + '\n')
        with tempfile.TemporaryDirectory() as scratch, patch.dict(os.environ, RUNNER_TEMP=scratch, GH_TOKEN='test-job-token', GITHUB_OUTPUT=str(Path(scratch) / 'outputs')), patch('http.client.HTTPSConnection') as connect:
            connect.return_value.getresponse.side_effect = OSError('unavailable')
            with self.assertRaises(OSError):
                exec(script, {})
            self.assertFalse((Path(scratch) / 'release-tools/commit').exists())

    def test_original_tools_decision(self):
        main = runpy.run_path(str(ACTION / 'decision.py'))['main']
        record = dict(name=f'Release tools {COMMIT} 703', run_id=41, head_sha=SOURCE,
                      head_branch='main', run_attempt=1, status='completed', conclusion='success')
        original = {'jobs': [record], 'total_count': 1}
        cases = [
            ('first-attempt', 1, original, {703: COMMIT + '\n'}, True),
            ('later-attempt', 3, original, {703: COMMIT + '\n'}, True),
            ('missing-decision', 2, {'jobs': [], 'total_count': 0}, {}, False),
            ('duplicate', 2, {'jobs': [record, record], 'total_count': 2}, {}, False),
            ('incomplete-list', 2, {'jobs': [record], 'total_count': 2}, {}, False),
            ('replaced-id', 2, original, {704: COMMIT + '\n'}, False),
            ('contradictory-commit', 2, original, {703: SOURCE + '\n'}, False),
            ('absent-artifact', 1, original, {}, False),
            ('invalid-format', 2, original, {703: COMMIT + '\r\n'}, False),
            ('extra-data', 2, original, {703: COMMIT + '\nextra'}, False),
        ]
        for field, value in [('head_sha', COMMIT), ('run_id', 42), ('head_branch', 'other'),
                             ('status', 'in_progress'), ('conclusion', 'failure'), ('run_attempt', 2),
                             ('name', 'Release tools bad 703'), ('name', f'Release tools {COMMIT} 9007199254740993')]:
            cases.append((field, 2, {'jobs': [{**record, field: value}], 'total_count': 1}, {703: COMMIT + '\n'}, False))
        for label, attempt, listing, artifacts, expected in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                lookup, verified = root / 'lookup', root / 'verified'
                env = dict(GITHUB_RUN_ID='41', GITHUB_RUN_ATTEMPT=str(attempt), GITHUB_SHA=SOURCE,
                           GITHUB_REPOSITORY='enkv-sh/core', GH_TOKEN='fixture', RUNNER_TEMP=scratch,
                           GITHUB_OUTPUT=str(lookup))
                with patch.dict(os.environ, env), patch('http.client.HTTPSConnection') as connect:
                    response = connect.return_value.getresponse.return_value
                    response.status = 200
                    response.read.return_value = json.dumps(listing).encode()
                    try:
                        main('lookup')
                        fields = dict(line.split('=', 1) for line in lookup.read_text().splitlines())
                        # The pinned action returns exactly the requested artifact ID or fails.
                        body = artifacts.get(int(fields['artifact_id']))
                        if body is not None:
                            directory = root / 'verified-release-tools'
                            directory.mkdir()
                            (directory / 'commit').write_bytes(body.encode())
                            with patch.dict(os.environ, EXPECTED_COMMIT=fields['commit'], GITHUB_OUTPUT=str(verified)):
                                main('verify')
                    except SystemExit:
                        if expected:
                            raise
                    self.assertEqual(verified.exists(), expected)
                    if expected:
                        self.assertEqual(verified.read_text(), f'commit={COMMIT}\n')
                    connection = connect.return_value
                    connect.assert_called_once_with('api.github.com', timeout=30)
                    self.assertEqual(connection.request.call_args.args,
                                     ('GET', '/repos/enkv-sh/core/actions/runs/41/attempts/1/jobs?per_page=100'))
                    connection.close.assert_called_once()


    def test_unavailable_job_record_and_unexpected_artifact_files(self):
        main = runpy.run_path(str(ACTION / 'decision.py'))['main']
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / 'outputs'
            env = dict(GITHUB_RUN_ID='41', GITHUB_SHA=SOURCE, GITHUB_REPOSITORY='enkv-sh/core',
                       GH_TOKEN='fixture', GITHUB_OUTPUT=str(output), RUNNER_TEMP=scratch,
                       EXPECTED_COMMIT=COMMIT)
            with patch.dict(os.environ, env), patch('http.client.HTTPSConnection') as connect:
                connect.return_value.getresponse.return_value.status = 404
                with self.assertRaises(SystemExit):
                    main('lookup')
                self.assertFalse(output.exists())
            directory = root / 'verified-release-tools'
            directory.mkdir()
            extra = directory / 'extra'
            extra.write_text(COMMIT + '\n')
            commit = directory / 'commit'
            commit.write_text(COMMIT + '\n')
            with patch.dict(os.environ, env):
                with self.assertRaises(SystemExit):
                    main('verify')
                self.assertFalse(output.exists())
                extra.rename(root / 'other-commit')
                commit.unlink()
                commit.symlink_to(root / 'other-commit')
                with self.assertRaises(SystemExit):
                    main('verify')
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
