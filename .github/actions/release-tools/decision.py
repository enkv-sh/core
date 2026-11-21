"""Authenticate the original tools choice before a release job checks it out."""

import http.client
import json
import os
from pathlib import Path
import re
import sys


def original_decision():
    run = os.environ['GITHUB_RUN_ID']
    source = os.environ['GITHUB_SHA']
    if (os.environ['GITHUB_REPOSITORY'] != 'enkv-sh/core'
            or not re.fullmatch('[1-9][0-9]*', run)
            or not re.fullmatch('[0-9a-f]{40}', source)):
        raise SystemExit('invalid Core release run')

    connection = http.client.HTTPSConnection('api.github.com', timeout=30)
    try:
        connection.request('GET', f'/repos/enkv-sh/core/actions/runs/{run}/attempts/1/jobs?per_page=100', headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
            'User-Agent': 'enkv-release',
        })
        response = connection.getresponse()
        if response.status != 200:
            raise SystemExit(f'original release jobs unavailable (HTTP {response.status})')
        page = json.load(response)
    finally:
        connection.close()

    # The release workflow fits on one page. An incomplete listing cannot
    # establish that exactly one protected job recorded the decision.
    jobs = page['jobs']
    if len(jobs) != page['total_count']:
        raise SystemExit('incomplete original release job list')
    decisions = [job for job in jobs if job['name'].startswith('Release tools ')]
    if len(decisions) != 1:
        raise SystemExit('expected one original release tools decision')
    job = decisions[0]
    match = re.fullmatch(r'Release tools ([0-9a-f]{40}) ([1-9][0-9]*)', job['name'])
    if (not match or job['run_id'] != int(run) or job['head_sha'] != source
            or job['head_branch'] != 'main' or job.get('run_attempt', 1) != 1
            or job['status'] != 'completed' or job['conclusion'] != 'success'):
        raise SystemExit('original release tools decision did not verify')
    commit, artifact_id = match.groups()
    # The pinned downloader represents numeric IDs as JavaScript numbers.
    if int(artifact_id) > 2**53 - 1:
        raise SystemExit('release artifact ID exceeds exact download range')
    return {'commit': commit, 'artifact_id': artifact_id}


def verified_commit():
    expected = os.environ['EXPECTED_COMMIT']
    directory = Path(os.environ['RUNNER_TEMP']) / 'verified-release-tools'
    entry = directory / 'commit'
    if (not re.fullmatch('[0-9a-f]{40}', expected) or directory.is_symlink()
            or list(directory.iterdir()) != [entry] or entry.is_symlink() or not entry.is_file()):
        raise SystemExit('invalid release tools artifact')
    with entry.open('rb') as saved:
        if saved.read(42) != (expected + '\n').encode('ascii'):
            raise SystemExit('release tools artifact differs from original decision')
    return {'commit': expected}


def main(command):
    if command == 'lookup':
        fields = original_decision()
    elif command == 'verify':
        fields = verified_commit()
    else:
        raise SystemExit('unknown release tools operation')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for name, value in fields.items():
            print(f'{name}={value}', file=output)


if __name__ == '__main__':
    main(sys.argv[1])
