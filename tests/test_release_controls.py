import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / '.github/workflows/web-app.yml'
DEPLOY = ROOT / '.github/workflows/deploy-production.yml'
SHA = 'a' * 40
VERSION = '12345678-1234-1234-1234-123456789abc'
spec = importlib.util.spec_from_file_location('verify_release', ROOT / 'scripts/verify-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def script(path, step):
    lines = path.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == '- name: ' + step)
    start = next(i for i in range(start, len(lines)) if lines[i].strip() == 'run: |') + 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start
    while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) >= indent):
        end += 1
    return textwrap.dedent('\n'.join(lines[start:end]))


CURL = r'''
curl() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -o) shift; printf '%s' "$MOCK_BODY" > "$1" ;;
      -D) shift; printf '%s' "$MOCK_HEADERS" > "$1" ;;
    esac
    shift
  done
  printf '%s' "$MOCK_STATUS"
}
'''


class ShellControls(unittest.TestCase):
    def run_shell(self, body, values=None, files=None, prefix=''):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {'PATH': os.environ['PATH'], 'GITHUB_OUTPUT': str(root / 'out'),
                   'RUNNER_TEMP': directory, 'TMPDIR': directory}
            env.update(values or {})
            for name, value in (files or {}).items():
                (root / name).write_text(value)
            result = subprocess.run(['/bin/bash', '-c', prefix + '\n' + body], cwd=root,
                                    env=env, capture_output=True, text=True, timeout=5)
            result.outputs = (root / 'out').read_text() if (root / 'out').exists() else ''
            return result

    def preview(self, sha=SHA, header=None, status='200', body='Sign in', site_url=''):
        return self.run_shell(script(ROOT / 'actions/wait-for-preview/action.yml', 'Poll the preview'), {
            'EXPECTED_SHA': sha, 'INPUT_ALIAS': '', 'HEAD_REF': 'feature/example',
            'WORKER_NAME': 'sak-portal-staging', 'SUBDOMAIN': 'example', 'SITE_URL': site_url,
            'PROBE_PATH': '/sign-in', 'TIMEOUT_MINUTES': '0',
            'CF_ACCESS_CLIENT_ID': '', 'CF_ACCESS_CLIENT_SECRET': '',
            'MOCK_HEADERS': header if header is not None else 'X-SAK-Build-SHA: ' + SHA + '\r\n',
            'MOCK_STATUS': status, 'MOCK_BODY': body,
        }, prefix=CURL)

    def test_expected_preview_passes(self):
        result = self.preview()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('sha=' + SHA, result.outputs)

    def test_missing_old_or_duplicate_build_identity_fails(self):
        for header in ['', 'X-SAK-Build-SHA: ' + 'b' * 40 + '\r\n',
                       ('X-SAK-Build-SHA: ' + SHA + '\r\n') * 2]:
            with self.subTest(header=header):
                self.assertNotEqual(self.preview(header=header).returncode, 0)

    def test_identity_does_not_override_failed_health_or_access(self):
        self.assertNotEqual(self.preview(status='500').returncode, 0)
        self.assertNotEqual(self.preview(body='Cloudflare Access').returncode, 0)

    def test_invalid_expected_sha_fails(self):
        self.assertNotEqual(self.preview(sha='').returncode, 0)
        self.assertNotEqual(self.preview(sha='main').returncode, 0)

    def test_explicit_staging_url_still_requires_identity(self):
        self.assertEqual(self.preview(site_url='https://staging.example').returncode, 0)
        self.assertNotEqual(self.preview(site_url='https://staging.example', header='').returncode, 0)

    def test_audit_missing_and_malformed_reports_fail(self):
        body = script(WEB, 'Block on CRITICAL')
        self.assertNotEqual(self.run_shell(body).returncode, 0)
        self.assertNotEqual(self.run_shell(body, files={'osv.json': '{broken'}).returncode, 0)

    def test_audit_threshold(self):
        for score, expected in [('8.9', 0), ('9.0', 1), ('9.8', 1)]:
            report = {'results': [{'packages': [{'groups': [{'max_severity': score}]}]}]}
            result = self.run_shell(script(WEB, 'Block on CRITICAL'), files={'osv.json': json.dumps(report)})
            self.assertEqual(result.returncode, expected, result.stderr)
        self.assertEqual(self.run_shell(script(WEB, 'Block on CRITICAL'), files={'osv.json': '{"results":[]}'}).returncode, 0)

    def test_required_job_fails_on_audit_failure_or_skip(self):
        body = script(WEB, 'Require successful prerequisites')
        for fast, audit in [('success', 'failure'), ('success', 'skipped'), ('cancelled', 'success')]:
            self.assertNotEqual(self.run_shell(body, {'FAST_RESULT': fast, 'AUDIT_RESULT': audit}).returncode, 0)
        self.assertEqual(self.run_shell(body, {'FAST_RESULT': 'success', 'AUDIT_RESULT': 'success'}).returncode, 0)

    def smoke(self, output, status='200', body='Sign in'):
        return self.run_shell(script(DEPLOY, 'Smoke the version preview'), {
            'SMOKE_PATH': '/sign-in', 'SMOKE_MARKER': 'Sign in',
            'CF_ACCESS_CLIENT_ID': '', 'CF_ACCESS_CLIENT_SECRET': '',
            'MOCK_STATUS': status, 'MOCK_BODY': body, 'MOCK_HEADERS': '',
        }, {'opennext-upload.log': output}, CURL)

    def test_smoke_selects_uploaded_version_not_helper_url(self):
        output = 'https://helper.example.workers.dev\nVersion ID: ' + VERSION + '\nhttps://12345678-portal.example.workers.dev\n'
        result = self.smoke(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('version-id=' + VERSION, result.outputs)
        for changed in [output.replace('12345678-portal', '87654321-portal'), 'https://helper.example.workers.dev']:
            self.assertNotEqual(self.smoke(changed).returncode, 0)
        self.assertNotEqual(self.smoke(output, status='500').returncode, 0)
        self.assertNotEqual(self.smoke(output, body='wrong page').returncode, 0)

    def test_failed_opennext_upload_stops_pipeline(self):
        result = self.run_shell(script(DEPLOY, 'Upload the version'), {'GITHUB_REF_NAME': 'v-test'}, prefix='npx() { return 1; }')
        self.assertNotEqual(result.returncode, 0)

    def test_production_authority_is_absent_from_pr_contract(self):
        self.assertNotIn('CLOUDFLARE_API_TOKEN', WEB.read_text())
        self.assertNotIn('CLOUDFLARE_ACCOUNT_ID', WEB.read_text())
        self.assertIn('needs: [fast, audit]\n    if: always()', WEB.read_text())


class Eligibility(unittest.TestCase):
    def fixture(self):
        run = {'id': 10, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
               'status': 'completed', 'conclusion': 'success'}
        jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success'}
                for name in ['ci / fast', 'ci / audit', 'ci / preview-gates']]
        return [{'status': 'ahead', 'merge_base_commit': {'sha': SHA}}, {'workflow_runs': [run]}, {'jobs': jobs}]

    def verify(self, fixture, ref='refs/tags/v-test'):
        responses = iter(copy.deepcopy(fixture))
        return release.verify_release('example/repo', SHA, ref, 'push', lambda path: next(responses))

    def test_main_accepted_commit_passes(self):
        self.assertEqual(self.verify(self.fixture()), 10)

    def test_non_main_and_non_tag_fail(self):
        fixture = self.fixture()
        fixture[0]['status'] = 'diverged'
        with self.assertRaises(ValueError): self.verify(fixture)
        with self.assertRaises(ValueError): self.verify(self.fixture(), 'refs/heads/main')

    def test_wrong_sha_or_pr_only_run_fails(self):
        for key, value in [('head_sha', 'b' * 40), ('event', 'pull_request')]:
            fixture = self.fixture()
            fixture[1]['workflow_runs'][0][key] = value
            with self.assertRaises(ValueError): self.verify(fixture)

    def test_newer_failed_run_does_not_reuse_old_success(self):
        fixture = self.fixture()
        latest = dict(fixture[1]['workflow_runs'][0], id=11, conclusion='failure')
        fixture[1]['workflow_runs'].append(latest)
        with self.assertRaises(ValueError): self.verify(fixture)

    def test_missing_skipped_or_failed_required_jobs_fail(self):
        fixture = self.fixture()
        fixture[2]['jobs'].pop()
        with self.assertRaises(ValueError): self.verify(fixture)
        for conclusion in ['skipped', 'failure', 'neutral']:
            fixture = self.fixture()
            fixture[2]['jobs'][1]['conclusion'] = conclusion
            with self.assertRaises(ValueError): self.verify(fixture)


if __name__ == '__main__':
    unittest.main()
