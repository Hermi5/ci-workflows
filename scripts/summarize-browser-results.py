"""Publish selected Playwright metadata, never error bodies or captured output."""
import json
from pathlib import Path
import sys


def error_messages(entries):
    for entry in entries:
        for error in [entry.get('error'), *entry.get('errors', [])]:
            if isinstance(error, dict):
                message = str(error.get('message', ''))
                yield message.splitlines()[0] if message else ''
        yield from error_messages(entry.get('steps', []))


def classification(test):
    details = '\n'.join(error_messages(test.get('results', []))).lower()
    if 'required totp coverage needs' in details or 'e2e_email and e2e_password are not set' in details:
        return 'missing fixture'
    if 'err_aborted' in details:
        return 'navigation aborted'
    if 'timeout' in details or 'timedout' in details or 'timed out' in details:
        return 'timeout'
    if 'expect(' in details or 'assertion' in details:
        return 'assertion'
    return 'runner error'


def specs(suites):
    if not isinstance(suites, list):
        raise ValueError('invalid suites')
    for suite in suites:
        yield from suite.get('specs', [])
        yield from specs(suite.get('suites', []))


def summarize(path):
    try:
        report = json.loads(Path(path).read_text())
        counts = {name: report['stats'][name] for name in ['expected', 'unexpected', 'flaky', 'skipped']}
        if any(type(count) is not int or count < 0 for count in counts.values()):
            raise ValueError('invalid counts')
        errors = report.get('errors', [])
        if not isinstance(errors, list):
            raise ValueError('invalid errors')
        failures = []
        for spec in specs(report['suites']):
            for test in spec.get('tests', []):
                if test.get('status') != 'unexpected':
                    continue
                title, file, line = spec['title'], spec['file'], spec['line']
                if not isinstance(title, str) or not isinstance(file, str) or type(line) is not int:
                    raise ValueError('invalid test metadata')
                failures.append(f'FAIL {json.dumps(file)}:{line} | {json.dumps(title)} | {classification(test)}')
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('Browser tests: runner error (missing or malformed JSON report)')
        return 1

    print(f"Browser tests: passed={counts['expected']} failed={counts['unexpected']} flaky={counts['flaky']} skipped={counts['skipped']}")
    for failure in failures:
        print(failure)
    if errors:
        print('Browser tests: runner error')
    return int(bool(counts['unexpected'] or failures or errors))


if __name__ == '__main__':
    sys.exit(summarize(sys.argv[1]) if len(sys.argv) == 2 else 1)
