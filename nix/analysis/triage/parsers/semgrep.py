"""Parse semgrep JSON reports."""

import json

from finding import Finding, normalize_path, normalize_severity


def rule_id(check_id: str) -> str:
    """semgrep prefixes a rule id with its config file's dotted path
    (nix.store.strtok-result-unchecked for a rules file in the store).
    Rule ids use dashes, never dots, so the id is the last component."""
    return check_id.rsplit('.', 1)[-1]


def parse(path: str) -> list:
    """Parse semgrep JSON report (may contain multiple JSON objects)."""
    findings = []
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        return findings

    # Parse all JSON objects in the file (semgrep may output multiple)
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(content):
        try:
            idx = content.index('{', pos)
            data, end = decoder.raw_decode(content, idx)
            pos = end
        except (ValueError, json.JSONDecodeError):
            break

        for result in data.get('results', []):
            findings.append(Finding(
                tool='semgrep',
                check_id=rule_id(result.get('check_id', '')),
                severity=normalize_severity(result.get('extra', {}).get('severity', 'warning')),
                file=normalize_path(result.get('path', '')),
                line=result.get('start', {}).get('line', 0),
                message=result.get('extra', {}).get('message', ''),
            ))

    return findings
