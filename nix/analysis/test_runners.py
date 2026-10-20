"""Table-driven tests for the analysis report plumbing.

test_scan_report    feeds semgrep-report.jq made-up semgrep output and
                    checks that it fails on anything but a complete,
                    well-formed scan (adapted from rocm-ernic).
test_normalize_path store prefixes and automake's src/../lib/ paths.
test_clang_parser   clang/gcc diagnostic lines -> findings.
test_flawfinder     flawfinder --singleline lines -> findings.
test_cppcheck       cppcheck XML -> findings.
test_semgrep_rule_id the rule id without semgrep's config-path prefix.
test_filters        which findings triage keeps (scope, vendored,
                    generated, excluded checks).
test_deduplicate    one finding per (file, line, check).

Each row carries a description and the expected result. The
analysis-runners flake check runs this file; it also runs outside Nix
given python3 and jq.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "triage"))

from finding import Finding, normalize_path  # noqa: E402
from filters import deduplicate, filter_findings  # noqa: E402
from parsers import clang, cppcheck, flawfinder, semgrep  # noqa: E402

STORE = "/nix/store/" + "a" * 32 + "-mcd-analysis-compile-db-3.0"


def finding(file="src/igmp.c", line=10, check="core.NullDereference", tool="clang-tidy"):
    return Finding(tool=tool, check_id=check, severity="warning", file=file, line=line, message="m")


def parse_text(parse, text, *args):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
    try:
        return parse(f.name, *args)
    finally:
        Path(f.name).unlink()


class RunnerTests(unittest.TestCase):
    def test_scan_report(self):
        """Empty and failed scans must not masquerade as zero findings."""
        valid = {"results": [], "errors": [], "paths": {"scanned": ["src/a.c"]}}
        # (category, description, semgrep's output, expected finding count,
        # or None if semgrep-report.jq must fail)
        cases = [
            ("positive", "valid empty scan", json.dumps(valid), "0"),
            (
                "corner",
                "known partial parsing warning",
                json.dumps(dict(valid, errors=[{"level": "warn", "type": ["PartialParsing", []]}])),
                "0",
            ),
            (
                "negative",
                "unknown warning",
                json.dumps(dict(valid, errors=[{"level": "warn", "type": ["Unknown", []]}])),
                None,
            ),
            ("positive", "one finding", json.dumps(dict(valid, results=[{"check_id": "rule"}])), "1"),
            ("negative", "engine error", json.dumps(dict(valid, errors=[{"type": "Fatal error"}])), None),
            ("negative", "malformed JSON", "{", None),
            ("boundary", "empty output", "", None),
            ("negative", "missing results", "{}", None),
            ("corner", "nothing scanned", json.dumps(dict(valid, paths={"scanned": []})), None),
            ("corner", "two documents", json.dumps(valid) + json.dumps(valid), None),
            (
                "negative",
                "finding without a check id",
                json.dumps(dict(valid, results=[{"check_id": 7}])),
                None,
            ),
        ]
        for category, description, source, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                result = subprocess.run(
                    ["jq", "-esr", "-f", str(HERE / "semgrep-report.jq")],
                    input=source,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)

    def test_normalize_path(self):
        cases = [
            ("positive", "store prefix stripped", f"{STORE}/src/igmp.c", "src/igmp.c"),
            ("positive", "automake lib/ replacement", f"{STORE}/src/../lib/pidfile.c", "lib/pidfile.c"),
            ("boundary", "already relative", "src/mld.c", "src/mld.c"),
            ("corner", "double slash collapsed", f"{STORE}/src//ipc.c", "src/ipc.c"),
            ("negative", "non-store absolute path kept", "/usr/include/stdio.h", "/usr/include/stdio.h"),
        ]
        for category, description, path, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                self.assertEqual(normalize_path(path), expected)

    def test_clang_parser(self):
        # (category, description, line, expected (file, line, check) or None)
        cases = [
            (
                "positive",
                "clang-tidy warning",
                f"{STORE}/src/bridge.c:115:17: warning: Null pointer passed [clang-analyzer-core.NonNullParamChecker]",
                ("src/bridge.c", 115, "clang-analyzer-core.NonNullParamChecker"),
            ),
            (
                "positive",
                "gcc warning with -W option",
                "src/bridge.c:90:13: warning: variable 'num' set but not used [-Wunused-but-set-variable=]",
                ("src/bridge.c", 90, "-Wunused-but-set-variable="),
            ),
            (
                "positive",
                "error severity",
                "src/igmp.c:1:2: error: something broke [some-check]",
                ("src/igmp.c", 1, "some-check"),
            ),
            ("negative", "note line ignored", "src/igmp.c:3:4: note: expanded from macro [x]", None),
            ("negative", "no check id in brackets", "src/igmp.c:3:4: warning: plain message", None),
            ("boundary", "empty line", "", None),
        ]
        for category, description, line, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                got = parse_text(clang.parse, line + "\n", "clang-tidy")
                if expected is None:
                    self.assertEqual(got, [])
                else:
                    self.assertEqual(len(got), 1)
                    self.assertEqual((got[0].file, got[0].line, got[0].check_id), expected)

    def test_flawfinder(self):
        cases = [
            (
                "positive",
                "single-line hit",
                f"{STORE}/src/ipc.c:98:7:  [4] (shell) popen:This causes a new program to execute",
                ("src/ipc.c", 98, "shell.popen", "error"),
            ),
            (
                "boundary",
                "lowest level",
                "src/log.c:12:3:  [1] (buffer) strlen:Does not handle strings that are not terminated",
                ("src/log.c", 12, "buffer.strlen", "style"),
            ),
            ("negative", "summary line ignored", "Hits = 42", None),
        ]
        for category, description, line, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                got = parse_text(flawfinder.parse, line + "\n")
                if expected is None:
                    self.assertEqual(got, [])
                else:
                    self.assertEqual(len(got), 1)
                    f = got[0]
                    self.assertEqual((f.file, f.line, f.check_id, f.severity), expected)

    def test_cppcheck(self):
        def doc(errors):
            return f'<?xml version="1.0"?><results version="2"><errors>{errors}</errors></results>'

        cases = [
            (
                "positive",
                "one error with location",
                doc(
                    '<error id="nullPointer" severity="error" msg="Null pointer">'
                    f'<location file="{STORE}/src/bridge.c" line="115"/></error>'
                ),
                [("src/bridge.c", 115, "nullPointer", "error")],
            ),
            (
                "corner",
                "only the first location is used",
                doc(
                    '<error id="uninitvar" severity="warning" msg="u">'
                    '<location file="src/a.c" line="5"/><location file="src/b.c" line="9"/></error>'
                ),
                [("src/a.c", 5, "uninitvar", "warning")],
            ),
            (
                "negative",
                "error without a location dropped",
                doc('<error id="toomanyconfigs" severity="information" msg="x"/>'),
                [],
            ),
            ("negative", "malformed XML yields nothing", "<results><errors>", []),
            ("boundary", "no errors", doc(""), []),
        ]
        for category, description, xml, expected in cases:
            with self.subTest(category=category, description=description):
                got = parse_text(cppcheck.parse, xml)
                self.assertEqual([(f.file, f.line, f.check_id, f.severity) for f in got], expected)

    def test_semgrep_rule_id(self):
        cases = [
            ("positive", "store config prefix stripped", "nix.store.strtok-result-unchecked", "strtok-result-unchecked"),
            ("positive", "relative config prefix stripped", "nix.analysis.goto-usage", "goto-usage"),
            ("boundary", "bare id unchanged", "goto-usage", "goto-usage"),
            ("corner", "empty id", "", ""),
        ]
        for category, description, check_id, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                self.assertEqual(semgrep.rule_id(check_id), expected)

    def test_filters(self):
        cases = [
            ("positive", "src/ finding kept", finding(), True),
            ("positive", "lib/ finding kept", finding(file="lib/strtonum.c"), True),
            ("negative", "vendored jsmn.h dropped", finding(file="src/jsmn.h"), False),
            ("negative", "vendored queue.h dropped", finding(file="src/queue.h"), False),
            ("negative", "generated cfparse.c dropped", finding(file="_build/src/cfparse.c"), False),
            ("negative", "system header out of scope", finding(file="/usr/include/x.h"), False),
            ("negative", "excluded check id", finding(check="missingIncludeSystem"), False),
            ("boundary", "line 0 dropped", finding(line=0), False),
            ("boundary", "line 1 kept", finding(line=1), True),
            ("corner", "cfparse.y (grammar source) kept", finding(file="src/cfparse.y"), True),
        ]
        for category, description, f, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                self.assertEqual(filter_findings([f]) == [f], expected)

    def test_deduplicate(self):
        a = finding()
        cases = [
            ("positive", "exact duplicate collapsed", [a, finding()], 1),
            ("negative", "different line kept", [a, finding(line=11)], 2),
            ("negative", "different check kept", [a, finding(check="other")], 2),
            ("corner", "same site, different tool collapsed", [a, finding(tool="cppcheck")], 1),
            ("boundary", "empty input", [], 0),
        ]
        for category, description, findings, expected in cases:
            with self.subTest(category=category, description=description, expected=expected):
                self.assertEqual(len(deduplicate(findings)), expected)


if __name__ == "__main__":
    unittest.main()
