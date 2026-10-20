"""Noise constants, path classifiers, filtering, and deduplication.

Adapted for mcd's C codebase. Path patterns reflect this repo's layout:
  - src/igmp.c, src/mld.c, src/iface.c   IGMP/MLD packet parsing and the
                                          querier state machine — untrusted
                                          network input
  - src/sock.c                            raw AF_PACKET receive path
  - src/cfparse.y                         mcd.conf grammar and lexer
  - src/ipc.c, src/mctl.c                 UNIX-socket IPC protocol
  - src/bridge.c                          parses `bridge`/`ip`/jq output
  - src/jsmn.h, src/queue.h               vendored (jsmn, BSD queue.h)
  - lib/                                  libc replacement functions
  - _build/src/cfparse.c                  bison output (generated)
"""

from finding import Finding


# Vendored headers: findings there are upstream's, not mcd's.
THIRD_PARTY_PATTERNS = ['src/jsmn.h', 'src/queue.h']

# Trees whose findings are in scope for triage.
ANALYSIS_ROOTS = ('src/', 'lib/')

# Generated files. Diagnostics in bison's own skeleton code are not
# actionable; the user actions in cfparse.y map back via #line directives.
GENERATED_FILE_PATTERNS = ['cfparse.c']

EXCLUDED_CHECK_IDS = {
    # Cppcheck noise — tool limitations, not code bugs
    'missingIncludeSystem',
    'missingInclude',
    'unmatchedSuppression',
    'checkersReport',
    'syntaxError',                  # Can't parse complex macro constructs
    'preprocessorErrorDirective',   # Intentional #error guards / macro failures
    'unknownMacro',                 # Doesn't understand queue.h style macros
    # Cppcheck false positives in idiomatic C
    'arithOperationsOnVoidPointer', # GNU C extension, intentional in networking code
    'subtractPointers',             # container_of style pointer arithmetic
    # Clang-tidy build errors (not real findings)
    'clang-diagnostic-error',
    # _FORTIFY_SOURCE warnings (build config, not code bugs)
    '-W#warnings',
    '-Wcpp',
}

EXCLUDED_MESSAGE_PATTERNS = [
    '_FORTIFY_SOURCE',
]

# mcd keeps its tests as shell scripts under test/; nothing C is test code
# today, but keep the hook for future C test helpers.
TEST_PATH_PATTERNS = ['test/', '/test_']

# Security-sensitive locations: code that parses untrusted input (packets
# off the wire, the IPC socket, external command output, the config file).
SECURITY_PATHS = [
    'src/igmp.',
    'src/mld.',
    'src/iface.',
    'src/sock.',
    'src/inet.',
    'src/ipc.',
    'src/bridge.',
    'src/cfparse.y',
    'src/mctl.c',
]


def _match_generated(path: str) -> bool:
    """Check if file matches a generated file pattern (supports * glob)."""
    import fnmatch
    name = path.rsplit('/', 1)[-1] if '/' in path else path
    return any(fnmatch.fnmatch(name, pat) for pat in GENERATED_FILE_PATTERNS)


def is_generated(path: str) -> bool:
    return _match_generated(path)


def is_third_party(path: str) -> bool:
    for pat in THIRD_PARTY_PATTERNS:
        if pat in path:
            return True
    # Files outside ANALYSIS_ROOTS are out of scope (tests, build).
    return not path.startswith(ANALYSIS_ROOTS)


def is_test_code(path: str) -> bool:
    return any(pat in path for pat in TEST_PATH_PATTERNS)


def is_security_sensitive(path: str) -> bool:
    return any(pat in path for pat in SECURITY_PATHS)


def filter_findings(findings: list) -> list:
    """Remove out-of-scope code and known false positive categories."""
    return [
        f for f in findings
        if not is_third_party(f.file)
        and not is_generated(f.file)
        and f.check_id not in EXCLUDED_CHECK_IDS
        and f.line > 0
        and not any(pat in f.message for pat in EXCLUDED_MESSAGE_PATTERNS)
    ]


def deduplicate(findings: list) -> list:
    """Deduplicate findings by (file, line, check_id).

    clang-tidy reports the same header finding once per translation unit.
    Keep first occurrence only.
    """
    seen = set()
    result = []
    for f in findings:
        key = f.dedup_key()
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
