"""Run every NetWatch AI quality gate in one command (M18.13).

M18's goal is that the whole project can be verified by one documented,
repeatable workflow rather than a dozen remembered commands. This script is that
workflow. It does **not** reimplement any check: every gate is one of the
project's existing commands, run as a child process from the directory the
command expects. The script's only job is to select the gates, run them in a
fixed order, report each one's real result, and exit non-zero if anything did
not pass.

Gates
-----

``backend-tests``
    ``python -m pytest`` — the complete backend unit and integration suite
    (milestone items 1, 2, 4). Uses the suite's own fixtures, which build
    throwaway databases; it never touches ``backend/netwatch.db``.

``backend-types``
    ``python -m pyright`` — static checking of ``backend/app`` and
    ``backend/tests`` (milestone item 8).

``security``
    ``python -m pytest tests/test_security_regression.py`` — the M18.11
    defensive suite (milestone item 12), run alone so its result is visible
    rather than buried in the full-suite summary. It also runs inside
    ``backend-tests``; that duplication is deliberate and is the only one here.

``frontend-unit``
    ``npm test`` — the Vitest suite (milestone item 5).

``frontend-types``
    ``npm run typecheck`` — ``tsc --noEmit`` (milestone item 9).

``frontend-build``
    ``npm run build`` — the Vite production build (milestone item 10).

``e2e``
    ``python scripts/verify_m18.py sample`` — the M18.9 end-to-end flow: real
    packets through capture, processing, persistence, discovery, detection,
    alerting, correlation, the API, analytics and report generation
    (milestone item 7).

``e2e-live``
    ``python scripts/verify_m18.py live`` — the same flow against a real uvicorn
    server, a real WebSocket client and real report downloads (milestone item
    6).

``performance``
    ``python scripts/benchmark_m18.py`` — the M18.10 regression harness
    (milestone item 11).

Prerequisites
-------------

Each gate declares what it needs. When something is missing the gate is
reported as ``SKIPPED`` with the reason and is **never** counted as a pass.

``backend-tests``, ``backend-types``, ``security``, ``e2e``, ``e2e-live``,
``performance``
    The backend virtual environment at ``backend/.venv`` (any Python 3.12+
    interpreter with ``backend/requirements.txt`` installed works; the script
    prefers the venv when it exists, otherwise it falls back to the interpreter
    running this file). ``e2e-live`` also needs a loopback TCP port it can
    bind, which it picks itself.

``frontend-unit``, ``frontend-types``, ``frontend-build``
    ``frontend/node_modules`` — run ``npm ci`` in ``frontend/`` first. These
    gates also need ``npm`` on ``PATH``.

``e2e`` and ``performance``
    Require ``scripts/verify_m18.py`` and ``scripts/benchmark_m18.py`` to
    exist. Until they do the gate reports ``SKIPPED``, which fails a run that
    selected it — a missing script is not a passing check.

No gate needs administrator rights, a network connection, an elevated capture
socket, an API key or a paid service. No gate writes to the developer's real
``backend/netwatch.db``, and the ones that start a server pick a free loopback
port and shut the server down again.

Selection
---------

The default run is the fast gate: ``backend-tests``, ``backend-types``,
``security``, ``frontend-unit``, ``frontend-types`` and ``frontend-build``.
``--full`` adds the three long-running gates (``e2e``, ``e2e-live``,
``performance``). ``--only`` and ``--skip`` take comma-separated gate names and
override the defaults, so a single gate can be re-run while working on it.
``--list`` prints the gates and their prerequisites without running anything.

Honesty rules
-------------

* A gate passes only when its process exits with status 0. The exit code is
  authoritative; the summary line is quoted for the reader, not trusted.
* A gate in the selection that collects no tests is a failure. "Ran nothing"
  and "passed" are not the same result, so a suite that reports no tests
  fails the gate with that reason attached.
* Skipped tests are never hidden. The count is printed next to the gate, and
  the runner ends with a warning naming every gate that skipped something, so
  a skip cannot be mistaken for coverage.
* A gate whose prerequisites are missing is reported as ``SKIPPED`` and makes
  the run fail. It is never silently dropped.
* The failure output of a failing gate is printed in full (its tail, bounded by
  ``--tail-lines``) so the reason is in front of the reader without opening a
  log file.

Usage
-----

.. code-block:: text

    python backend/scripts/run_quality_gates.py                 # fast gate
    python backend/scripts/run_quality_gates.py --full          # + e2e/perf
    python backend/scripts/run_quality_gates.py --list
    python backend/scripts/run_quality_gates.py --only security
    python backend/scripts/run_quality_gates.py --skip frontend-build
    python backend/scripts/run_quality_gates.py --full -v       # stream output

The process exits 0 only when every selected gate ran and passed. It exits 1
when any selected gate failed, was skipped for a missing prerequisite, or
collected no tests.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent
FRONTEND_ROOT = PROJECT_ROOT / "frontend"

#: Width of the banner and rule lines the report is drawn with.
BANNER_WIDTH = 78

#: Lines of captured output shown for a gate that failed.
DEFAULT_TAIL_LINES = 40


def resolve_python() -> str:
    """Return the interpreter the backend gates run under (M18.13).

    The project keeps its dependencies in ``backend/.venv``. When that
    environment exists it is used directly, because it is the one the project's
    own documentation and scripts assume; otherwise the interpreter running this
    file is used, which is correct when someone has installed the requirements
    into a different environment.
    """
    candidates = (
        BACKEND_ROOT / ".venv" / "Scripts" / "python.exe",  # Windows
        BACKEND_ROOT / ".venv" / "bin" / "python",  # POSIX
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def resolve_npm() -> str:
    """Return the npm entry point for this platform (M18.13).

    On Windows npm is a batch shim, and ``subprocess`` can only launch it by its
    full name; ``shutil.which`` finds the right one on either platform.
    """
    return shutil.which("npm.cmd") or shutil.which("npm") or "npm"


@dataclass(frozen=True)
class Stage:
    """One quality gate: an existing command plus what it needs to be run (M18.13).

    A stage carries no knowledge of how to check anything. It names a command,
    the directory the command expects, and the patterns that pick the summary
    line out of that command's output so the report can quote the real numbers
    instead of paraphrasing them.
    """

    key: str
    title: str
    #: The milestone item of the M18.13 list this gate closes, for the report.
    closes: str
    #: The command, as an argument vector. Never a shell string.
    command: tuple[str, ...]
    #: The directory the command must run from.
    cwd: Path
    #: Summary patterns, tried in order; the first match in the output wins.
    summaries: tuple[re.Pattern[str], ...] = ()
    #: Paths that must exist for the gate to be meaningful.
    requires: tuple[Path, ...] = ()
    #: True when the command's success is legitimately silent.
    silent_on_success: bool = False
    #: True when the gate is expected to run tests, so no tests is a failure.
    collects_tests: bool = False

    def missing_requirements(self) -> tuple[Path, ...]:
        """Return the prerequisites that are absent (M18.13)."""
        return tuple(path for path in self.requires if not path.exists())


# -- the summary lines each gate's output is read for -------------------------

#: pytest -q ends with e.g. "2329 passed, 3 skipped, 2 warnings in 142.31s".
_PYTEST_SUMMARY = re.compile(
    r"^\d+ (?:passed|failed|error|errors|skipped|xfailed|xpassed)[^\n]* in [\d.]+s\s*$",
    re.MULTILINE,
)

#: pytest says this instead of a summary when it collected nothing.
_NO_TESTS = re.compile(r"^no tests ran in [\d.]+s\s*$", re.MULTILINE)

#: pyright ends with e.g. "0 errors, 0 warnings, 0 informations".
_PYRIGHT_SUMMARY = re.compile(
    r"^\d+ errors?, \d+ warnings?, \d+ informations?\s*$",
    re.MULTILINE,
)

#: vitest prints e.g. "Tests  13 passed (13)" or "Tests  1 failed | 12 passed (13)".
_VITEST_SUMMARY = re.compile(r"^\s*Tests\s+\S.*$", re.MULTILINE)

#: vitest prints this when the glob matched no file at all.
_NO_TEST_FILES = re.compile(r"No test files found", re.IGNORECASE)

#: vite ends with e.g. "built in 3.45s" or "built in 1.20m".
_VITE_BUILD_SUMMARY = re.compile(r"^.*built in [\d.]+m?s\s*$", re.MULTILINE)

#: Used to decide whether a test gate actually ran something.
_PASSED_COUNT = re.compile(r"[1-9]\d* passed")

#: Used to surface skipped tests, which must never look like coverage.
_SKIPPED_COUNT = re.compile(r"(\d+) skipped")

PASSED = "PASS"
FAILED = "FAIL"
SKIPPED = "SKIP"

#: Gates run by default: fast enough to run on every change.
DEFAULT_KEYS = (
    "backend-tests",
    "backend-types",
    "security",
    "frontend-unit",
    "frontend-types",
    "frontend-build",
)

#: Gates added by --full: they start servers and take minutes, not seconds.
LONG_KEYS = ("e2e", "e2e-live", "performance")

#: Directories the frontend gates cannot run without.
_FRONTEND_REQUIREMENTS = (FRONTEND_ROOT / "node_modules",)


def build_stages() -> tuple[Stage, ...]:
    """Return every gate, in the order the report presents them (M18.13).

    The command vectors are built here rather than at module import so that the
    interpreter and npm shim are resolved from the filesystem when the gates are
    actually going to run. Each command is exactly the one the project's own
    documentation gives for that check, with flags added only to keep the
    working tree clean (``-p no:cacheprovider`` stops pytest writing a cache
    directory) or to keep the output parseable (``-q``).
    """
    python = resolve_python()
    npm = resolve_npm()

    return (
        Stage(
            key="backend-tests",
            title="Backend unit and integration suite",
            closes="M18.13 items 1, 2 and 4",
            command=(python, "-m", "pytest", "-q", "-p", "no:cacheprovider"),
            cwd=BACKEND_ROOT,
            summaries=(_PYTEST_SUMMARY,),
            collects_tests=True,
        ),
        Stage(
            key="backend-types",
            title="Backend static type checking",
            closes="M18.13 item 8",
            command=(python, "-m", "pyright"),
            cwd=BACKEND_ROOT,
            summaries=(_PYRIGHT_SUMMARY,),
        ),
        Stage(
            key="security",
            title="Security regression suite",
            closes="M18.13 item 12",
            command=(
                python,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/test_security_regression.py",
            ),
            cwd=BACKEND_ROOT,
            summaries=(_PYTEST_SUMMARY,),
            collects_tests=True,
        ),
        Stage(
            key="frontend-unit",
            title="Frontend unit suite",
            closes="M18.13 item 5",
            command=(npm, "test"),
            cwd=FRONTEND_ROOT,
            summaries=(_VITEST_SUMMARY,),
            requires=_FRONTEND_REQUIREMENTS,
            collects_tests=True,
        ),
        Stage(
            key="frontend-types",
            title="Frontend TypeScript checking",
            closes="M18.13 item 9",
            command=(npm, "run", "typecheck"),
            cwd=FRONTEND_ROOT,
            requires=_FRONTEND_REQUIREMENTS,
            silent_on_success=True,
        ),
        Stage(
            key="frontend-build",
            title="Frontend production build",
            closes="M18.13 item 10",
            command=(npm, "run", "build"),
            cwd=FRONTEND_ROOT,
            summaries=(_VITE_BUILD_SUMMARY,),
            requires=_FRONTEND_REQUIREMENTS,
        ),
        Stage(
            key="e2e",
            title="End-to-end data flow",
            closes="M18.13 item 7",
            command=(python, "scripts/verify_m18.py", "sample"),
            cwd=BACKEND_ROOT,
            summaries=(_PYTEST_SUMMARY,),
            requires=(BACKEND_ROOT / "scripts" / "verify_m18.py",),
        ),
        Stage(
            key="e2e-live",
            title="Live API, WebSocket and download flow",
            closes="M18.13 item 6",
            command=(python, "scripts/verify_m18.py", "live"),
            cwd=BACKEND_ROOT,
            summaries=(_PYTEST_SUMMARY,),
            requires=(BACKEND_ROOT / "scripts" / "verify_m18.py",),
        ),
        Stage(
            key="performance",
            title="Performance regression harness",
            closes="M18.13 item 11",
            command=(python, "scripts/benchmark_m18.py"),
            cwd=BACKEND_ROOT,
            requires=(BACKEND_ROOT / "scripts" / "benchmark_m18.py",),
        ),
    )


@dataclass(frozen=True)
class StageResult:
    """What actually happened when a gate ran (M18.13)."""

    stage: Stage
    status: str
    duration: float = 0.0
    #: The gate's own summary line, quoted verbatim.
    summary: str = ""
    #: Why the gate did not pass: a missing file, no tests, and so on.
    reason: str = ""
    #: The captured output, kept for the failure tail.
    output: str = ""
    #: Tests the gate itself reported as skipped.
    skipped_tests: int = 0

    @property
    def ok(self) -> bool:
        """True only for a gate that ran and exited successfully (M18.13)."""
        return self.status == PASSED


# -- reading a gate's own result ----------------------------------------------


def _relative(path: Path) -> str:
    """Return a path relative to the project root, for readable messages (M18.13)."""
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def _quoted(argument: str) -> str:
    """Quote one argument, so a path with a space is still copy-pasteable (M18.13).

    The project lives under a path containing a space on the reference machine,
    so an unquoted interpreter path would produce a command that cannot be run.
    """
    return f'"{argument}"' if " " in argument else argument


def _reproduction(stage: Stage) -> str:
    """Return the exact command that re-runs one gate by hand (M18.13)."""
    command = " ".join(_quoted(argument) for argument in stage.command)
    return f"cd {_relative(stage.cwd)} && {command}"


def _join_streams(stdout: str, stderr: str) -> str:
    """Join a process's two output streams on a line boundary (M18.13).

    Concatenating them directly would glue the last stdout line to the first
    stderr line, corrupting both the summary search and the failure tail.
    """
    parts = []
    for stream in (stdout, stderr):
        if stream:
            parts.append(stream if stream.endswith("\n") else stream + "\n")
    return "".join(parts)


def _extract_summary(output: str, patterns: Sequence[re.Pattern[str]]) -> str:
    """Return the last line matching any summary pattern, or empty (M18.13).

    The last match is taken because a command can echo a summary-looking line
    earlier in its output — a test that reports another suite's total, say —
    while the real summary is the final one.
    """
    found = ""
    for pattern in patterns:
        last = None
        for match in pattern.finditer(output):
            last = match
        if last is not None:
            text = last.group(0).strip()
            if text:
                found = text
    return found


def _no_tests_reason(stage: Stage, output: str) -> str:
    """Explain why a test gate that ran nothing is not a pass (M18.13)."""
    if not stage.collects_tests:
        return ""
    if _NO_TESTS.search(output):
        return "the runner collected no tests"
    if _NO_TEST_FILES.search(output):
        return "the runner found no test files"
    if not _PASSED_COUNT.search(output):
        return "no passing tests were reported"
    return ""


def _count_skips(output: str) -> int:
    """Return how many tests the gate itself reported as skipped (M18.13)."""
    return sum(int(count) for count in _SKIPPED_COUNT.findall(output))


def _tail(text: str, lines: int) -> str:
    """Return the last ``lines`` lines of some output (M18.13)."""
    if lines <= 0:
        return ""
    stripped = text.rstrip("\n")
    if not stripped:
        return ""
    return "\n".join(stripped.splitlines()[-lines:])


# -- running a gate -----------------------------------------------------------


def _run_stage(stage: Stage) -> StageResult:
    """Run one gate and describe exactly what happened (M18.13).

    Three things make a gate pass: it could be started, its process exited with
    status 0, and — when it is a suite — it really did run tests. Anything else
    is reported as a failure or a skip with the reason attached.
    """
    missing = stage.missing_requirements()
    if missing:
        return StageResult(
            stage=stage,
            status=SKIPPED,
            reason="missing prerequisite: "
            + ", ".join(_relative(path) for path in missing),
        )

    if shutil.which(stage.command[0]) is None:
        return StageResult(
            stage=stage,
            status=SKIPPED,
            reason=f"{stage.command[0]!r} was not found on PATH",
        )

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            stage.command,
            cwd=stage.cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        return StageResult(
            stage=stage,
            status=FAILED,
            duration=time.perf_counter() - started,
            reason=f"the command could not be started: {error}",
        )

    duration = time.perf_counter() - started
    output = _join_streams(completed.stdout, completed.stderr)
    summary = _extract_summary(output, stage.summaries)
    skipped_tests = _count_skips(output)

    if completed.returncode != 0:
        return StageResult(
            stage=stage,
            status=FAILED,
            duration=duration,
            summary=summary,
            reason=f"exit status {completed.returncode}",
            output=output,
            skipped_tests=skipped_tests,
        )

    no_tests = _no_tests_reason(stage, output)
    if no_tests:
        return StageResult(
            stage=stage,
            status=FAILED,
            duration=duration,
            summary=summary,
            reason=no_tests,
            output=output,
            skipped_tests=skipped_tests,
        )

    return StageResult(
        stage=stage,
        status=PASSED,
        duration=duration,
        summary=summary,
        output=output,
        skipped_tests=skipped_tests,
    )


# -- reporting ----------------------------------------------------------------


def _print_table(results: Sequence[StageResult]) -> None:
    """Print the one-line-per-gate summary (M18.13)."""
    key_width = max((len(result.stage.key) for result in results), default=4)
    print()
    print("=" * BANNER_WIDTH)
    print(f"NetWatch AI quality gates — {len(results)} selected")
    print("=" * BANNER_WIDTH)
    print(f"{'gate'.ljust(key_width)}  {'result':<6}  {'time':>8}  summary")
    print(f"{'-' * key_width}  {'-' * 6}  {'-' * 8}  {'-' * 44}")
    for result in results:
        timing = f"{result.duration:8.2f}s"
        detail = result.summary or result.reason
        if not detail:
            detail = (
                "(silent on success)"
                if result.stage.silent_on_success
                else "(no summary line recognised)"
            )
        line = f"{result.stage.key.ljust(key_width)}  {result.status:<6}  {timing}"
        print(f"{line}  {detail}")


def _print_detail(result: StageResult, tail_lines: int) -> None:
    """Print the failure or skip detail for one gate (M18.13)."""
    print()
    if result.status == SKIPPED:
        rule = f"---- SKIPPED {result.stage.key}: {result.reason} "
        print(rule.ljust(BANNER_WIDTH, "-"))
        print("     it was selected, so this run cannot pass while it is unrun")
        return
    rule = f"---- FAILED {result.stage.key}: {result.reason} "
    print(rule.ljust(BANNER_WIDTH, "-"))
    print(f"     re-run it: {_reproduction(result.stage)}")
    body = _tail(result.output, tail_lines)
    if body:
        print(body)


def _print_output(result: StageResult, tail_lines: int) -> None:
    """Print one gate's output because --verbose asked for it (M18.13)."""
    body = _tail(result.output, tail_lines)
    if not body:
        return
    print()
    print(f"---- output: {result.stage.key} ".ljust(BANNER_WIDTH, "-"))
    print(body)


def _report(
    results: Sequence[StageResult],
    *,
    tail_lines: int,
    verbose: bool,
    strict_skips: bool,
) -> int:
    """Print every gate's outcome and return the process exit code (M18.13).

    The exit code is the only thing a caller should trust. It is 0 exactly when
    every selected gate ran and passed.
    """
    _print_table(results)

    failures = [result for result in results if result.status == FAILED]
    skipped = [result for result in results if result.status == SKIPPED]
    with_skipped_tests = [result for result in results if result.skipped_tests]

    for result in results:
        if result.status in (FAILED, SKIPPED):
            _print_detail(result, tail_lines)
        elif verbose:
            _print_output(result, tail_lines)

    if with_skipped_tests:
        print()
        print("tests skipped inside a gate (reported, and never counted as a pass):")
        for result in with_skipped_tests:
            print(f"  {result.stage.key}: {result.skipped_tests} skipped")

    passed = [result for result in results if result.ok]
    print()
    print(
        f"{len(results)} gate(s): {len(passed)} passed, {len(failures)} failed, "
        f"{len(skipped)} skipped"
    )

    reasons = []
    if failures:
        reasons.append(f"{len(failures)} failed")
    if skipped:
        reasons.append(f"{len(skipped)} skipped for a missing prerequisite")
    if strict_skips and with_skipped_tests:
        reasons.append("skipped tests reported while --strict-skips is set")

    if reasons:
        print(f"RESULT: FAIL ({'; '.join(reasons)})")
        return 1

    print("RESULT: PASS")
    return 0


# -- the command line ---------------------------------------------------------


def _print_stage_list(stages: Sequence[Stage]) -> None:
    """Print every gate, what it runs and what it needs (M18.13)."""
    for stage in stages:
        missing = stage.missing_requirements()
        if missing:
            availability = "missing " + ", ".join(
                _relative(path) for path in missing
            )
        else:
            availability = "all present"
        default = "yes" if stage.key in DEFAULT_KEYS else "only with --full"
        print(f"{stage.key} — {stage.title}")
        print(f"    closes:   {stage.closes}")
        print(f"    command:  {_reproduction(stage)}")
        print(f"    default:  {default}")
        print(f"    requires: {availability}")
        print()


def _parse_keys(raw: str, by_key: Mapping[str, Stage], flag: str) -> set[str]:
    """Turn a comma-separated gate list into keys, rejecting unknown names (M18.13)."""
    keys = {part.strip() for part in raw.split(",") if part.strip()}
    if not keys:
        raise SystemExit(f"{flag} needs at least one gate name; run --list to see them")
    unknown = sorted(key for key in keys if key not in by_key)
    if unknown:
        raise SystemExit(
            f"{flag}: unknown gate(s): {', '.join(unknown)}; run --list to see them"
        )
    return keys


def _select_keys(
    args: argparse.Namespace, by_key: Mapping[str, Stage]
) -> frozenset[str]:
    """Work out which gates this run should execute (M18.13)."""
    if args.only:
        keys = _parse_keys(args.only, by_key, "--only")
    elif args.full:
        keys = set(DEFAULT_KEYS) | set(LONG_KEYS)
    else:
        keys = set(DEFAULT_KEYS)
    if args.skip:
        keys -= _parse_keys(args.skip, by_key, "--skip")
    return frozenset(keys)


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser (M18.13)."""
    gates = ", ".join(stage.key for stage in build_stages())
    parser = argparse.ArgumentParser(
        prog="run_quality_gates.py",
        description="Run the NetWatch AI quality gates (M18.13).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"gates: {gates}\n\n"
            "The exit status is 0 only when every selected gate ran and passed."
        ),
    )
    parser.add_argument(
        "--only",
        metavar="KEYS",
        help="run only these comma-separated gates, in the order shown by --list",
    )
    parser.add_argument(
        "--skip",
        metavar="KEYS",
        help="drop these comma-separated gates from the selection",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run the long gates: e2e, e2e-live and performance",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list the gates, their commands and their prerequisites, then exit",
    )
    parser.add_argument(
        "--strict-skips",
        action="store_true",
        help="fail the run when any selected gate reports skipped tests",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="also print the output of gates that passed",
    )
    parser.add_argument(
        "--tail-lines",
        type=int,
        default=DEFAULT_TAIL_LINES,
        metavar="N",
        help=f"lines of output shown per gate (default {DEFAULT_TAIL_LINES})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected gates and return the process exit code (M18.13)."""
    args = _build_parser().parse_args(argv)
    stages = build_stages()
    by_key = {stage.key: stage for stage in stages}

    if args.list:
        _print_stage_list(stages)
        return 0

    selected = tuple(stage for stage in stages if stage.key in _select_keys(args, by_key))
    if not selected:
        print("no gates selected; run --list to see the gates", file=sys.stderr)
        return 1

    results = []
    for index, stage in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] {stage.key}: {_reproduction(stage)}")
        result = _run_stage(stage)
        results.append(result)
        detail = result.summary or result.reason
        suffix = f" — {detail}" if detail else ""
        print(f"          {result.status} in {result.duration:.2f}s{suffix}")

    return _report(
        tuple(results),
        tail_lines=args.tail_lines,
        verbose=args.verbose,
        strict_skips=args.strict_skips,
    )


if __name__ == "__main__":
    raise SystemExit(main())
