"""Tests for the quality-gate runner's own reporting (M19.2).

The gate runner is the one command M18.13 asks a reader to trust, and its report
is only worth trusting if it states each gate's *own* result rather than merely
that a child process exited 0. The M19 baseline found that it could not: five of
the nine gates were reported as ``(no summary line recognised)``.

The finding was not a wrong verdict — the exit code is authoritative and every
gate passed — it was a report that had stopped describing what it ran. The cause
was that the summary search matched raw captured output, so

* a colourised line (Vite's build reporter and Vitest's summary both colourise)
  begins with an escape sequence and never matched a ``^``-anchored pattern; and
* the three script gates print their own ``RESULT: …`` verdict, which no pattern
  in the runner was looking for at all.

These tests drive the extraction functions directly with the output shapes those
commands really produce, so the report cannot silently stop naming a result
again. They run no gate: a test that spawned the nine real gates would take
minutes and would be testing them, not this.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

#: The repository root, derived from this file rather than assumed.
BACKEND_ROOT = Path(__file__).resolve().parent.parent

#: The runner under test.
_RUNNER_PATH = BACKEND_ROOT / "scripts" / "run_quality_gates.py"


def _load_runner() -> ModuleType:
    """Import ``scripts/run_quality_gates.py`` as a module (M19.2).

    Loaded by path rather than by ``import scripts.run_quality_gates`` because
    ``scripts/`` is a directory of entry points rather than an installed package:
    the gates are meant to be *run*, and a test is the only caller that needs to
    import one. Loading it explicitly keeps that property and does not require
    the directory to grow an ``__init__.py`` it does not need.
    """
    name = "m19_quality_gate_runner"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


#: What each gate's command really ends with, as the baseline run captured it.
#:
#: Keyed by gate so the structural test below can hold every gate to a sample of
#: its own output: a gate whose patterns match none of its sample is a gate whose
#: result the report cannot state, which is the defect this file exists for.
SAMPLES: dict[str, str] = {
    "backend-tests": (
        "....................\n"
        "2539 passed, 1 warning in 36.58s\n"
    ),
    "backend-types": "0 errors, 0 warnings, 0 informations\n",
    "security": "145 passed, 1 warning in 2.55s\n",
    # Vitest colourises its summary, so the line arrives wrapped in escapes.
    "frontend-unit": (
        "\x1b[2m Test Files \x1b[22m \x1b[1m\x1b[32m16 passed\x1b[39m\x1b[22m (16)\n"
        "\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m461 passed\x1b[39m\x1b[22m (461)\n"
        "\x1b[2m   Start at \x1b[22m 19:07:11\n"
    ),
    # Vite's reporter writes progress with a carriage return and ends with a
    # colourised "built in" line.
    "frontend-build": (
        "\x1b[32m\u2713 2554 modules transformed.\x1b[39m\r"
        "\x1b[32m\u2713 built in 714ms\x1b[39m\n"
    ),
    "e2e": "Every property the M18.9 flow promises held\nRESULT: PASS (sample mode)\n",
    "e2e-live": "Every property the M18.9 flow promises held\nRESULT: PASS (live mode)\n",
    "performance": "--- notes ---\nRESULT: measured\n",
}


def _stage(key: str):
    """Return the built stage for a gate key."""
    stages = {stage.key: stage for stage in runner.build_stages()}
    assert key in stages, f"the runner no longer declares a {key!r} gate"
    return stages[key]


# ---------------------------------------------------------------------------
# The defect: a gate's own result was not being read
# ---------------------------------------------------------------------------


def test_the_last_summary_shaped_line_is_the_one_reported() -> None:
    """A run that printed a summary-like fragment still reports the real one.

    The extractor takes the *last* match, so a command that echoes an earlier
    summary-shaped line cannot make the report quote the wrong numbers.
    """
    output = "9 passed in 0.01s (an inner suite)\n2539 passed in 36.58s\n"
    assert (
        runner._extract_summary(output, (runner._PYTEST_SUMMARY,))
        == "2539 passed in 36.58s"
    )


def test_every_gate_reads_its_own_kind_of_summary() -> None:
    """Every gate recognises a sample of its own real output (M19.2).

    This is the regression test for the defect: before the fix, ``frontend-unit``,
    ``frontend-build``, ``e2e``, ``e2e-live`` and ``performance`` all failed this
    assertion while still exiting 0 — a green run whose report said nothing about
    five of its nine gates.
    """
    for key, sample in SAMPLES.items():
        stage = _stage(key)
        found = runner._extract_summary(
            runner._normalise_output(sample), stage.summaries
        )
        assert found, (
            f"the {key!r} gate reports no summary for output it really produces, "
            "so its result cannot be stated in the report"
        )


def test_the_vitest_summary_is_read_through_colour() -> None:
    """A colourised Vitest summary line is still recognised (M19.2)."""
    found = runner._extract_summary(
        runner._normalise_output(SAMPLES["frontend-unit"]), (runner._VITEST_SUMMARY,)
    )
    assert "461 passed" in found


def test_the_vite_summary_is_read_through_a_carriage_return() -> None:
    """A ``built in`` line written after a carriage-returned progress line reads."""
    found = runner._extract_summary(
        runner._normalise_output(SAMPLES["frontend-build"]),
        (runner._VITE_BUILD_SUMMARY,),
    )
    assert "built in 714ms" in found


@pytest.mark.parametrize("key", ["e2e", "e2e-live", "performance"])
def test_a_script_gate_reads_its_own_verdict_line(key: str) -> None:
    """A gate that is a script quotes the verdict the script printed (M19.2)."""
    found = runner._extract_summary(
        runner._normalise_output(SAMPLES[key]), _stage(key).summaries
    )
    assert found.startswith("RESULT:")


def test_a_script_gate_reports_a_failure_as_a_failure() -> None:
    """The failing verdict is quoted too, not only the passing one.

    A report that could only read ``RESULT: PASS`` would leave the one case that
    matters — a gate that did not pass — as an unstated result.
    """
    found = runner._extract_summary(
        runner._normalise_output("RESULT: FAIL (sample mode)\n"), (runner._RESULT_LINE,)
    )
    assert found == "RESULT: FAIL (sample mode)"


# ---------------------------------------------------------------------------
# Normalisation, and the honesty rules it must not disturb
# ---------------------------------------------------------------------------


def test_normalisation_strips_escapes_and_carriage_returns() -> None:
    """Escapes and stray carriage returns are removed before matching (M19.2)."""
    assert runner._normalise_output("\x1b[32mred\x1b[0m\r\n next\r last") == (
        "red\n next\n last"
    )


def test_normalisation_leaves_ordinary_text_alone() -> None:
    """A report is not altered where it had nothing to alter."""
    text = "145 passed, 1 warning in 2.55s\n"
    assert runner._normalise_output(text) == text


def test_a_run_that_collected_nothing_is_still_not_a_pass() -> None:
    """The M18.13 honesty rule survives the M19.2 change (M18.13)."""
    stage = _stage("backend-tests")
    reason = runner._no_tests_reason(stage, "no tests ran in 0.02s\n")
    assert reason == "the runner collected no tests"


def test_a_suite_that_reported_no_passing_test_is_not_a_pass() -> None:
    """A gate whose output never says "passed" is refused (M18.13)."""
    stage = _stage("frontend-unit")
    assert runner._no_tests_reason(stage, "Test Files  no tests\n")


def test_skipped_tests_are_counted_after_normalisation() -> None:
    """A skip count survives the change, so a skip can never look like coverage."""
    output = "\x1b[33m10 passed, 2 skipped in 1.00s\x1b[0m\n"
    assert runner._count_skips(runner._normalise_output(output)) == 2


def test_only_the_silent_gate_declares_no_summary_pattern() -> None:
    """Every gate that prints something declares what to read from it (M19.2).

    ``frontend-types`` is the one legitimate exception: ``tsc --noEmit`` is
    silent on success, which the stage declares rather than inferring.
    """
    expected = {
        stage.key
        for stage in runner.build_stages()
        if not stage.summaries and not stage.silent_on_success
    }
    assert expected == set()
