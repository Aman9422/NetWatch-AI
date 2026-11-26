"""Learning-lifecycle tests (M21.7).

The state is the one thing a reader will act on — a frontend badge, an operator's
"is this device known yet?" — so the rules around it get their own file. Three of
them are load-bearing:

* **Maturity is a sample count, never elapsed time.** A device that appeared once
  an hour ago is still learning; one with thirty windows in thirty minutes is
  established.
* **A new device never gets a fabricated baseline.** ``learning`` publishes no
  statistics at all, rather than a profile of zeroes.
* **Established is descriptive, not a verdict.** The sentence every consumer shows
  has to say so, because it is the one most likely to be misread.
"""

from __future__ import annotations

import pytest

from app.baselines.states import (
    DEFAULT_ESTABLISHED_MIN_SAMPLES,
    DEFAULT_PROVISIONAL_MIN_SAMPLES,
    LEARNING_STATES,
    STATE_ORDER,
    LearningState,
    describe_state,
    is_mature,
    normalize_state,
    publishes_statistics,
    state_for_samples,
)


# ---------------------------------------------------------------------------
# the thresholds
# ---------------------------------------------------------------------------


def test_the_default_thresholds_are_ordered_and_positive() -> None:
    """A zero threshold would make every device established on creation."""
    assert DEFAULT_PROVISIONAL_MIN_SAMPLES >= 1
    assert DEFAULT_ESTABLISHED_MIN_SAMPLES > DEFAULT_PROVISIONAL_MIN_SAMPLES


def test_the_vocabulary_is_the_three_documented_states() -> None:
    """The API's closed vocabulary and the stored values are the same tuple."""
    assert LEARNING_STATES == ("learning", "provisional", "established")


def test_the_states_have_a_defined_display_order() -> None:
    """Least to most mature, which is what a sort or a colour ramp reads."""
    assert STATE_ORDER == {"learning": 0, "provisional": 1, "established": 2}


# ---------------------------------------------------------------------------
# state_for_samples
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, LearningState.LEARNING),
        (1, LearningState.LEARNING),
        (4, LearningState.LEARNING),
        (5, LearningState.PROVISIONAL),
        (29, LearningState.PROVISIONAL),
        (30, LearningState.ESTABLISHED),
        (1000, LearningState.ESTABLISHED),
    ],
)
def test_a_sample_count_maps_to_the_documented_state(
    count: int, expected: LearningState
) -> None:
    """The boundaries are inclusive at the threshold, which is what "minimum" means."""
    assert state_for_samples(count) == expected


def test_a_negative_count_is_treated_as_zero() -> None:
    """A corrupt count must not be able to claim maturity."""
    assert state_for_samples(-5) == LearningState.LEARNING


def test_the_thresholds_are_configurable() -> None:
    """An operator can tighten or loosen the requirements."""
    assert (
        state_for_samples(3, provisional_min=3, established_min=4)
        is LearningState.PROVISIONAL
    )
    assert (
        state_for_samples(4, provisional_min=3, established_min=4)
        is LearningState.ESTABLISHED
    )


def test_an_inconsistent_configuration_reports_the_weaker_state() -> None:
    """Established below provisional is clamped up, not used to skip a stage."""
    assert (
        state_for_samples(2, provisional_min=5, established_min=1)
        is LearningState.LEARNING
    )


def test_a_zero_provisional_threshold_is_rejected() -> None:
    """It would make "established on creation" reachable, which M21.7 forbids."""
    with pytest.raises(ValueError):
        state_for_samples(0, provisional_min=0)


def test_maturity_depends_on_count_and_never_on_time() -> None:
    """The same count gives the same state however long the device has existed.

    There is no timestamp in this call and no clock behind it, which is the
    property being asserted.
    """
    assert state_for_samples(30) is LearningState.ESTABLISHED
    assert state_for_samples(29) is LearningState.PROVISIONAL


# ---------------------------------------------------------------------------
# what a state publishes
# ---------------------------------------------------------------------------


def test_learning_publishes_no_statistics() -> None:
    """A median of two windows is not a description of normal behaviour."""
    assert publishes_statistics(LearningState.LEARNING) is False


def test_provisional_and_established_publish_statistics() -> None:
    """Both are calculated from real observations, so both are shown."""
    assert publishes_statistics(LearningState.PROVISIONAL) is True
    assert publishes_statistics(LearningState.ESTABLISHED) is True


def test_only_established_is_mature() -> None:
    """A provisional profile is available but is not yet mature."""
    assert is_mature(LearningState.ESTABLISHED) is True
    assert is_mature(LearningState.PROVISIONAL) is False
    assert is_mature(LearningState.LEARNING) is False


@pytest.mark.parametrize("state", LEARNING_STATES)
def test_a_string_state_behaves_the_same_as_the_enum(state: str) -> None:
    """The API reads a stored string, so both forms must be accepted."""
    assert publishes_statistics(state) == publishes_statistics(
        LearningState(state)
    )
    assert is_mature(state) == is_mature(LearningState(state))


# ---------------------------------------------------------------------------
# normalizing what was stored
# ---------------------------------------------------------------------------


def test_a_stored_state_is_read_back() -> None:
    """The value in the column round-trips to the enum."""
    assert normalize_state("established") is LearningState.ESTABLISHED


def test_a_stored_state_is_case_and_whitespace_tolerant() -> None:
    """A hand-edited row should not crash a listing."""
    assert normalize_state("  PROVISIONAL  ") is LearningState.PROVISIONAL


def test_an_absent_state_is_reported_as_learning() -> None:
    """Claiming more maturity than was recorded would be claiming evidence."""
    assert normalize_state(None) is LearningState.LEARNING


def test_an_unrecognized_state_is_reported_as_learning() -> None:
    """An unknown value is not evidence of anything, so the weakest state wins."""
    assert normalize_state("almost-established") is LearningState.LEARNING
    assert normalize_state("") is LearningState.LEARNING


# ---------------------------------------------------------------------------
# what the sentence says
# ---------------------------------------------------------------------------


def test_every_state_has_a_non_empty_description() -> None:
    """The frontend shows this beside the badge, so it is never blank."""
    for state in LEARNING_STATES:
        assert describe_state(state).strip()


def test_the_established_description_denies_being_a_verdict() -> None:
    """The sentence most likely to be misread says what it is not (M21.7)."""
    sentence = describe_state(LearningState.ESTABLISHED)

    assert "not a statement that the device is safe" in sentence
    assert "describes what this device normally does" in sentence


def test_the_learning_description_says_nothing_is_known_yet() -> None:
    """It must not imply a profile exists."""
    sentence = describe_state(LearningState.LEARNING)

    assert "Not enough observations" in sentence


def test_the_provisional_description_says_the_figures_are_developing() -> None:
    """A reader has to know the profile is real but not yet settled."""
    sentence = describe_state(LearningState.PROVISIONAL)

    assert "still developing" in sentence


def test_the_descriptions_differ_between_states() -> None:
    """Three states that read identically would be one state with three labels."""
    sentences = {describe_state(state) for state in LEARNING_STATES}

    assert len(sentences) == 3
