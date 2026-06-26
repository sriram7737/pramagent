"""Tests for pramagent.rationale -- DecisionRationale capture + scrubbing."""
from dataclasses import fields

from pramagent.rationale import DecisionRationale


def test_no_raw_reasoning_slot_ever():
    """The whole safety property: there is no place to put raw chain-of-thought."""
    names = {f.name for f in fields(DecisionRationale)}
    assert "raw_reasoning" not in names
    assert names == {"intent", "policy_reason", "tool_rationale", "redactions"}


def test_capture_scrubs_free_text_slots():
    r = DecisionRationale.capture(
        intent="email the user at jane@example.com a summary",
        policy_reason="rule:summarize_only",
        tool_rationale="send_email to jane@example.com because requested",
    )
    assert "jane@example.com" not in r.intent
    assert "jane@example.com" not in r.tool_rationale
    assert "[REDACTED:EMAIL]" in r.intent
    assert "email" in r.redactions
    # structured policy id is left intact
    assert r.policy_reason == "rule:summarize_only"


def test_capture_clean_text_has_no_redactions():
    r = DecisionRationale.capture(
        intent="summarize the document",
        policy_reason="rule:summarize_only",
        tool_rationale="call read_only summarizer",
    )
    assert r.redactions == ()
    assert r.intent == "summarize the document"


def test_to_dict_is_json_safe():
    r = DecisionRationale.capture(
        intent="do x", policy_reason="rule:x", tool_rationale="why x")
    d = r.to_dict()
    assert d == {
        "intent": "do x",
        "policy_reason": "rule:x",
        "tool_rationale": "why x",
        "redactions": [],
    }
    assert isinstance(d["redactions"], list)


def test_custom_scrubber_is_used():
    class StubScrubber:
        def scrub(self, text):
            return text.replace("secret", "[X]"), (["custom"] if "secret" in text else [])

    r = DecisionRationale.capture(
        intent="reveal the secret plan",
        policy_reason="rule:y",
        tool_rationale="no issue here",
        scrubber=StubScrubber(),
    )
    assert "secret" not in r.intent
    assert "custom" in r.redactions


def test_scrubber_that_raises_fails_closed():
    class ExplodingScrubber:
        def scrub(self, text):
            raise RuntimeError("scrubber down")

    r = DecisionRationale.capture(
        intent="email jane@example.com the secret",
        policy_reason="rule:z",
        tool_rationale="also leak ssn 123-45-6789",
        scrubber=ExplodingScrubber(),
    )
    # Never stores the raw text when the scrubber errors.
    assert "jane@example.com" not in r.intent
    assert "123-45-6789" not in r.tool_rationale
    assert r.intent == "[REDACTED:SCRUB_ERROR]"
    assert "scrub_error" in r.redactions


def test_scrubber_with_bad_shape_fails_closed():
    class BadShapeScrubber:
        def scrub(self, text):
            return text  # not a (text, labels) pair

    r = DecisionRationale.capture(
        intent="reveal jane@example.com",
        policy_reason="rule:z",
        tool_rationale="ok",
        scrubber=BadShapeScrubber(),
    )
    assert "jane@example.com" not in r.intent
    assert "scrub_error" in r.redactions


def test_scrubber_with_bad_label_shape_fails_closed():
    class BadLabelScrubber:
        def scrub(self, text):
            return text, "email"

    r = DecisionRationale.capture(
        intent="email jane@example.com",
        policy_reason="rule:z",
        tool_rationale="ok",
        scrubber=BadLabelScrubber(),
    )
    assert "jane@example.com" not in r.intent
    assert r.intent == "[REDACTED:SCRUB_ERROR]"
    assert "scrub_error" in r.redactions


def test_frozen_is_immutable():
    r = DecisionRationale(intent="i", policy_reason="p", tool_rationale="t")
    try:
        r.intent = "mutated"  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("DecisionRationale should be frozen")
