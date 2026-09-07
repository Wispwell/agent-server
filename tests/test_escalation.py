"""Tests for escalation handlers. Every one of them must fail closed."""

from __future__ import annotations

import io
import os

import pytest

from agentserver.containment.escalation import (
    auto_refuse,
    cli_handler,
    scripted_handler,
)

ESC = {"agent_id": "abc", "capability": "cap:fs.read",
       "resource": "workspace/x.md", "reason": "requires_review", "detail": ""}


def test_the_default_refuses():
    assert auto_refuse(ESC) is False


def test_scripted_answers_are_replayed_in_order():
    handle = scripted_handler([True, False, True])
    assert [handle(ESC) for _ in range(3)] == [True, False, True]


def test_a_script_that_runs_out_refuses_rather_than_approving():
    """An eval that silently began approving everything would report a
    containment boundary that had quietly stopped existing."""
    handle = scripted_handler([True])
    assert handle(ESC) is True
    assert [handle(ESC) for _ in range(5)] == [False] * 5


def _with_stdin(text, monkeypatch):
    r, w = os.pipe()
    os.write(w, text.encode())
    os.close(w)
    monkeypatch.setattr("sys.stdin", os.fdopen(r))


@pytest.mark.parametrize(("typed", "expected"),
                         [("y\n", True), ("yes\n", True), ("Y\n", True),
                          ("n\n", False), ("\n", False), ("maybe\n", False)])
def test_the_cli_reads_an_answer(monkeypatch, typed, expected):
    _with_stdin(typed, monkeypatch)
    assert cli_handler(timeout=5, stream=io.StringIO())(ESC) is expected


def test_an_unanswered_prompt_times_out_into_refusal(monkeypatch):
    """The whole point of the timeout: 'the operator stepped away' must resolve
    to refusal, not to waiting forever."""
    r, _w = os.pipe()          # nothing ever written, and the writer stays open
    monkeypatch.setattr("sys.stdin", os.fdopen(r))
    out = io.StringIO()
    assert cli_handler(timeout=1, stream=out)(ESC) is False
    assert "timed out" in out.getvalue()


def test_a_closed_stdin_refuses(monkeypatch):
    stream = io.StringIO()
    stream.close()
    monkeypatch.setattr("sys.stdin", stream)
    assert cli_handler(timeout=1, stream=io.StringIO())(ESC) is False
