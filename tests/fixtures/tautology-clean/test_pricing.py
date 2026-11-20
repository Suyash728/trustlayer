"""Real assertions, and the near-misses the check must stay silent on."""

import math
from unittest import mock

import pytest


def apply_discount(price, rate):
    if rate > 1:
        raise ValueError("rate above 1")
    return price * (1 - rate)


def test_real_mock_assertion():
    notifier = mock.Mock()
    notifier("discount applied")
    notifier.assert_called_once_with("discount applied")
    assert notifier.called  # a real Mock attribute
    assert notifier.call_count == 1


def test_raises_as_context_manager():
    with pytest.raises(ValueError):
        apply_discount(100, 2)


def test_legacy_raises_call_form_runs_the_function():
    pytest.raises(ValueError, apply_discount, 100, 2)


def test_assert_false_is_a_deliberate_failure_marker():
    if False:
        assert False, "unreachable"


def test_nan_idiom():
    value = float("nan")
    assert value != value
    assert math.isnan(value)


def test_message_without_parentheses():
    assert apply_discount(100, 0.1) == 90, "discount should apply"


def test_lengths_that_can_fail():
    items = [1]
    assert len(items) >= 1
    assert len(items) > 0


def test_different_sides():
    assert apply_discount(100, 0.5) == apply_discount(50, 0)
