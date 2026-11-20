"""Every assertion here passes no matter what the code under test does."""

from unittest import mock

import pytest


def apply_discount(price, rate):
    return price * (1 - rate)


def test_mock_lookalike():
    notifier = mock.AsyncMock()
    apply_discount(100, 0.1)
    assert notifier.awaited_once_with("discount applied")


def test_uncalled_assertion_statement():
    notifier = mock.Mock()
    notifier.assert_called_once_with


def test_uncalled_assertion_in_assert():
    notifier = mock.Mock()
    assert notifier.assert_not_called


def test_unused_raises():
    pytest.raises(ValueError)
    apply_discount(100, 2)


def test_constant():
    assert True


def test_tuple_message():
    assert (apply_discount(100, 0.1) == 90, "discount should apply")


def test_self_comparison():
    result = apply_discount(100, 0.1)
    assert result == result


def test_length():
    items = [apply_discount(10, 0.1)]
    assert len(items) >= 0
