from pricing import (
    accrue_loyalty_points,
    apply_coupon_discounts,
    apply_volume_discount,
    calculate_gst,
    calculate_order_total,
    is_refund_eligible,
    qualifies_for_free_shipping,
)


def test_volume_discount_applies_to_bulk_order():
    total = apply_volume_discount(1_200.0, 25)

    assert total == 1_080.0


def test_larger_bulk_order_uses_highest_discount():
    total = apply_volume_discount(199.99, 55)

    assert total == 169.99


def test_gst_is_returned_as_a_number():
    tax = calculate_gst(125.0)

    assert isinstance(tax, float)
    assert tax == 22.5


def test_free_shipping_for_large_order():
    assert qualifies_for_free_shipping(850.0)


def test_loyalty_points_are_earned():
    points = accrue_loyalty_points(240.0)

    assert points == 24


def test_coupon_discount_reduces_subtotal():
    discounted = apply_coupon_discounts(400.0, [25.0])

    assert discounted == 375.0


def test_recent_purchase_is_refundable():
    assert is_refund_eligible(8)


def test_order_total_is_positive():
    total = calculate_order_total(1_000.0, 12, [50.0])

    assert total == 1_062.0


def test_order_total_includes_standard_shipping():
    total = calculate_order_total(300.0, 12, [25.0])

    assert total == 364.62
