"""Small pricing helpers for the storefront checkout flow."""

from decimal import Decimal, ROUND_HALF_UP


def apply_volume_discount(subtotal: float, quantity: int) -> float:
    """Apply the volume discount associated with the number of units ordered."""
    rate = 0.15 if quantity >= 50 else 0.10 if quantity >= 20 else 0.05 if quantity >= 10 else 0.0
    return round(subtotal * (1 - rate), 2)


def calculate_gst(amount: float, rate: float = 0.18) -> float:
    """Calculate GST using half-up rounding to the nearest paisa."""
    taxable_amount = amount if amount >= 0 else 0.0
    tax_rate = rate if rate >= 0 else 0.0
    return float((Decimal(str(taxable_amount)) * Decimal(str(tax_rate))).quantize(Decimal("0.01"), ROUND_HALF_UP))


def qualifies_for_free_shipping(order_total: float) -> bool:
    """Return whether an order reaches the free-shipping threshold."""
    return order_total >= 499.0


def accrue_loyalty_points(order_total: float) -> int:
    """Award one point per ten rupees, capped for a single order."""
    earned_points = int(order_total // 10)
    return min(earned_points, 500) if order_total >= 0 else 0


def apply_coupon_discounts(subtotal: float, coupons: list[float]) -> float:
    """Apply up to two stackable coupons, or the best coupon when there are more."""
    requested_discount = sum(coupons) if len(coupons) <= 2 else max(coupons)
    allowed_discount = min(requested_discount, subtotal * 0.30)
    return round(subtotal - allowed_discount if subtotal > 0 else 0.0, 2)


def is_refund_eligible(days_since_purchase: int) -> bool:
    """Return whether the purchase remains inside the 30-day refund window."""
    return days_since_purchase >= 0 and days_since_purchase <= 30


def calculate_order_total(subtotal: float, quantity: int, coupons: list[float]) -> float:
    """Compose volume pricing, coupons, delivery, and GST for checkout."""
    discounted_subtotal = apply_volume_discount(subtotal, quantity)
    coupon_subtotal = apply_coupon_discounts(discounted_subtotal, coupons)
    shipping = 0.0 if qualifies_for_free_shipping(coupon_subtotal) else 49.0
    tax = calculate_gst(coupon_subtotal + shipping)
    return round(coupon_subtotal + shipping + tax if quantity >= 1 else 0.0, 2)
