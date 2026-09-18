"""Local validation before a request is sent.

The rule table in _rules.py is generated from the protocol's method rules and
shared by every SDK language.

Checks follow the protocol's client-side validation section: top-level required
fields and formats, method shape, and method required fields. Nothing else.

Format rules (phone length, e-mail, IFSC length, ...) are deliberately left to
the gateway: they evolve per currency and channel, a copy in the SDK would
drift, and merchants could only get the fix through an SDK release.
"""

from __future__ import annotations

import re
from typing import Any

from ._rules import (
    AMOUNT_PATTERN,
    CREATE_REQUIRED_TEXT_FIELDS,
    METHOD_EXTRA_FIELDS,
    PAYMENT_METHOD_RULES,
    PAYOUT_METHOD_RULES,
    WEBHOOK_URL_PREFIX,
)
from .errors import RequestError


# Mirrors the gateway regex and the DECIMAL(18,2) cap
_AMOUNT = re.compile(AMOUNT_PATTERN)


def _validate_amount(field: str, value: Any) -> None:
    """Amount must be a positive decimal string; the gateway rejects JSON numbers.
    The pattern allows only digits and a dot, so "> 0" means "has a non-zero digit"."""
    if value is None or value == "":
        raise RequestError(f"sdk: required field is empty: {field}")
    if not isinstance(value, str):
        raise RequestError(
            f"sdk: {field} must be a decimal string such as \"100.00\", got {type(value).__name__}"
        )
    if not _AMOUNT.match(value):
        raise RequestError(f"sdk: {field} must be a positive decimal string: {value!r}")
    if not re.search(r"[1-9]", value):
        raise RequestError(f"sdk: {field} must be greater than 0")


def _validate_webhook_url(field: str, value: Any) -> None:
    """Mirrors the gateway rule: required and starting with https://."""
    if not isinstance(value, str) or not value.strip():
        raise RequestError(f"sdk: required field is empty: {field}")
    if not value.lower().startswith(WEBHOOK_URL_PREFIX):
        scheme = WEBHOOK_URL_PREFIX.removesuffix("://")
        raise RequestError(f"sdk: {field} must be an absolute {scheme} URL")


def validate_create_common(body: dict[str, Any]) -> None:
    """Top-level fields the gateway marks required. Catching blanks here avoids
    signing and sealing a request only to get INVALID_FIELD back."""
    for field in CREATE_REQUIRED_TEXT_FIELDS:
        if _empty(body.get(field)):
            raise RequestError(f"sdk: required field is empty: {field}")
    _validate_amount("amount", body.get("amount"))
    _validate_webhook_url("webhookUrl", body.get("webhookUrl"))


def validate_path_order_no(order_no: Any) -> str:
    """Order number used as a path segment: trimmed and non-blank.
    The caller percent-encodes it before it enters the signature base."""
    value = str(order_no or "").strip()
    if not value:
        raise RequestError("sdk: invalid path parameter")
    return value


def _empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    return False


def _validate_method(currency: str, method: dict[str, Any] | None, rules: dict) -> None:
    method = method or {}
    code = str(method.get("code") or "").strip()
    if not code:
        raise RequestError("sdk: method code is required")

    present = sorted(k for k in method if k != "code" and method[k] is not None)
    if len(present) > 1:
        raise RequestError(f"sdk: only one method extra may be set: {', '.join(present)}")
    want = METHOD_EXTRA_FIELDS.get(code)
    if present and want and present[0] != want:
        raise RequestError(
            f"sdk: method extra does not match code: {code} expects {want!r}, got {present[0]!r}"
        )

    rule = rules.get((currency or "").strip().upper())
    if rule is None:
        # unknown currency: let the gateway decide, the SDK table may be older than the gateway
        return
    if rule["codes"] and code not in rule["codes"]:
        raise RequestError(f"sdk: method is not available for this currency: {code} for {currency}")

    need = list(rule["required"]) + list(rule["byMethod"].get(code, []))
    optional_nullable_strings = rule.get("optionalNullableStringsByMethod", {}).get(code, [])
    if not need and not optional_nullable_strings:
        return
    extra = method.get(present[0]) or {} if present else {}
    if not isinstance(extra, dict):
        raise RequestError(f"sdk: method extra must be an object: {present[0]}")
    for field in need:
        if field in rule.get("allowEmpty", []):
            if not isinstance(extra.get(field), str):
                raise RequestError(f"sdk: extra.{field} must be a string for {currency} {code}")
            continue
        if field not in extra or _empty(extra[field]):
            raise RequestError(
                f"sdk: required extra field is empty: extra.{field} for {currency} {code}"
            )
    for field in optional_nullable_strings:
        value = extra.get(field)
        if value is not None and not isinstance(value, str):
            raise RequestError(f"sdk: extra.{field} must be a string or null for {currency} {code}")


def validate_payment_method(currency: str, method: dict[str, Any] | None) -> None:
    _validate_method(currency, method, PAYMENT_METHOD_RULES)


def validate_payout_method(currency: str, method: dict[str, Any] | None) -> None:
    _validate_method(currency, method, PAYOUT_METHOD_RULES)
