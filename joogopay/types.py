"""DTOs for merchant requests, responses and webhooks.

Amounts, fees and rates are always decimal strings, never floats.

Payment method extras have many variants that evolve with channels, so they are
passed through as dicts; core DTOs are dataclasses with fixed fields.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Externally visible order statuses; there are no others
STATUS_PENDING = "PENDING"
STATUS_PROCESSING = "PROCESSING"
STATUS_SUCCEEDED = "SUCCEEDED"
STATUS_FAILED = "FAILED"
STATUS_EXPIRED = "EXPIRED"
STATUS_CANCELED = "CANCELED"
STATUS_REFUNDED = "REFUNDED"  # Payouts only, after the refund is credited.

EXTERNAL_STATUSES = frozenset({
    STATUS_PENDING, STATUS_PROCESSING, STATUS_SUCCEEDED,
    STATUS_FAILED, STATUS_EXPIRED, STATUS_CANCELED, STATUS_REFUNDED,
})

WEBHOOK_ORDER_TYPE_PAYMENT = "PAYMENT"
WEBHOOK_ORDER_TYPE_PAYOUT = "PAYOUT"


def _drop_empty(data: dict[str, Any]) -> dict[str, Any]:
    """Omit None and empty values from the serialized body."""
    return {k: v for k, v in data.items() if v not in (None, "", {}, [])}


@dataclass
class CreatePaymentReq:
    merchantOrderNo: str
    currency: str
    amount: str  # decimal string, e.g. "100.00"
    paymentMethod: dict[str, Any]  # {"code": "PIX", "pix": {...}}
    webhookUrl: str
    country: str = ""
    returnUrl: str = ""
    attach: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["paymentMethod"] = _drop_empty(self.paymentMethod)
        return _drop_empty(out)


@dataclass
class CreatePayoutReq:
    merchantOrderNo: str
    currency: str
    amount: str
    payoutMethod: dict[str, Any]  # {"code": "PIX", "pix": {...}}
    webhookUrl: str
    country: str = ""
    attach: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["payoutMethod"] = _drop_empty(self.payoutMethod)
        return _drop_empty(out)


class _FromDict:
    """Build from a dict by field name; unknown fields are ignored for forward compatibility."""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None):  # type: ignore[no-untyped-def]
        data = data or {}
        names = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in names})  # type: ignore[call-arg]


@dataclass
class OrderAction(_FromDict):
    url: str = ""
    payContent: str = ""
    qrCode: str = ""


@dataclass
class Failure(_FromDict):
    code: int = 0
    msg: str = ""
    message: str = ""


@dataclass
class PaymentPayer(_FromDict):
    """Channel-reported payer in authenticated payment queries and payment webhooks."""

    name: str = ""
    documentNumber: str = ""


@dataclass
class PaymentOrder(_FromDict):
    orderNo: str = ""
    merchantOrderNo: str = ""
    status: str = ""
    currency: str = ""
    amount: str = ""
    paidAmount: str = ""
    country: str = ""
    paymentMethod: str = ""
    action: OrderAction = field(default_factory=OrderAction)
    attach: str = ""
    failure: Failure | None = None
    createdAt: int = 0
    updatedAt: int = 0
    payer: PaymentPayer | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PaymentOrder":
        data = dict(data or {})
        data["action"] = OrderAction.from_dict(data.get("action"))
        data["payer"] = PaymentPayer.from_dict(data["payer"]) if data.get("payer") else None
        data["failure"] = Failure.from_dict(data["failure"]) if data.get("failure") else None
        return super().from_dict(data)  # type: ignore[return-value]


@dataclass
class PayoutOrder(_FromDict):
    orderNo: str = ""
    merchantOrderNo: str = ""
    status: str = ""
    currency: str = ""
    amount: str = ""
    country: str = ""
    payoutMethod: str = ""
    action: OrderAction = field(default_factory=OrderAction)
    attach: str = ""
    failure: Failure | None = None
    createdAt: int = 0
    updatedAt: int = 0

    refundNo: str = ""
    refundAmount: str = ""
    refundTime: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PayoutOrder":
        data = dict(data or {})
        data["action"] = OrderAction.from_dict(data.get("action"))
        data["failure"] = Failure.from_dict(data["failure"]) if data.get("failure") else None
        return super().from_dict(data)  # type: ignore[return-value]


@dataclass
class ReceiptBank(_FromDict):
    ispb: str = ""
    name: str = ""
    branch: str = ""
    account: str = ""
    number: str = ""


@dataclass
class ReceiptAccount(_FromDict):
    bank: ReceiptBank | None = None
    name: str = ""
    taxId: str = ""
    taxType: str = ""
    key: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ReceiptAccount | None":
        if not data:
            return None
        data = dict(data)
        data["bank"] = ReceiptBank.from_dict(data["bank"]) if data.get("bank") else None
        return super().from_dict(data)  # type: ignore[return-value]


@dataclass
class PayoutReceipt(_FromDict):
    orderNo: str = ""
    amount: str = ""
    currency: str = ""
    timestamp: int = 0
    channelTradeNo: str = ""
    sourceAccount: ReceiptAccount | None = None
    destinationAccount: ReceiptAccount | None = None
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PayoutReceipt":
        data = dict(data or {})
        data["sourceAccount"] = ReceiptAccount.from_dict(data.get("sourceAccount"))
        data["destinationAccount"] = ReceiptAccount.from_dict(data.get("destinationAccount"))
        return super().from_dict(data)  # type: ignore[return-value]


@dataclass
class Balance(_FromDict):
    currency: str = ""
    balance: str = ""
    lockBalance: str = ""
    paymentBalance: str = ""
    paymentLockBalance: str = ""
    payoutBalance: str = ""
    payoutLockBalance: str = ""


@dataclass
class USDRate(_FromDict):
    usdRate: str = ""


@dataclass
class PaymentWebhook(_FromDict):
    eventId: str = ""
    orderType: str = ""
    orderNo: str = ""
    merchantOrderNo: str = ""
    status: str = ""
    currency: str = ""
    amount: str = ""
    paidAmount: str = ""
    channelTradeNo: str = ""
    attach: str = ""
    failure: Failure | None = None
    payer: PaymentPayer | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PaymentWebhook":
        data = dict(data or {})
        data["payer"] = PaymentPayer.from_dict(data["payer"]) if data.get("payer") else None
        data["failure"] = Failure.from_dict(data["failure"]) if data.get("failure") else None
        return super().from_dict(data)  # type: ignore[return-value]


@dataclass
class PayoutWebhook(_FromDict):
    eventId: str = ""
    orderType: str = ""
    orderNo: str = ""
    merchantOrderNo: str = ""
    status: str = ""
    currency: str = ""
    amount: str = ""
    channelTradeNo: str = ""
    attach: str = ""
    failure: Failure | None = None

    refundNo: str = ""
    refundAmount: str = ""
    refundTime: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PayoutWebhook":
        data = dict(data or {})
        data["failure"] = Failure.from_dict(data["failure"]) if data.get("failure") else None
        return super().from_dict(data)  # type: ignore[return-value]
