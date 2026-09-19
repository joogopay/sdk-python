"""Python SDK for the merchant open API.

Only business methods, DTOs, webhook verification and error types are public.
Signing, digest and body envelope internals live in _protocol / _request and
are not exported.
"""

from .client import Client
from .errors import (
    APIError,
    ConfigError,
    RequestError,
    ResponseError,
    ResponseTooLargeError,
    SDKError,
    TransportError,
    WebhookError,
)
from .types import (
    Balance,
    CreatePaymentReq,
    CreatePayoutReq,
    EXTERNAL_STATUSES,
    Failure,
    OrderAction,
    PaymentOrder,
    PaymentWebhook,
    PayoutOrder,
    PayoutReceipt,
    PayoutWebhook,
    STATUS_CANCELED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_SUCCEEDED,
    USDRate,
)

__version__ = "0.1.3"

__all__ = [
    "Client",
    "CreatePaymentReq", "CreatePayoutReq",
    "PaymentOrder", "PayoutOrder", "PayoutReceipt", "Balance", "USDRate",
    "PaymentWebhook", "PayoutWebhook", "OrderAction", "Failure",
    "SDKError", "ConfigError", "RequestError", "APIError",
    "ResponseError", "ResponseTooLargeError", "TransportError", "WebhookError",
    "STATUS_PENDING", "STATUS_PROCESSING", "STATUS_SUCCEEDED",
    "STATUS_FAILED", "STATUS_EXPIRED", "STATUS_CANCELED", "EXTERNAL_STATUSES",
    "__version__",
]
