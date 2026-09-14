from __future__ import annotations

# Gateway envelope "msg" values; the set is open, unknown values are opaque strings
MSG_UNAUTHORIZED = "UNAUTHORIZED"
MSG_INVALID_FIELD = "INVALID_FIELD"
MSG_UNSUPPORTED_CURRENCY = "UNSUPPORTED_CURRENCY"
MSG_UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD"
MSG_INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
MSG_METHOD_NOT_ENABLED = "METHOD_NOT_ENABLED"
MSG_ORDER_NOT_FOUND = "ORDER_NOT_FOUND"
MSG_IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
MSG_RATE_LIMITED = "RATE_LIMITED"
MSG_SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
MSG_INTERNAL_ERROR = "INTERNAL_ERROR"
MSG_ORDER_REJECTED = "ORDER_REJECTED"
MSG_CHANNEL_ERROR = "CHANNEL_ERROR"
MSG_CHANNEL_BUSY = "CHANNEL_BUSY"


class SDKError(Exception):
    pass


class ConfigError(SDKError):
    """Client configuration is missing or invalid."""


class RequestError(SDKError):
    """The request was rejected before it was sent: local validation or a bad parameter."""


class TransportError(SDKError):
    """No response was obtained after the request left the process (connection failure,
    timeout, interrupted read). The outcome is unknown: query the order before retrying."""


class WebhookError(SDKError):
    """Webhook verification or parsing failed."""


class APIError(SDKError):
    """The gateway returned a valid envelope reporting a business failure."""

    def __init__(
        self,
        *,
        http_status: int,
        code: int,
        msg: str = "",
        message: str = "",
        trace_id: str = "",
        raw_body: bytes = b"",
    ) -> None:
        self.http_status = http_status
        self.code = code
        self.msg = msg
        self.message = message
        self.trace_id = trace_id
        self.raw_body = raw_body
        detail = f" message={message}" if message else ""
        super().__init__(
            f"sdk: http={http_status} code={code} msg={msg} traceId={trace_id}{detail}"
        )


class ResponseError(SDKError):
    """The response is not a valid envelope JSON (HTML error page or plain-text
    502 from the gateway or CDN)."""

    def __init__(self, *, http_status: int, raw_body: bytes = b"") -> None:
        self.http_status = http_status
        self.raw_body = raw_body
        super().__init__(f"sdk: http={http_status} response is not a valid envelope JSON")


class ResponseTooLargeError(SDKError):
    """The response body exceeds max_response_bytes."""
