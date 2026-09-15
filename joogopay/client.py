"""Merchant API client.

HTTP goes through the standard library; the only third-party dependency is PyNaCl.
"""

from __future__ import annotations

import base64
import http.client
import json
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from . import _protocol as p
from . import _request as rq
from . import types as t
from ._validate import (
    validate_create_common,
    validate_path_order_no,
    validate_payment_method,
    validate_payout_method,
)
from .errors import (
    APIError,
    ConfigError,
    RequestError,
    ResponseError,
    ResponseTooLargeError,
    WebhookError,
    TransportError,
)

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RESPONSE_BYTES = 8 << 20
DEFAULT_USER_AGENT = "merchant-sdk-python"
DEFAULT_ACCEPT_LANGUAGE = "en-US"

ED25519_PRIVATE_KEY_SIZES = (32, 64)


def _decode_key(value: str, sizes: tuple[int, ...], what: str) -> bytes:
    try:
        raw = base64.b64decode((value or "").strip(), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"sdk: invalid {what}") from exc
    if len(raw) not in sizes:
        raise ConfigError(f"sdk: invalid {what}")
    return raw


def _validated_write(key, builder):
    """Rejecting a malformed idempotency key is a pre-send failure like any other
    build failure, so it runs inside _build and surfaces as RequestError."""

    def call(**kwargs):
        p.validate_idempotency_key(key)
        return builder(**kwargs)

    return call


def _build(builder):
    """Sealing and signing happen before the request is sent, so a protocol failure
    there is a request error rather than an unknown outcome."""

    def call(**kwargs):
        try:
            return builder(**kwargs)
        except p.ProtocolError as exc:
            raise RequestError(f"sdk: build signed request: {exc}") from exc

    return call


def _encode_body(body: dict[str, Any]) -> bytes:
    """Serialisation happens before signing, so a failure here is a request error, never a transport one."""
    try:
        return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RequestError(f"sdk: marshal request body: {exc}") from exc


class Client:
    """Merchant open API client.

    Callers keep the configuration, build requests and call methods; signing,
    digest and body encryption happen here, so callers never touch
    Signature-Input, Content-Digest or the envelope.
    """

    def __init__(
        self,
        *,
        base_url: str,
        access_key: str,
        merchant_private_key_base64: str,
        platform_body_key_id: str,
        platform_body_public_key_base64: str,
        platform_webhook_public_keys: dict[str, str],
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        accept_language: str = DEFAULT_ACCEPT_LANGUAGE,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        _now: Any = None,  # clock injection for tests
    ) -> None:
        """base_url is scheme and host only, https; a path is rejected because the
        SDK appends the endpoint path itself.

        merchant_private_key_base64 takes either form of Ed25519 private key: the
        32-byte seed libsodium and OpenSSL hand out, or the 64-byte seed plus
        public key.

        platform_body_key_id names which platform key seals the request body and
        travels in the envelope so the gateway knows which private key opens it;
        it must name the key given in platform_body_public_key_base64, which is
        X25519, not the Ed25519 webhook key.

        platform_webhook_public_keys maps key id to platform Ed25519 public key
        and verifies webhook signatures, the opposite direction. The webhook names
        its key id, so this holds every key the platform may currently sign with;
        during a rotation that is two. Required even without webhooks.
        """
        base_url = (base_url or "").strip()
        if not base_url:
            raise ConfigError("sdk: base_url is required")
        parts = urlsplit(base_url)
        if parts.scheme.lower() != "https" or not parts.netloc or parts.query or parts.fragment:
            raise ConfigError("sdk: base_url must be an absolute origin URL")
        if parts.path not in ("", "/"):
            raise ConfigError("sdk: base_url must not contain a path")

        if not (access_key or "").strip():
            raise ConfigError("sdk: access_key is required")
        if not (platform_body_key_id or "").strip():
            raise ConfigError("sdk: platform_body_key_id is required")
        if not platform_webhook_public_keys:
            raise ConfigError("sdk: platform_webhook_public_keys is required")

        self._base_url = base_url.rstrip("/")
        self._access_key = access_key.strip()
        self._merchant_private_key = _decode_key(
            merchant_private_key_base64, ED25519_PRIVATE_KEY_SIZES, "merchant Ed25519 private key"
        )
        self._body_key_id = platform_body_key_id.strip()
        self._body_public_key = _decode_key(
            platform_body_public_key_base64,
            (p.X25519_PUBLIC_KEY_SIZE,),
            "platform X25519 public key",
        )
        self._webhook_keys = {
            (key_id or "").strip(): _decode_key(
                value, (p.ED25519_PUBLIC_KEY_SIZE,), "platform webhook Ed25519 public key"
            )
            for key_id, value in platform_webhook_public_keys.items()
        }
        if "" in self._webhook_keys:
            raise ConfigError("sdk: platform webhook key id must not be empty")

        self._timeout = timeout
        self._user_agent = user_agent or DEFAULT_USER_AGENT
        self._accept_language = accept_language or DEFAULT_ACCEPT_LANGUAGE
        self._max_response_bytes = max_response_bytes
        self._now = _now or (lambda: int(time.time()))

    def create_payment(
        self, req: t.CreatePaymentReq, *, idempotency_key: str | None = None
    ) -> t.PaymentOrder:
        body = req.to_dict()
        validate_create_common(body)
        validate_payment_method(body.get("currency", ""), body.get("paymentMethod"))
        data = self._write("/api/v1/payments", body, idempotency_key)
        return t.PaymentOrder.from_dict(data)

    def create_payout(
        self, req: t.CreatePayoutReq, *, idempotency_key: str | None = None
    ) -> t.PayoutOrder:
        body = req.to_dict()
        validate_create_common(body)
        validate_payout_method(body.get("currency", ""), body.get("payoutMethod"))
        data = self._write("/api/v1/payouts", body, idempotency_key)
        return t.PayoutOrder.from_dict(data)

    def query_payment_by_order_no(self, order_no: str) -> t.PaymentOrder:
        return t.PaymentOrder.from_dict(self._read("/api/v1/payments", {"orderNo": order_no}))

    def query_payment_by_merchant_order_no(self, merchant_order_no: str) -> t.PaymentOrder:
        return t.PaymentOrder.from_dict(
            self._read("/api/v1/payments", {"merchantOrderNo": merchant_order_no})
        )

    def query_payout_by_order_no(self, order_no: str) -> t.PayoutOrder:
        return t.PayoutOrder.from_dict(self._read("/api/v1/payouts", {"orderNo": order_no}))

    def query_payout_by_merchant_order_no(self, merchant_order_no: str) -> t.PayoutOrder:
        return t.PayoutOrder.from_dict(
            self._read("/api/v1/payouts", {"merchantOrderNo": merchant_order_no})
        )

    def get_payout_receipt(self, order_no: str) -> t.PayoutReceipt:
        order_no = validate_path_order_no(order_no)
        path = f"/api/v1/payouts/{quote(order_no, safe='')}/receipt"
        return t.PayoutReceipt.from_dict(self._read(path, None))

    def get_balance(self, currency: str) -> t.Balance:
        return t.Balance.from_dict(self._read("/api/v1/balances", {"currency": currency}))

    def get_usd_rate(self, currency: str, pay_method: str) -> t.USDRate:
        return t.USDRate.from_dict(
            self._read("/api/v1/usd-rates", {"currency": currency, "payMethod": pay_method})
        )

    def get_payment_checkout(self, order_no: str) -> dict[str, Any]:
        """Hosted checkout public query: unsigned and unencrypted."""
        return self._public_get("/api/v1/payment/checkout", {"orderNo": order_no})

    def submit_payment_trade_no(self, order_no: str, trade_no: str) -> dict[str, Any]:
        """Report the upstream transaction number (UTR) the payer entered on the
        hosted checkout so the platform can match the transfer to the order.

        Unsigned and unencrypted, like the checkout query.

        Not raising does not mean accepted: a refusal also returns HTTP 200 with
        envelope code 200. The outcome is data["status"] (1 accepted / 0 refused,
        with "message" giving the reason, e.g. rate limiting).
        """
        no, trade = (order_no or "").strip(), (trade_no or "").strip()
        if not no or not trade:
            raise RequestError("sdk: invalid query parameter")
        return self._public_post("/api/v1/payment/submitTradeNo", {"orderNo": no, "tradeNo": trade})

    def add_payment_extra_info(
        self, order_no: str, pay_method: str = "", extra: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Complete payer details for an order created without them; only then
        does the platform place the order with the channel.

        pay_method / extra may be omitted when the order already carries them.
        Unsigned and unencrypted; data["status"] means the same as in
        submit_payment_trade_no.
        """
        no = (order_no or "").strip()
        if not no:
            raise RequestError("sdk: invalid query parameter")
        body: dict[str, Any] = {"orderNo": no}
        method = (pay_method or "").strip()
        if method:
            body["payMethod"] = method
        if extra:
            body["extra"] = extra
        return self._public_post("/api/v1/payment/addExtraInfo", body)

    def verify_webhook(self, *, method: str, path: str, headers: dict[str, str], body: bytes,
                       raw_query: str = "") -> bytes:
        """Verify a platform webhook: shape, digest, event id, time window and
        Ed25519 signature. Returns the raw body."""
        if (method or "").upper() != "POST":
            raise WebhookError("sdk: webhook must be POST")
        get = {k.lower(): v for k, v in headers.items()}.get
        if (get("content-type") or "").strip() != "application/json":
            raise WebhookError("sdk: webhook Content-Type must be application/json")
        if not body or len(body) > p.MAX_WIRE_BODY_BYTES:
            raise WebhookError("sdk: invalid webhook body size")

        digest = get(p.HEADER_CONTENT_DIGEST.lower()) or ""
        if not p.verify_content_digest(body, digest):
            raise WebhookError("sdk: webhook Content-Digest mismatch")

        event_id = (get(p.HEADER_WEBHOOK_EVENT_ID.lower()) or "").strip()
        p.validate_webhook_event_id(event_id)
        try:
            if json.loads(body).get("eventId") != event_id:
                raise WebhookError("sdk: webhook event id mismatch")
        except ValueError as exc:
            raise WebhookError("sdk: invalid webhook body") from exc

        params = p.parse_platform_signature_input(get(p.HEADER_SIGNATURE_INPUT.lower()) or "")
        p.validate_signature_params(params, self._now())
        public_key = self._webhook_keys.get(params.key_id)
        if public_key is None:
            raise WebhookError("sdk: webhook platform key not found")

        signature = p.parse_signature(
            get(p.HEADER_SIGNATURE.lower()) or "", p.SIGNATURE_LABEL_PLATFORM
        )
        base = p.signature_base(
            params, method="POST", path=path, raw_query=raw_query, headers=headers
        )
        p.verify_ed25519(public_key, base, signature)
        return body

    def parse_payment_webhook(self, **kwargs: Any) -> t.PaymentWebhook:
        payload = t.PaymentWebhook.from_dict(json.loads(self.verify_webhook(**kwargs)))
        self._require_webhook_fields(payload, t.WEBHOOK_ORDER_TYPE_PAYMENT)
        return payload

    def parse_payout_webhook(self, **kwargs: Any) -> t.PayoutWebhook:
        payload = t.PayoutWebhook.from_dict(json.loads(self.verify_webhook(**kwargs)))
        self._require_webhook_fields(payload, t.WEBHOOK_ORDER_TYPE_PAYOUT)
        return payload

    @staticmethod
    def _require_webhook_fields(payload: Any, order_type: str) -> None:
        if (
            not payload.eventId
            or payload.orderType != order_type
            or not payload.orderNo
            or not payload.merchantOrderNo
            or not payload.status
        ):
            raise WebhookError("sdk: invalid webhook body")

    def _write(self, path: str, body: dict[str, Any], idempotency_key: str | None) -> Any:
        key = (idempotency_key or p.new_nonce()).strip()
        built = _build(_validated_write(key, rq.build_write))(
            endpoint_url=self._base_url + path,
            access_key=self._access_key,
            idempotency_key=key,
            body_key_id=self._body_key_id,
            body_public_key=self._body_public_key,
            merchant_private_key=self._merchant_private_key,
            body=_encode_body(body),
            nonce=p.new_nonce(),
            now=self._now(),
        )
        return self._send(self._base_url + path, built)

    def _read(self, path: str, query: dict[str, str] | None) -> Any:
        query = {k: v for k, v in (query or {}).items()}
        for key, value in query.items():
            if not (value or "").strip():
                raise RequestError(f"sdk: invalid query parameter: {key}")
        url = self._base_url + path
        if query:
            url += "?" + urlencode(query)
        built = _build(rq.build_read)(
            endpoint_url=url,
            access_key=self._access_key,
            merchant_private_key=self._merchant_private_key,
            nonce=p.new_nonce(),
            now=self._now(),
        )
        return self._send(url, built)

    def _public_get(self, path: str, query: dict[str, str]) -> Any:
        url = self._base_url + path + "?" + urlencode(query)
        return self._send(url, rq.BuiltRequest(method="GET", headers={}))

    def _public_post(self, path: str, body: dict[str, Any]) -> Any:
        raw = _encode_body(body)
        return self._send(
            self._base_url + path,
            rq.BuiltRequest(
                method="POST", headers={"Content-Type": "application/json"}, body=raw
            ),
        )

    def _send(self, url: str, built: rq.BuiltRequest) -> Any:
        request = urllib.request.Request(url, method=built.method)
        for key, value in built.headers.items():
            request.add_header(key, value)
        request.add_header("Accept", "application/json")
        request.add_header("Accept-Language", self._accept_language)
        request.add_header("User-Agent", self._user_agent)
        if built.body:
            request.data = built.body

        limit = self._max_response_bytes + 1
        try:
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                    status, raw = resp.status, resp.read(limit)
            except urllib.error.HTTPError as exc:  # 4xx/5xx bodies are envelopes too
                status, raw = exc.code, exc.read(limit)
        except (OSError, http.client.HTTPException) as exc:
            # URLError, connection reset, read timeout: the request may have reached the platform.
            raise TransportError(f"sdk: send request: {exc}") from exc
        return self._decode(status, raw)

    def _decode(self, http_status: int, raw: bytes) -> Any:
        if len(raw) > self._max_response_bytes:
            raise ResponseTooLargeError("sdk: response body exceeds max_response_bytes")
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict):
                raise ValueError("envelope must be an object")
        except ValueError as exc:
            raise ResponseError(http_status=http_status, raw_body=raw) from exc

        code = envelope.get("code")
        # HTTP 200 with a non-200 envelope code is still a business failure
        if http_status != 200 or code != 200:
            data = envelope.get("data")
            raise APIError(
                http_status=http_status,
                code=code if isinstance(code, int) else 0,
                msg=str(envelope.get("msg") or ""),
                message=str(data.get("message") or "") if isinstance(data, dict) else "",
                trace_id=str(envelope.get("traceId") or ""),
                raw_body=raw,
            )
        data = envelope.get("data")
        # A success envelope always carries the business object; handing back None
        # would let a caller record an order that has no orderNo as successful.
        if not isinstance(data, (dict, list)):
            raise ResponseError(http_status=http_status, raw_body=raw)
        return data
