"""Merchant request signing and platform webhook verification.

The protocol specification (signature, body encryption, webhook) is the source
of truth; cross-language consistency is guaranteed by the shared test vectors.

Depends only on the standard library and PyNaCl.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field

import nacl.exceptions
import nacl.public
import nacl.signing

from .errors import SDKError

HEADER_MERCHANT_ACCESS_KEY = "Merchant-Access-Key"
HEADER_WEBHOOK_EVENT_ID = "Webhook-Event-Id"
HEADER_CONTENT_ENCRYPTION = "Content-Encryption"
HEADER_CONTENT_DIGEST = "Content-Digest"
HEADER_IDEMPOTENCY_KEY = "Idempotency-Key"
HEADER_SIGNATURE_INPUT = "Signature-Input"
HEADER_SIGNATURE = "Signature"

SIGNATURE_LABEL_MERCHANT = "merchant"
SIGNATURE_LABEL_PLATFORM = "platform"
SIGNATURE_ALG_ED25519 = "ed25519"
CONTENT_ENCRYPTION = "sealedbox-v1-x25519-xsalsa20poly1305"

MAX_PLAIN_BODY_BYTES = 1 << 20
MAX_WIRE_BODY_BYTES = 2 << 20
MAX_SIGNATURE_LIFETIME = 300  # seconds
X25519_PUBLIC_KEY_SIZE = 32
X25519_PRIVATE_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
ED25519_PUBLIC_KEY_SIZE = 32

# Fixed by the protocol; tuple order is the signature base order
MERCHANT_WRITE_COVERED = (
    "@method",
    "@path",
    "content-type",
    "content-encryption",
    "content-digest",
    "idempotency-key",
    "merchant-access-key",
)
MERCHANT_READ_COVERED = (
    "@method",
    "@path",
    "@query",
    "merchant-access-key",
)
PLATFORM_COVERED = (
    "@method",
    "@path",
    "@query",
    "content-type",
    "content-digest",
    "webhook-event-id",
)

ALLOWED_READ_QUERY_FIELDS = frozenset({
    "orderNo", "merchantOrderNo", "currency", "payMethod", "status",
    "startTime", "endTime", "page", "pageSize", "consentNo",
    "subscriptionPaymentNo", "planNo", "merchantPlanNo", "merchantCustomerNo",
    "subscriptionNo", "merchantSubscriptionNo", "invoiceNo",
})

_CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class ProtocolError(SDKError):
    """Base class for protocol-level errors."""


class InvalidHeaderError(ProtocolError):
    """Signature headers, request shape or parameters are invalid."""


class InvalidEnvelopeError(ProtocolError):
    """Body envelope is malformed or cannot be decrypted."""


class InvalidSignatureError(ProtocolError):
    """Signature is malformed or verification failed."""


class ExpiredSignatureError(ProtocolError):
    """Signature time window is invalid or has expired."""


@dataclass(frozen=True)
class SignatureParams:
    """Signature parameters of the fixed RFC 9421 profile."""

    label: str
    covered: tuple[str, ...]
    created: int
    expires: int
    nonce: str
    alg: str = SIGNATURE_ALG_ED25519
    key_id: str = ""  # only platform webhooks carry keyid; merchant requests never do


@dataclass(frozen=True)
class BodyEnvelope:
    """Encrypted envelope of a merchant POST wire body."""

    version: int
    alg: str
    key_id: str
    ciphertext: str

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "alg": self.alg,
                "keyId": self.key_id,
                "ciphertext": self.ciphertext,
            },
            separators=(",", ":"),
        ).encode()


def new_merchant_write_signature_params(nonce: str, now: int | None = None) -> SignatureParams:
    created = int(time.time()) if now is None else int(now)
    return SignatureParams(
        label=SIGNATURE_LABEL_MERCHANT,
        covered=MERCHANT_WRITE_COVERED,
        created=created,
        expires=created + MAX_SIGNATURE_LIFETIME,
        nonce=nonce,
    )


def new_merchant_read_signature_params(nonce: str, now: int | None = None) -> SignatureParams:
    created = int(time.time()) if now is None else int(now)
    return SignatureParams(
        label=SIGNATURE_LABEL_MERCHANT,
        covered=MERCHANT_READ_COVERED,
        created=created,
        expires=created + MAX_SIGNATURE_LIFETIME,
        nonce=nonce,
    )


def new_platform_signature_params(key_id: str, nonce: str, now: int | None = None) -> SignatureParams:
    created = int(time.time()) if now is None else int(now)
    return SignatureParams(
        label=SIGNATURE_LABEL_PLATFORM,
        covered=PLATFORM_COVERED,
        created=created,
        expires=created + MAX_SIGNATURE_LIFETIME,
        nonce=nonce,
        key_id=key_id,
    )


def new_nonce() -> str:
    return str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))


def _quote(value: str) -> str:
    """Protocol values are ASCII without escapes, so JSON quoting yields the RFC 9421 form."""
    return json.dumps(value, ensure_ascii=False)


def signature_input_value(params: SignatureParams) -> str:
    """The Signature-Input value after the label; also the @signature-params line of the base."""
    components = " ".join(_quote(c) for c in params.covered)
    value = (
        f"({components})"
        f";created={params.created}"
        f";expires={params.expires}"
        f";nonce={_quote(params.nonce)}"
    )
    if params.label == SIGNATURE_LABEL_PLATFORM:
        value += f";keyid={_quote(params.key_id)}"
    return value + f";alg={_quote(params.alg)}"


def signature_input_header(params: SignatureParams) -> str:
    validate_signature_params(params, params.created)
    return f"{params.label}={signature_input_value(params)}"


def _component_value(
    component: str, *, method: str, path: str, raw_query: str, headers: dict[str, str]
) -> str:
    if component == "@method":
        return method
    if component == "@path":
        return path or "/"
    if component == "@query":
        return "?" + raw_query
    name = {
        "content-type": "Content-Type",
        "content-encryption": HEADER_CONTENT_ENCRYPTION,
        "content-digest": HEADER_CONTENT_DIGEST,
        "idempotency-key": HEADER_IDEMPOTENCY_KEY,
        "merchant-access-key": HEADER_MERCHANT_ACCESS_KEY,
        "webhook-event-id": HEADER_WEBHOOK_EVENT_ID,
    }.get(component)
    if name is None:
        raise InvalidHeaderError(f"unknown covered component: {component}")
    value = headers.get(name)
    if value is None:
        lowered = {k.lower(): v for k, v in headers.items()}
        value = lowered.get(name.lower())
    if value is None or not _valid_header_value(value.strip()):
        raise InvalidHeaderError(f"missing or invalid header: {name}")
    return value.strip()


def signature_base(
    params: SignatureParams,
    *,
    method: str,
    path: str,
    raw_query: str = "",
    headers: dict[str, str] | None = None,
) -> bytes:
    """Build the RFC 9421 signature base."""
    if not params.covered:
        raise InvalidHeaderError("empty covered components")
    headers = headers or {}
    lines = [
        f"{_quote(c)}: "
        + _component_value(c, method=method, path=path, raw_query=raw_query, headers=headers)
        for c in params.covered
    ]
    lines.append(f'{_quote("@signature-params")}: {signature_input_value(params)}')
    return "\n".join(lines).encode()


def _valid_header_value(value: str) -> bool:
    return bool(value) and value.strip() == value and "\r" not in value and "\n" not in value


def valid_uuid_v4(value: str) -> bool:
    """Lowercase UUID v4; uppercase hex digits are rejected."""
    if len(value) != 36:
        return False
    for i, ch in enumerate(value):
        if i in (8, 13, 18, 23):
            if ch != "-":
                return False
        elif i == 14:
            if ch != "4":
                return False
        elif i == 19:
            if ch not in "89ab":
                return False
        elif not ("0" <= ch <= "9" or "a" <= ch <= "f"):
            return False
    return True


def validate_idempotency_key(value: str) -> None:
    if not valid_uuid_v4(value):
        raise InvalidHeaderError("Idempotency-Key must be a lowercase UUID v4")


def validate_webhook_event_id(value: str) -> None:
    if not value.startswith("evt_") or len(value) != 30:
        raise InvalidHeaderError("invalid Webhook-Event-Id")
    if any(ch not in _CROCKFORD32 for ch in value[4:]):
        raise InvalidHeaderError("invalid Webhook-Event-Id")


def validate_merchant_read_query(raw_query: str) -> None:
    """A signed GET query may carry only allowed locator fields, one value per key."""
    if not raw_query:
        return
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw_query):
        raise InvalidHeaderError("query contains malformed percent-encoding")
    from urllib.parse import parse_qs

    values = parse_qs(raw_query, keep_blank_values=True, strict_parsing=False)
    for key, items in values.items():
        if key not in ALLOWED_READ_QUERY_FIELDS or len(items) != 1 or not items[0].strip():
            raise InvalidHeaderError(f"query field not allowed: {key}")


def validate_freshness(params: SignatureParams, now: int) -> None:
    if (
        params.created <= 0
        or params.expires <= 0
        or params.expires <= params.created
        or params.expires - params.created > MAX_SIGNATURE_LIFETIME
    ):
        raise ExpiredSignatureError("invalid signature lifetime")
    if now < params.created - MAX_SIGNATURE_LIFETIME or now > params.expires:
        raise ExpiredSignatureError("signature expired")


def validate_signature_params(params: SignatureParams, now: int) -> None:
    if not params.label or params.alg != SIGNATURE_ALG_ED25519 or not valid_uuid_v4(params.nonce):
        raise InvalidHeaderError("invalid signature params")
    if params.label == SIGNATURE_LABEL_PLATFORM:
        if not _valid_header_value(params.key_id):
            raise InvalidHeaderError("platform signature requires keyid")
    elif params.label != SIGNATURE_LABEL_MERCHANT:
        raise InvalidHeaderError("unknown signature label")
    if not _covered_components_allowed(params.label, params.covered):
        raise InvalidHeaderError("covered components not allowed")
    validate_freshness(params, now)


def _covered_components_allowed(label: str, covered: tuple[str, ...]) -> bool:
    if label == SIGNATURE_LABEL_MERCHANT:
        return covered in (MERCHANT_WRITE_COVERED, MERCHANT_READ_COVERED)
    if label == SIGNATURE_LABEL_PLATFORM:
        return covered == PLATFORM_COVERED
    return False


def parse_signature_input(value: str, label: str, covered: tuple[str, ...]) -> SignatureParams:
    prefix = f"{label}=("
    if not value.startswith(prefix):
        raise InvalidHeaderError("bad Signature-Input label")
    closing = value.find(")")
    if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ";":
        raise InvalidHeaderError("bad Signature-Input components")
    raw_components = value[len(prefix):closing].split()
    if len(raw_components) != len(covered):
        raise InvalidHeaderError("covered components mismatch")
    for raw, want in zip(raw_components, covered):
        if json.loads(raw) != want:
            raise InvalidHeaderError("covered components mismatch")

    parts = value[closing + 2:].split(";")
    expected = 5 if label == SIGNATURE_LABEL_PLATFORM else 4
    if len(parts) != expected:
        raise InvalidHeaderError("bad Signature-Input params")
    got: dict[str, str] = {}
    for part in parts:
        key, sep, raw = part.partition("=")
        if not sep or not key or key in got:
            raise InvalidHeaderError("bad Signature-Input params")
        got[key] = raw
    if got.keys() - {"created", "expires", "nonce", "keyid", "alg"}:
        raise InvalidHeaderError("unknown Signature-Input param")
    if "keyid" in got and label != SIGNATURE_LABEL_PLATFORM:
        raise InvalidHeaderError("merchant signature must not carry keyid")
    try:
        return SignatureParams(
            label=label,
            covered=covered,
            created=int(got["created"]),
            expires=int(got["expires"]),
            nonce=json.loads(got["nonce"]),
            alg=json.loads(got["alg"]),
            key_id=json.loads(got["keyid"]) if "keyid" in got else "",
        )
    except (KeyError, ValueError) as exc:
        raise InvalidHeaderError("bad Signature-Input params") from exc


def parse_merchant_write_signature_input(value: str) -> SignatureParams:
    return parse_signature_input(value, SIGNATURE_LABEL_MERCHANT, MERCHANT_WRITE_COVERED)


def parse_merchant_read_signature_input(value: str) -> SignatureParams:
    return parse_signature_input(value, SIGNATURE_LABEL_MERCHANT, MERCHANT_READ_COVERED)


def parse_platform_signature_input(value: str) -> SignatureParams:
    return parse_signature_input(value, SIGNATURE_LABEL_PLATFORM, PLATFORM_COVERED)


def content_digest_sha256(body: bytes) -> str:
    """RFC 9530 Content-Digest value with sha-256."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def verify_content_digest(body: bytes, header: str) -> bool:
    return secrets.compare_digest(header, content_digest_sha256(body))


def _signing_key(private_key: bytes) -> nacl.signing.SigningKey:
    # 64-byte keys are seed||pub; PyNaCl takes only the 32-byte seed
    if len(private_key) == 64:
        return nacl.signing.SigningKey(private_key[:32])
    if len(private_key) == 32:
        return nacl.signing.SigningKey(private_key)
    raise InvalidSignatureError("ed25519 private key must be 32 or 64 bytes")


def sign_ed25519(private_key: bytes, label: str, base: bytes) -> str:
    if not label or not base:
        raise InvalidSignatureError("empty label or signature base")
    signature = _signing_key(private_key).sign(base).signature
    return signature_header(label, signature)


def verify_ed25519(public_key: bytes, base: bytes, signature: bytes) -> None:
    if (
        len(public_key) != ED25519_PUBLIC_KEY_SIZE
        or not base
        or len(signature) != ED25519_SIGNATURE_SIZE
    ):
        raise InvalidSignatureError("invalid ed25519 verify input")
    try:
        nacl.signing.VerifyKey(public_key).verify(base, signature)
    except nacl.exceptions.BadSignatureError as exc:
        raise InvalidSignatureError("signature verification failed") from exc


def signature_header(label: str, signature: bytes) -> str:
    if not _valid_header_value(label) or len(signature) != ED25519_SIGNATURE_SIZE:
        raise InvalidSignatureError("invalid signature header input")
    return f"{label}=:" + base64.b64encode(signature).decode() + ":"


def parse_signature(value: str, label: str) -> bytes:
    if not _valid_header_value(label):
        raise InvalidSignatureError("invalid signature label")
    prefix = f"{label}=:"
    if not value.startswith(prefix) or not value.endswith(":"):
        raise InvalidSignatureError("malformed Signature header")
    try:
        signature = base64.b64decode(value[len(prefix):-1], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise InvalidSignatureError("malformed Signature header") from exc
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise InvalidSignatureError("malformed Signature header")
    return signature


def seal_body_envelope(plaintext: bytes, public_key: bytes, key_id: str) -> bytes:
    """Seal a POST plaintext body to the platform X25519 public key; returns the wire body."""
    if not plaintext or len(plaintext) > MAX_PLAIN_BODY_BYTES:
        raise InvalidEnvelopeError("invalid plaintext size")
    if len(public_key) != X25519_PUBLIC_KEY_SIZE or not _valid_header_value(key_id):
        raise InvalidEnvelopeError("invalid platform body key")
    ciphertext = nacl.public.SealedBox(nacl.public.PublicKey(public_key)).encrypt(plaintext)
    return BodyEnvelope(
        version=1,
        alg=CONTENT_ENCRYPTION,
        key_id=key_id,
        ciphertext=base64.b64encode(ciphertext).decode(),
    ).to_json_bytes()


def decode_body_envelope(wire_body: bytes) -> BodyEnvelope:
    if not wire_body or len(wire_body) > MAX_WIRE_BODY_BYTES:
        raise InvalidEnvelopeError("invalid envelope size")
    try:
        raw = json.loads(wire_body)
    except ValueError as exc:
        raise InvalidEnvelopeError("envelope is not valid json") from exc
    if not isinstance(raw, dict) or raw.keys() != {"version", "alg", "keyId", "ciphertext"}:
        raise InvalidEnvelopeError("unexpected envelope fields")
    envelope = BodyEnvelope(
        version=raw["version"], alg=raw["alg"], key_id=raw["keyId"], ciphertext=raw["ciphertext"]
    )
    if (
        envelope.version != 1
        or envelope.alg != CONTENT_ENCRYPTION
        or not _valid_header_value(str(envelope.key_id))
        or not envelope.ciphertext
    ):
        raise InvalidEnvelopeError("invalid envelope")
    try:
        base64.b64decode(envelope.ciphertext, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise InvalidEnvelopeError("invalid envelope ciphertext") from exc
    return envelope


def peek_body_envelope_key_id(wire_body: bytes) -> str:
    try:
        return decode_body_envelope(wire_body).key_id
    except InvalidEnvelopeError:
        return ""


def open_body_envelope(wire_body: bytes, public_key: bytes, private_key: bytes) -> tuple[bytes, str]:
    """Open an envelope with the platform X25519 key pair; returns (plaintext, keyId)."""
    if len(public_key) != X25519_PUBLIC_KEY_SIZE or len(private_key) != X25519_PRIVATE_KEY_SIZE:
        raise InvalidEnvelopeError("invalid platform body key pair")
    envelope = decode_body_envelope(wire_body)
    ciphertext = base64.b64decode(envelope.ciphertext, validate=True)
    try:
        plaintext = nacl.public.SealedBox(nacl.public.PrivateKey(private_key)).decrypt(ciphertext)
    except nacl.exceptions.CryptoError as exc:
        raise InvalidEnvelopeError("envelope decrypt failed") from exc
    if not plaintext or len(plaintext) > MAX_PLAIN_BODY_BYTES:
        raise InvalidEnvelopeError("invalid plaintext size")
    return plaintext, envelope.key_id
