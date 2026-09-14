"""Signed request construction.

build_write / build_read only produce headers and the wire body and never send
anything, so they can be tested directly against the protocol vectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from . import _protocol as p
from .errors import RequestError


@dataclass(frozen=True)
class BuiltRequest:
    method: str
    headers: dict[str, str]
    body: bytes = b""


def build_write(
    *,
    endpoint_url: str,
    access_key: str,
    idempotency_key: str,
    body_key_id: str,
    body_public_key: bytes,
    merchant_private_key: bytes,
    body: bytes,
    nonce: str,
    now: int | None = None,
) -> BuiltRequest:
    """Signed POST; the digest covers the sealed body, not the plaintext."""
    if not (endpoint_url and access_key and idempotency_key and body_key_id and body):
        raise RequestError("sdk: invalid signed request")
    p.validate_idempotency_key(idempotency_key)

    parts = urlsplit(endpoint_url)
    if parts.query:
        raise RequestError("sdk: signed POST query is not allowed")

    wire_body = p.seal_body_envelope(body, body_public_key, body_key_id)
    params = p.new_merchant_write_signature_params(nonce, now)

    headers = {
        "Content-Type": "application/json",
        p.HEADER_CONTENT_ENCRYPTION: p.CONTENT_ENCRYPTION,
        p.HEADER_CONTENT_DIGEST: p.content_digest_sha256(wire_body),
        p.HEADER_IDEMPOTENCY_KEY: idempotency_key,
        p.HEADER_MERCHANT_ACCESS_KEY: access_key,
    }
    headers[p.HEADER_SIGNATURE_INPUT] = p.signature_input_header(params)
    base = p.signature_base(
        params, method="POST", path=parts.path or "/", raw_query="", headers=headers
    )
    headers[p.HEADER_SIGNATURE] = p.sign_ed25519(
        merchant_private_key, p.SIGNATURE_LABEL_MERCHANT, base
    )
    return BuiltRequest(method="POST", headers=headers, body=wire_body)


def build_read(
    *,
    endpoint_url: str,
    access_key: str,
    merchant_private_key: bytes,
    nonce: str,
    now: int | None = None,
) -> BuiltRequest:
    """Signed GET: no body and no idempotency key; the signature covers method, path, query and access key."""
    if not endpoint_url or not access_key:
        raise RequestError("sdk: invalid signed request")

    parts = urlsplit(endpoint_url)
    p.validate_merchant_read_query(parts.query)
    params = p.new_merchant_read_signature_params(nonce, now)

    headers = {p.HEADER_MERCHANT_ACCESS_KEY: access_key}
    headers[p.HEADER_SIGNATURE_INPUT] = p.signature_input_header(params)
    base = p.signature_base(
        params,
        method="GET",
        path=parts.path or "/",
        raw_query=parts.query,
        headers=headers,
    )
    headers[p.HEADER_SIGNATURE] = p.sign_ed25519(
        merchant_private_key, p.SIGNATURE_LABEL_MERCHANT, base
    )
    return BuiltRequest(method="GET", headers=headers)
