"""Assertions against the cross-language protocol vectors.

The vectors are the shared source of truth for every SDK language. A failure
here means the Python implementation disagrees with the protocol: fix the
implementation, not the vectors.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from joogopay import _protocol as p  # noqa: E402

TESTDATA = pathlib.Path(__file__).resolve().parents[1] / "protocol" / "testdata"


def load(rel: str) -> dict:
    return json.loads((TESTDATA / rel).read_text())


def b64(value: str) -> bytes:
    return base64.b64decode(value)


@pytest.mark.parametrize(
    "name,covered",
    [
        ("signature/001-read-query.json", p.MERCHANT_READ_COVERED),
        ("signature/002-write-envelope.json", p.MERCHANT_WRITE_COVERED),
        ("signature/003-read-raw-query-unicode.json", p.MERCHANT_READ_COVERED),
    ],
)
def test_signature_vector(name: str, covered: tuple[str, ...]) -> None:
    v = load(name)
    inp, want = v["input"], v["expected"]

    params = p.SignatureParams(
        label=p.SIGNATURE_LABEL_MERCHANT,
        covered=covered,
        created=1787803200,
        expires=1787803500,
        nonce=inp["nonce"],
    )

    got_input = p.signature_input_header(params)
    assert got_input == want["signatureInput"]
    assert "keyid" not in got_input

    # header values come from the expected signature base so the test invents no data
    headers = _headers_from_base(want["signatureBase"])
    base = p.signature_base(
        params,
        method=inp["method"],
        path=inp["path"],
        raw_query=inp["rawQuery"],
        headers=headers,
    )
    assert base.decode() == want["signatureBase"]

    # Ed25519 is deterministic, so the signature is compared byte for byte
    got_sig = p.sign_ed25519(b64(v["key"]["merchantPrivateKeyBase64"]), p.SIGNATURE_LABEL_MERCHANT, base)
    assert got_sig == want["signature"]

    p.verify_ed25519(
        b64(v["key"]["merchantPublicKeyBase64"]),
        base,
        p.parse_signature(want["signature"], p.SIGNATURE_LABEL_MERCHANT),
    )


def _headers_from_base(signature_base: str) -> dict[str, str]:
    """Recover the header dict from an expected signature base."""
    names = {
        "content-type": "Content-Type",
        "content-encryption": p.HEADER_CONTENT_ENCRYPTION,
        "content-digest": p.HEADER_CONTENT_DIGEST,
        "idempotency-key": p.HEADER_IDEMPOTENCY_KEY,
        "merchant-access-key": p.HEADER_MERCHANT_ACCESS_KEY,
        "webhook-event-id": p.HEADER_WEBHOOK_EVENT_ID,
    }
    headers: dict[str, str] = {}
    for line in signature_base.split("\n"):
        key, _, value = line.partition(": ")
        key = json.loads(key)
        if key in names:
            headers[names[key]] = value
    return headers


def test_signature_input_roundtrip() -> None:
    v = load("signature/001-read-query.json")
    params = p.parse_merchant_read_signature_input(v["expected"]["signatureInput"])
    assert params.nonce == v["input"]["nonce"]
    assert params.key_id == ""
    assert p.signature_input_header(params) == v["expected"]["signatureInput"]


def test_merchant_signature_input_rejects_keyid() -> None:
    tampered = load("signature/001-read-query.json")["expected"]["signatureInput"].replace(
        ';alg="ed25519"', ';keyid="mkey_x";alg="ed25519"'
    )
    with pytest.raises(p.InvalidHeaderError):
        p.parse_merchant_read_signature_input(tampered)


@pytest.mark.parametrize(
    "name,covered",
    [
        ("signature/001-read-query.json", p.MERCHANT_READ_COVERED),
        ("signature/002-write-envelope.json", p.MERCHANT_WRITE_COVERED),
    ],
)
def test_seed_private_key_equals_full_key(name: str, covered: tuple[str, ...]) -> None:
    """A 32-byte seed and the 64-byte private key must produce the same signature.

    libsodium / OpenSSL hand merchants the seed while the vectors carry the
    64-byte form, so the vector tests alone cannot catch an SDK that accepts
    only one of them.
    """
    v = load(name)
    seed = b64(v["key"]["merchantPrivateKeySeedBase64"])
    full = b64(v["key"]["merchantPrivateKeyBase64"])
    assert len(seed) == 32
    assert len(full) == 64
    assert full[:32] == seed

    params = p.SignatureParams(
        label=p.SIGNATURE_LABEL_MERCHANT,
        covered=covered,
        created=1787803200,
        expires=1787803500,
        nonce=v["input"]["nonce"],
    )
    base = p.signature_base(
        params,
        method=v["input"]["method"],
        path=v["input"]["path"],
        raw_query=v["input"]["rawQuery"],
        headers=_headers_from_base(v["expected"]["signatureBase"]),
    )
    assert p.sign_ed25519(seed, p.SIGNATURE_LABEL_MERCHANT, base) == v["expected"]["signature"]
    assert p.sign_ed25519(full, p.SIGNATURE_LABEL_MERCHANT, base) == v["expected"]["signature"]


def test_client_accepts_seed_and_full_private_key() -> None:
    from joogopay import Client

    v = load("signature/001-read-query.json")
    for key in (v["key"]["merchantPrivateKeySeedBase64"], v["key"]["merchantPrivateKeyBase64"]):
        Client(
            base_url="https://api.example.com",
            access_key=v["input"]["accessKey"],
            merchant_private_key_base64=key,
            platform_body_key_id="bodykey_1",
            platform_body_public_key_base64=base64.b64encode(bytes(32)).decode(),
            platform_webhook_public_keys={"whk_1": v["key"]["merchantPublicKeyBase64"]},
        )


def test_bodycrypt_vector_open() -> None:
    v = load("bodycrypt/001-sealed-box.json")
    wire = json.dumps(v["envelope"], separators=(",", ":")).encode()

    assert p.peek_body_envelope_key_id(wire) == v["keyId"]

    plaintext, key_id = p.open_body_envelope(
        wire,
        b64(v["platformBodyPublicKeyBase64"]),
        b64(v["platformBodyPrivateKeyBase64"]),
    )
    assert plaintext == b64(v["plaintextBase64"])
    assert key_id == v["keyId"]

    with pytest.raises(p.InvalidEnvelopeError):
        p.open_body_envelope(wire, bytes([0x44]) * 32, bytes([0x44]) * 32)

    ciphertext = bytearray(b64(v["envelope"]["ciphertext"]))
    ciphertext[-1] ^= 0x01
    tampered_envelope = dict(v["envelope"], ciphertext=base64.b64encode(ciphertext).decode())
    tampered_wire = json.dumps(tampered_envelope, separators=(",", ":")).encode()
    with pytest.raises(p.InvalidEnvelopeError):
        p.open_body_envelope(
            tampered_wire,
            b64(v["platformBodyPublicKeyBase64"]),
            b64(v["platformBodyPrivateKeyBase64"]),
        )


def test_bodycrypt_roundtrip() -> None:
    """Sealed box ciphertext differs on every call, so sealing is verified by a round trip."""
    v = load("bodycrypt/001-sealed-box.json")
    plaintext = b64(v["plaintextBase64"])

    wire = p.seal_body_envelope(plaintext, b64(v["platformBodyPublicKeyBase64"]), v["keyId"])
    envelope = json.loads(wire)
    assert envelope["version"] == 1
    assert envelope["alg"] == p.CONTENT_ENCRYPTION
    assert envelope["keyId"] == v["keyId"]

    got, key_id = p.open_body_envelope(
        wire, b64(v["platformBodyPublicKeyBase64"]), b64(v["platformBodyPrivateKeyBase64"])
    )
    assert got == plaintext
    assert key_id == v["keyId"]


def test_bodycrypt_rejects_tampered_envelope() -> None:
    v = load("bodycrypt/001-sealed-box.json")
    bad = dict(v["envelope"])
    bad["alg"] = "aes-gcm"
    with pytest.raises(p.InvalidEnvelopeError):
        p.decode_body_envelope(json.dumps(bad, separators=(",", ":")).encode())

    extra = dict(v["envelope"], unexpected="x")
    with pytest.raises(p.InvalidEnvelopeError):
        p.decode_body_envelope(json.dumps(extra, separators=(",", ":")).encode())


def test_empty_object_post_vector() -> None:
    v = load("empty-object-post/001-empty-object.json")
    wire = json.dumps(v["envelope"], separators=(",", ":")).encode()
    body_key = v["platformBodyKey"]
    assert v["plaintext"] == "{}"
    assert p.content_digest_sha256(wire) == v["expected"]["contentDigest"]

    plaintext, key_id = p.open_body_envelope(
        wire, b64(body_key["publicKeyBase64"]), b64(body_key["privateKeyBase64"])
    )
    assert plaintext == b"{}"
    assert key_id == body_key["keyId"]

    params = p.SignatureParams(
        label=p.SIGNATURE_LABEL_MERCHANT,
        covered=p.MERCHANT_WRITE_COVERED,
        created=1787803200,
        expires=1787803500,
        nonce=v["input"]["nonce"],
    )
    assert p.signature_input_header(params) == v["expected"]["signatureInput"]
    base = p.signature_base(
        params,
        method=v["input"]["method"],
        path=v["input"]["path"],
        raw_query=v["input"]["rawQuery"],
        headers=_headers_from_base(v["expected"]["signatureBase"]),
    )
    assert base.decode() == v["expected"]["signatureBase"]
    assert p.sign_ed25519(
        b64(v["merchantKey"]["merchantPrivateKeyBase64"]),
        p.SIGNATURE_LABEL_MERCHANT,
        base,
    ) == v["expected"]["signature"]
    with pytest.raises(p.InvalidEnvelopeError):
        p.seal_body_envelope(b"", b64(body_key["publicKeyBase64"]), body_key["keyId"])


def test_webhook_vector() -> None:
    v = load("webhook/001-payment-succeeded.json")
    body = v["body"].encode()
    headers = v["headers"]

    assert p.content_digest_sha256(body) == headers["Content-Digest"]
    assert p.verify_content_digest(body, headers["Content-Digest"])

    params = p.parse_platform_signature_input(headers["Signature-Input"])
    assert params.key_id == v["key"]["platformWebhookKeyId"]  # platform signatures carry keyid

    base = p.signature_base(
        params,
        method=v["input"]["method"],
        path=v["input"]["path"],
        raw_query=v["input"]["rawQuery"],
        headers=headers,
    )
    assert base.decode() == v["expected"]["signatureBase"]

    p.verify_ed25519(
        b64(v["key"]["platformWebhookPublicKeyBase64"]),
        base,
        p.parse_signature(headers["Signature"], p.SIGNATURE_LABEL_PLATFORM),
    )
    with pytest.raises(p.InvalidSignatureError):
        p.verify_ed25519(
            bytes([0x55]) * 32,
            base,
            p.parse_signature(headers["Signature"], p.SIGNATURE_LABEL_PLATFORM),
        )

    p.validate_webhook_event_id(headers["Webhook-Event-Id"])
    assert json.loads(v["body"])["eventId"] == headers["Webhook-Event-Id"]


def test_webhook_rejects_tampered_body() -> None:
    v = load("webhook/001-payment-succeeded.json")
    headers = v["headers"]
    params = p.parse_platform_signature_input(headers["Signature-Input"])
    tampered = v["body"].replace('"100.50"', '"999.00"').encode()

    assert not p.verify_content_digest(tampered, headers["Content-Digest"])

    base = p.signature_base(
        params,
        method=v["input"]["method"],
        path=v["input"]["path"],
        raw_query=v["input"]["rawQuery"],
        headers={**headers, "Content-Digest": p.content_digest_sha256(tampered)},
    )
    with pytest.raises(p.InvalidSignatureError):
        p.verify_ed25519(
            b64(v["key"]["platformWebhookPublicKeyBase64"]),
            base,
            p.parse_signature(headers["Signature"], p.SIGNATURE_LABEL_PLATFORM),
        )


def test_uuid_v4_rules() -> None:
    assert p.valid_uuid_v4("b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a")
    assert p.valid_uuid_v4(p.new_nonce())
    assert not p.valid_uuid_v4("B7754A6C-4A9C-4CF0-B77F-6F2D4B7E5F5A")
    assert not p.valid_uuid_v4("b7754a6c-4a9c-1cf0-b77f-6f2d4b7e5f5a")  # version nibble must be 4
    assert not p.valid_uuid_v4("b7754a6c-4a9c-4cf0-c77f-6f2d4b7e5f5a")  # variant must be 8/9/a/b


def test_webhook_event_id_rules() -> None:
    p.validate_webhook_event_id("evt_00000000000000000000000001")
    for bad in ("evt_0000", "xxx_00000000000000000000000001", "evt_0000000000000000000000000I"):
        with pytest.raises(p.InvalidHeaderError):
            p.validate_webhook_event_id(bad)


def test_read_query_allowlist() -> None:
    p.validate_merchant_read_query("orderNo=P202608270001")
    p.validate_merchant_read_query("currency=BRL&payMethod=PIX")
    for bad in ("secret=1", "orderNo=", "orderNo=a&orderNo=b", "orderNo=%zz"):
        with pytest.raises(p.InvalidHeaderError):
            p.validate_merchant_read_query(bad)


def test_freshness_window() -> None:
    params = p.new_merchant_read_signature_params(p.new_nonce(), now=1787803200)
    assert params.expires - params.created == p.MAX_SIGNATURE_LIFETIME
    p.validate_freshness(params, 1787803200)
    p.validate_freshness(params, 1787803500)
    with pytest.raises(p.ExpiredSignatureError):
        p.validate_freshness(params, 1787803501)
    with pytest.raises(p.ExpiredSignatureError):
        p.validate_freshness(params, 1787803200 - p.MAX_SIGNATURE_LIFETIME - 1)
