# JooGoPay SDK for Python

Python SDK for the merchant open API. Signing, digesting and body encryption are
handled by the SDK; merchants never assemble `Signature-Input`, `Content-Digest`
or the sealed box envelope themselves.

## Protocol

[`protocol/`](protocol/) is the source of truth, shared with the Go / JavaScript /
PHP / Java SDKs through one set of test vectors:

| Item | Approach |
| --- | --- |
| Signature | Ed25519 + fixed RFC 9421 profile |
| Digest | RFC 9530 `Content-Digest` (sha-256) |
| POST body | X25519 sealed box envelope; the digest covers the sealed body |
| GET | No encryption, no body; only the public query and access key are signed |
| Webhook | Platform Ed25519 signature, plaintext body |
| Merchant identity | Located by `Merchant-Access-Key` only; signature params carry **no keyId** |

## Installation

```
pip install joogopay
```

Runtime dependency: pynacl. Python 3.10 or newer.

## Configuration

Six values; only the private key is generated on the merchant side, and the
platform never receives it:

| Field | Meaning |
| --- | --- |
| `base_url` | HTTPS platform origin, without `/api/v1` |
| `access_key` | Merchant access key issued by the platform |
| `merchant_private_key_base64` | Merchant Ed25519 private key, **kept on the merchant side only** |
| `platform_body_key_id` | Current platform body key id (per deployment) |
| `platform_body_public_key_base64` | Platform X25519 public key used to seal POST bodies |
| `platform_webhook_public_keys` | Platform webhook Ed25519 public keys, indexed by keyId |

`Client` rejects non-HTTPS base URLs. Synchronous responses remain plaintext JSON
and rely on HTTPS/TLS for confidentiality and integrity.

## Quick start

```python
from joogopay import APIError, Client, CreatePaymentReq, RequestError, ResponseError, TransportError

client = Client(
    base_url="https://panama.joogopay.com",          # production origin; no /api/v1
    access_key="mak_live_xxx",
    merchant_private_key_base64=merchant_private_key,          # merchant Ed25519 private key, base64
    platform_body_key_id="body_20260827_01",
    platform_body_public_key_base64=platform_body_public_key,  # platform X25519 public key, base64
    platform_webhook_public_keys={                             # keyId -> platform Ed25519 public key, base64
        "pwhk_20260827_01": platform_webhook_public_key,
    },
)

order = client.create_payment(CreatePaymentReq(
    merchantOrderNo="M20260101001",
    currency="BRL",
    amount="100.00",                                   # decimal string, never a float
    paymentMethod={"code": "PIX", "pix": {"payerName": "Joao Silva"}},
    webhookUrl="https://merchant.example/webhook/payments",
))
print(order.orderNo, order.status, order.action.url)
```

### Two kinds of failure, opposite handling

| Error | Meaning | Handling |
| --- | --- | --- |
| `RequestError` | Rejected **before it was sent** (local validation, a bad parameter, or a request the SDK could not encode or sign) | Safe to mark failed; fix the request and retry under the same `merchantOrderNo` |
| `TransportError` | Handed to the transport, no usable response (connection failure, timeout, interrupted read) | Outcome unknown; **never mark a payout failed**. Query by `merchantOrderNo`, or resend the identical request under the same number |
| `APIError` | The gateway returned a business error (`msg` / `message` / `trace_id`) | Branch on `msg`. `IDEMPOTENCY_CONFLICT`: the number is taken but the platform could not return its order, query that number and keep querying rather than switching numbers. `CHANNEL_ERROR`: the order may already exist, query by `merchantOrderNo` first and reuse that number only once the query returns `ORDER_NOT_FOUND`. `CHANNEL_BUSY`: refused before the order was created, so resend the same number after a back-off; this is the only channel error that needs no query first |
| `ResponseError` | The gateway or CDN returned something that is not an envelope (HTML 502, ...) | Outcome unknown; query before deciding |
| `ResponseTooLargeError` | A response arrived but exceeded the size limit and was discarded | Outcome unknown; the order was most likely created, query before deciding |
| Anything else | An unexpected error; assume the request may have arrived | Outcome unknown; query before deciding |

**`merchantOrderNo` is the only key that prevents a duplicate order.** A second
create with the same number never creates a second order: the platform answers
with the original order, or with `IDEMPOTENCY_CONFLICT` when it recognises the
number as taken but cannot return that order. The idempotency key travels with the request for tracing and
is **not** a deduplication key.

Two rules follow:

- After an unknown outcome, never allocate a new `merchantOrderNo`. Query the
  existing one, or resend the same request under the same number.
- A resend must carry identical parameters. The platform returns the original
  order without comparing fields, so a changed amount or account silently has no
  effect. To change anything, use a new `merchantOrderNo` and reconcile the
  original order first.

The SDK validates locally before signing (top-level required fields and formats,
method shape and required extras); the rules are defined in
[`protocol/merchant-api.md`](protocol/merchant-api.md#client-side-validation).
Format checks (phone length, e-mail, ...) stay with the gateway on purpose so the
SDK cannot drift from it.

### Next steps

Queries, idempotent retries and webhook verification are covered by the platform
documentation at <https://docs.joogopay.com>; its examples map one to one onto this
SDK. The wire protocol is in
[`protocol/webhook.md`](protocol/webhook.md) and
[`protocol/merchant-api.md`](protocol/merchant-api.md). Key points:

- After a create timeout, query by `merchantOrderNo` first instead of sending a
  new order; a deliberate retry repeats the same call with the same `merchantOrderNo`.
- For webhooks, pass the method, path, headers and the **raw, unparsed body bytes**
  to `client.parse_payment_webhook(method=, path=, headers=, body=)`; the SDK checks
  the digest, event id, time window and Ed25519 signature. Return 2xx once processed
  and deduplicate by `eventId`.

## Amounts

Amounts, fees and rates in requests, responses, webhooks, balances, rates and
receipts are **always decimal strings** such as `"100.00"`. Never use floats.

## Order status

There are exactly six external statuses: `PENDING` `PROCESSING` `SUCCEEDED`
`FAILED` `EXPIRED` `CANCELED`.

## Troubleshooting

| Situation | Action |
| --- | --- |
| Create request timed out | Query by `merchantOrderNo`; do not send a new order |
| Deliberate retry | Call the same method again with the same `merchantOrderNo` and identical parameters; the SDK regenerates the nonce on every request |
| Signature rejected | Check the server clock, the access key, and that the merchant private key matches the public key registered with the platform |
| Body decryption failed | Check that `platform_body_key_id` and the public key belong to the current environment |
| Webhook signature rejected | Check that the webhook key set contains the `keyid` from the header |

## Tests

```
python -m pip install -e '.[dev]'
python -m pytest -q
```

The tests assert directly against the [`protocol/testdata`](protocol/testdata/)
vectors: `Signature-Input`, the signature base and the signature value are compared
byte for byte, and body encryption is verified by opening ciphertext produced by
the reference implementation.
