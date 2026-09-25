"""End-to-end client tests: real HTTP shape, response vectors, webhook flow.

A local http.server plays the gateway and checks that what the SDK sends
satisfies the protocol: POST has no query, the body is a sealed box envelope,
Content-Digest covers the envelope, GET has no body and no idempotency key,
and the server can recover the plaintext with the platform private key.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import joogopay as sdk  # noqa: E402
from joogopay import _protocol as p  # noqa: E402

TESTDATA = pathlib.Path(__file__).resolve().parents[1] / "protocol" / "testdata"
SIG = json.loads((TESTDATA / "signature" / "001-read-query.json").read_text())
BODY = json.loads((TESTDATA / "bodycrypt" / "001-sealed-box.json").read_text())
HOOK = json.loads((TESTDATA / "webhook" / "001-payment-succeeded.json").read_text())

CAPTURED: dict = {}
NEXT_RESPONSE: dict = {}


class _Handler(BaseHTTPRequestHandler):
    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        CAPTURED.clear()
        CAPTURED.update(
            method=self.command,
            path=self.path,
            headers={k: v for k, v in self.headers.items()},
            body=self.rfile.read(length) if length else b"",
        )
        payload = NEXT_RESPONSE.get("body", {"code": 200, "msg": "OK", "data": {}})
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(NEXT_RESPONSE.get("status", 200))
        self.send_header("Content-Type", NEXT_RESPONSE.get("ctype", "application/json"))
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = _serve

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def client(server, monkeypatch):
    original_urlopen = urllib.request.urlopen

    def test_urlopen(request, *args, **kwargs):
        transport_request = urllib.request.Request(
            request.full_url.replace("https://", "http://", 1),
            data=request.data,
            headers=dict(request.header_items()),
            method=request.get_method(),
        )
        return original_urlopen(transport_request, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", test_urlopen)
    return sdk.Client(
        base_url=server,
        access_key="mak_live_test",
        merchant_private_key_base64=SIG["key"]["merchantPrivateKeyBase64"],
        platform_body_key_id=BODY["keyId"],
        platform_body_public_key_base64=BODY["platformBodyPublicKeyBase64"],
        platform_webhook_public_keys={
            HOOK["key"]["platformWebhookKeyId"]: HOOK["key"]["platformWebhookPublicKeyBase64"]
        },
    )


def test_malformed_idempotency_key_is_request_error(client):
    """Rejecting the key happens before anything is sent, so it must land in the
    same class as any other pre-send failure; a merchant reading TransportError
    here would query an order that was never created."""
    CAPTURED.clear()
    with pytest.raises(sdk.RequestError):
        client.create_payment(sdk.CreatePaymentReq(
            merchantOrderNo="M1", currency="BRL", amount="1.00",
            paymentMethod={"code": "PIX", "pix": {"payerName": "X"}},
            webhookUrl="https://merchant.example/webhook",
        ), idempotency_key="my-key-123")
    assert CAPTURED == {}


def test_unencodable_request_body_is_request_error(client):
    with pytest.raises(sdk.RequestError) as info:
        client.create_payment(sdk.CreatePaymentReq(
            merchantOrderNo="M1", currency="BRL", amount="1.00",
            paymentMethod={"code": "PIX", "pix": {"payerName": object()}},
            webhookUrl="https://merchant.example/webhook",
        ))
    assert not isinstance(info.value, sdk.TransportError)


def test_transport_failure_is_transport_error():
    client = sdk.Client(
        base_url="https://127.0.0.1:9",
        access_key="mak_live_test",
        merchant_private_key_base64=SIG["key"]["merchantPrivateKeyBase64"],
        platform_body_key_id=BODY["keyId"],
        platform_body_public_key_base64=BODY["platformBodyPublicKeyBase64"],
        platform_webhook_public_keys={
            HOOK["key"]["platformWebhookKeyId"]: HOOK["key"]["platformWebhookPublicKeyBase64"]
        },
        timeout=2.0,
    )
    with pytest.raises(sdk.TransportError) as info:
        client.get_balance("BRL")
    assert not isinstance(info.value, sdk.RequestError)


def test_create_payment_wire_shape(client):
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(
        body={"code": 200, "msg": "OK", "data": {"orderNo": "ORD001", "status": "PENDING",
                                                 "amount": "100.00", "currency": "BRL"}}
    )
    order = client.create_payment(
        sdk.CreatePaymentReq(
            merchantOrderNo="M202608270001",
            currency="BRL",
            amount="100.00",
            paymentMethod={"code": "PIX", "pix": {"payerCPF": "12345678901"}},
            webhookUrl="https://merchant.example.com/webhook/payments",
        )
    )
    assert order.orderNo == "ORD001"
    assert order.amount == "100.00"  # decimal string, not a JSON number

    h = {k.lower(): v for k, v in CAPTURED["headers"].items()}
    assert CAPTURED["method"] == "POST"
    assert "?" not in CAPTURED["path"]
    assert h["content-type"] == "application/json"
    assert h["content-encryption"] == p.CONTENT_ENCRYPTION
    assert p.valid_uuid_v4(h["idempotency-key"])
    assert h["merchant-access-key"] == "mak_live_test"
    assert h["signature-input"].startswith("merchant=(")
    assert "keyid" not in h["signature-input"]  # merchant requests never carry keyid
    assert h["signature"].startswith("merchant=:")

    # Content-Digest covers the sealed envelope, not the plaintext
    assert h["content-digest"] == p.content_digest_sha256(CAPTURED["body"])
    envelope = json.loads(CAPTURED["body"])
    assert envelope["alg"] == p.CONTENT_ENCRYPTION
    assert envelope["keyId"] == BODY["keyId"]

    plaintext, key_id = p.open_body_envelope(
        CAPTURED["body"],
        base64.b64decode(BODY["platformBodyPublicKeyBase64"]),
        base64.b64decode(BODY["platformBodyPrivateKeyBase64"]),
    )
    assert key_id == BODY["keyId"]
    assert json.loads(plaintext) == {
        "merchantOrderNo": "M202608270001",
        "currency": "BRL",
        "amount": "100.00",
        "paymentMethod": {"code": "PIX", "pix": {"payerCPF": "12345678901"}},
        "webhookUrl": "https://merchant.example.com/webhook/payments",
    }


def test_idempotency_key_is_reusable(client):
    NEXT_RESPONSE.clear()
    key = p.new_nonce()
    req = sdk.CreatePayoutReq(
        merchantOrderNo="M1", currency="BRL", amount="1.00",
        payoutMethod={"code": "PIX", "pix": {"keyType": "CPF", "key": "12345678901"}},
        webhookUrl="https://m.example.com/w",
    )
    client.create_payout(req, idempotency_key=key)
    first = CAPTURED["headers"]["Idempotency-Key"]
    client.create_payout(req, idempotency_key=key)
    assert first == CAPTURED["headers"]["Idempotency-Key"] == key


def test_read_wire_shape(client):
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(body={"code": 200, "msg": "OK", "data": {"orderNo": "ORD001"}})
    client.query_payment_by_order_no("P202608270001")

    h = {k.lower(): v for k, v in CAPTURED["headers"].items()}
    assert CAPTURED["method"] == "GET"
    assert CAPTURED["path"] == "/api/v1/payments?orderNo=P202608270001"
    assert CAPTURED["body"] == b""
    for absent in ("content-type", "content-encryption", "content-digest", "idempotency-key"):
        assert absent not in h
    assert "keyid" not in h["signature-input"]


def test_read_rejects_blank_query(client):
    with pytest.raises(sdk.RequestError):
        client.query_payment_by_order_no("   ")


def test_balance_and_rate_use_target_paths(client):
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(body={"code": 200, "msg": "OK", "data": {"balance": "10.00"}})
    client.get_balance("BRL")
    assert CAPTURED["path"].startswith("/api/v1/balances?")

    NEXT_RESPONSE.update(body={"code": 200, "msg": "OK", "data": {"usdRate": "5.40"}})
    rate = client.get_usd_rate("BRL", "PIX")
    assert CAPTURED["path"].startswith("/api/v1/usd-rates?")
    assert rate.usdRate == "5.40"


def _load_response(name: str) -> dict:
    return json.loads((TESTDATA / "responses" / name).read_text())


def test_response_success_vector(client):
    v = _load_response("001-success-payment-order.json")
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(status=v["httpStatus"], body=v["body"])
    order = client.query_payment_by_order_no("ORD202605190001")
    assert order.orderNo == "ORD202605190001"
    assert order.status == sdk.STATUS_SUCCEEDED
    assert order.action.qrCode == "00020-qr"
    assert isinstance(order.payer, sdk.PaymentPayer)
    assert order.payer.name == "Maria Silva"
    assert order.payer.documentNumber == "01234567890"


@pytest.mark.parametrize("fields, expected", [
    ({}, None),
    ({"payer": None}, None),
    ({"payer": {}}, None),
    ({"payer": {"name": "Maria Silva"}}, sdk.PaymentPayer(name="Maria Silva")),
    ({"payer": {"documentNumber": "01234567890"}}, sdk.PaymentPayer(documentNumber="01234567890")),
])
def test_payment_query_optional_payer(client, fields, expected):
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(body={"code": 200, "data": {"orderNo": "payment-1", **fields}})
    for query in (client.query_payment_by_order_no, client.query_payment_by_merchant_order_no):
        assert query("payment-1").payer == expected


def test_response_api_error_vector(client):
    v = _load_response("002-api-error-order-not-found.json")
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(status=v["httpStatus"], body=v["body"])
    with pytest.raises(sdk.APIError) as exc:
        client.query_payment_by_order_no("missing")
    want = v["expectedFields"]
    assert (exc.value.http_status, exc.value.code) == (want["HTTPStatus"], want["Code"])
    assert (exc.value.msg, exc.value.message) == (want["Msg"], want["Message"])
    assert exc.value.trace_id == want["TraceID"]


def test_response_http200_but_envcode_not_ok(client):
    """HTTP 200 with envelope code != 200 must raise, or a drifted status would pass as success."""
    v = _load_response("003-http-200-envcode-not-ok.json")
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(status=v["httpStatus"], body=v["body"])
    with pytest.raises(sdk.APIError) as exc:
        client.query_payment_by_order_no("drift")
    assert exc.value.http_status == 200 and exc.value.code == 12100099


def test_success_without_data_is_response_error(client):
    # An order object with no orderNo would be recorded as a successful payout.
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(status=200, body=b'{"code":200,"msg":"OK","data":null}', ctype="application/json")
    with pytest.raises(sdk.ResponseError):
        client.query_payment_by_order_no("P1")


def test_response_non_json_vector(client):
    v = _load_response("004-non-json-body.json")
    html = (TESTDATA / "responses" / v["bodyFile"]).read_bytes()
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(status=v["httpStatus"], body=html, ctype="text/html")
    with pytest.raises(sdk.ResponseError) as exc:
        client.query_payment_by_order_no("boom")
    assert exc.value.http_status == v["expectedFields"]["HTTPStatus"]


def test_response_vectors_amounts_are_decimal_strings():
    """Amounts in the response vectors must be decimal strings, never JSON numbers."""
    money_fields = (
        "amount", "paidAmount", "minAmount", "maxAmount", "usdRate",
        "balance", "lockBalance", "paymentBalance", "paymentLockBalance",
        "payoutBalance", "payoutLockBalance",
    )
    for path in sorted((TESTDATA / "responses").glob("*.json")):
        data = (json.loads(path.read_text()).get("body") or {}).get("data")
        if not isinstance(data, dict):
            continue
        for field_name in money_fields:
            if field_name in data:
                assert isinstance(data[field_name], str), (
                    f"{path.name}: {field_name}={data[field_name]!r} must be a decimal string"
                )


def _hook_client(server, now: int = 1787803300, vector=HOOK):
    return sdk.Client(
        base_url=server,
        access_key="mak_live_test",
        merchant_private_key_base64=SIG["key"]["merchantPrivateKeyBase64"],
        platform_body_key_id=BODY["keyId"],
        platform_body_public_key_base64=BODY["platformBodyPublicKeyBase64"],
        platform_webhook_public_keys={
            vector["key"]["platformWebhookKeyId"]: vector["key"]["platformWebhookPublicKeyBase64"]
        },
        _now=lambda: now,
    )


def test_parse_payment_webhook(server):
    hook = _hook_client(server).parse_payment_webhook(
        method=HOOK["input"]["method"], path=HOOK["input"]["path"],
        raw_query=HOOK["input"]["rawQuery"], headers=HOOK["headers"], body=HOOK["body"].encode(),
    )
    assert hook.eventId == HOOK["headers"]["Webhook-Event-Id"]
    assert hook.orderType == "PAYMENT"
    assert hook.status == sdk.STATUS_SUCCEEDED
    assert (hook.amount, hook.paidAmount) == ("100.50", "100.50")
    assert hook.payer is None


def test_parse_payment_webhook_payer(server):
    vector = json.loads((TESTDATA / "webhook" / "002-payment-payer.json").read_text())
    kwargs = dict(
        method=vector["input"]["method"], path=vector["input"]["path"],
        raw_query=vector["input"]["rawQuery"], headers=vector["headers"], body=vector["body"].encode(),
    )
    client = _hook_client(server, vector=vector)
    hook = client.parse_payment_webhook(**kwargs)
    assert hook.payer == sdk.PaymentPayer(name="Maria Silva", documentNumber="01234567890")
    assert (hook.amount, hook.paidAmount) == ("100.50", "100.50")


@pytest.mark.parametrize("field", ["name", "documentNumber"])
@pytest.mark.parametrize("refresh_digest", [False, True])
def test_payment_webhook_rejects_altered_payer(server, field, refresh_digest):
    vector = json.loads((TESTDATA / "webhook" / "002-payment-payer.json").read_text())
    payload = json.loads(vector["body"])
    payload["payer"][field] = "Other Name" if field == "name" else "11234567890"
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = dict(vector["headers"])
    if refresh_digest:
        headers["Content-Digest"] = p.content_digest_sha256(body)
    expected_error = p.InvalidSignatureError if refresh_digest else sdk.WebhookError
    with pytest.raises(expected_error):
        _hook_client(server, vector=vector).parse_payment_webhook(
            method=vector["input"]["method"], path=vector["input"]["path"],
            raw_query=vector["input"]["rawQuery"], headers=headers, body=body,
        )


@pytest.mark.parametrize("fields,expected", [
    ({}, None),
    ({"payer": None}, None),
    ({"payer": {}}, None),
    ({"payer": {"name": "Maria Silva"}}, sdk.PaymentPayer(name="Maria Silva")),
    ({"payer": {"documentNumber": "01234567890"}}, sdk.PaymentPayer(documentNumber="01234567890")),
])
def test_payment_webhook_optional_payer(fields, expected):
    assert sdk.PaymentWebhook.from_dict(fields).payer == expected


def test_webhook_rejects_unknown_key_id(server):
    c = sdk.Client(
        base_url=server, access_key="mak_live_test",
        merchant_private_key_base64=SIG["key"]["merchantPrivateKeyBase64"],
        platform_body_key_id=BODY["keyId"],
        platform_body_public_key_base64=BODY["platformBodyPublicKeyBase64"],
        platform_webhook_public_keys={"wk_other": HOOK["key"]["platformWebhookPublicKeyBase64"]},
        _now=lambda: 1787803300,
    )
    with pytest.raises(sdk.WebhookError, match="platform key not found"):
        c.parse_payment_webhook(
            method=HOOK["input"]["method"], path=HOOK["input"]["path"],
            raw_query=HOOK["input"]["rawQuery"], headers=HOOK["headers"], body=HOOK["body"].encode(),
        )


def test_webhook_rejects_expired_signature(server):
    with pytest.raises(p.ExpiredSignatureError):
        _hook_client(server, now=1787803501).parse_payment_webhook(
            method=HOOK["input"]["method"], path=HOOK["input"]["path"],
            raw_query=HOOK["input"]["rawQuery"], headers=HOOK["headers"], body=HOOK["body"].encode(),
        )


def test_webhook_rejects_wrong_order_type(server):
    with pytest.raises(sdk.WebhookError):
        _hook_client(server).parse_payout_webhook(  # the vector is a PAYMENT event
            method=HOOK["input"]["method"], path=HOOK["input"]["path"],
            raw_query=HOOK["input"]["rawQuery"], headers=HOOK["headers"], body=HOOK["body"].encode(),
        )


def test_webhook_rejects_event_id_mismatch(server):
    headers = dict(HOOK["headers"], **{"Webhook-Event-Id": "evt_0000000000000000000000000Z"})
    with pytest.raises(sdk.WebhookError):
        _hook_client(server).parse_payment_webhook(
            method=HOOK["input"]["method"], path=HOOK["input"]["path"],
            raw_query=HOOK["input"]["rawQuery"], headers=headers, body=HOOK["body"].encode(),
        )


@pytest.mark.parametrize(
    "override",
    [
        {"base_url": ""},
        {"base_url": "http://api.example.com"},
        {"base_url": "ftp://api.example.com"},
        {"base_url": "https://api.example.com/api/v1"},  # no path allowed
        {"base_url": "not-a-url"},
        {"access_key": ""},
        {"merchant_private_key_base64": "bm90LWEta2V5"},
        {"platform_body_key_id": ""},
        {"platform_body_public_key_base64": "c2hvcnQ="},
        {"platform_webhook_public_keys": {}},
    ],
)
def test_config_validation(server, override):
    base = dict(
        base_url=server, access_key="mak_live_test",
        merchant_private_key_base64=SIG["key"]["merchantPrivateKeyBase64"],
        platform_body_key_id=BODY["keyId"],
        platform_body_public_key_base64=BODY["platformBodyPublicKeyBase64"],
        platform_webhook_public_keys={"wk_test_1": HOOK["key"]["platformWebhookPublicKeyBase64"]},
    )
    with pytest.raises(sdk.ConfigError):
        sdk.Client(**{**base, **override})


def test_get_payout_receipt_escapes_path(client):
    """The receipt order number is a path segment and must be percent-encoded
    before it enters the signature base."""
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(
        body={"code": 200, "msg": "OK", "data": {
            "orderNo": "ORD/001", "amount": "100.00", "currency": "BRL",
            "destinationAccount": {"name": "Maria", "bank": {"name": "Itau"}},
        }}
    )
    receipt = client.get_payout_receipt("ORD/001")
    assert CAPTURED["method"] == "GET"
    assert CAPTURED["path"] == "/api/v1/payouts/ORD%2F001/receipt"
    assert "?" not in CAPTURED["path"]
    assert receipt.amount == "100.00"
    assert receipt.destinationAccount.bank.name == "Itau"


def test_get_payout_receipt_rejects_empty_order_no(client):
    with pytest.raises(sdk.RequestError):
        client.get_payout_receipt("")


def test_submit_payment_trade_no_is_plain_json(client):
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE["body"] = {"code": 200, "msg": "OK", "data": {"status": 1, "orderStatus": "PENDING"}}

    got = client.submit_payment_trade_no("P1", "UTR123")

    assert got["status"] == 1
    assert got["orderStatus"] == "PENDING"
    assert CAPTURED["method"] == "POST"
    assert CAPTURED["path"] == "/api/v1/payment/submitTradeNo"
    headers = {k.lower(): v for k, v in CAPTURED["headers"].items()}
    assert headers["content-type"] == "application/json"
    assert "signature" not in headers
    assert "content-encryption" not in headers
    assert json.loads(CAPTURED["body"]) == {"orderNo": "P1", "tradeNo": "UTR123"}


def test_submit_payment_trade_no_refusal_is_not_an_error(client):
    """A refusal also returns HTTP 200 + code 200; not raising does not mean accepted."""
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE["body"] = {
        "code": 200,
        "msg": "OK",
        "data": {"status": 0, "message": "too many requests, please retry later"},
    }

    got = client.submit_payment_trade_no("P1", "UTR123")

    assert got["status"] == 0
    assert "too many requests" in got["message"]


@pytest.mark.parametrize("order_no,trade_no", [("", "UTR"), ("P1", ""), (" ", "UTR"), ("P1", " ")])
def test_submit_payment_trade_no_requires_both(client, order_no, trade_no):
    with pytest.raises(sdk.RequestError):
        client.submit_payment_trade_no(order_no, trade_no)


def test_add_payment_extra_info_omits_optional_fields(client):
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE["body"] = {
        "code": 200,
        "msg": "OK",
        "data": {"status": 1, "orderStatus": "PENDING", "paymentUrl": "https://h5.example/p/1"},
    }

    got = client.add_payment_extra_info("P1", "PK_JAZZCASH", {"mobile": "03001234567"})

    assert got["paymentUrl"] == "https://h5.example/p/1"
    assert CAPTURED["path"] == "/api/v1/payment/addExtraInfo"
    assert json.loads(CAPTURED["body"]) == {
        "orderNo": "P1",
        "payMethod": "PK_JAZZCASH",
        "extra": {"mobile": "03001234567"},
    }

    client.add_payment_extra_info("P1")
    assert json.loads(CAPTURED["body"]) == {"orderNo": "P1"}

    with pytest.raises(sdk.RequestError):
        client.add_payment_extra_info(" ")


# The rule table is generated; these tests guard how it is applied. Half the cases
# assert acceptance: a wrongly rejected valid request can only be fixed by an SDK
# release.


@pytest.mark.parametrize(
    "currency,method,fragment",
    [
        ("BRL", {}, "code is required"),
        (
            "PKR",
            {"code": "PK_JAZZCASH",
             "pkJazzcash": {"mobile": "03001234567"},
             "pkEasypaisa": {"mobile": "03001234567"}},
            "only one method extra",
        ),
        ("PKR", {"code": "PK_JAZZCASH", "pkEasypaisa": {"mobile": "03001234567"}},
         "does not match code"),
        ("PKR", {"code": "PH_GCASH", "phGcash": {"mobile": "09171234567"}},
         "not available for this currency"),
        (
            "IDR",
            {"code": "ID_VA", "idVa": {"accountName": "Budi", "email": "b@example.com", "mobile": "0812"}},
            "extra.bankCode",
        ),
    ],
)
def test_validate_payment_method_rejects(client, currency, method, fragment):
    req = sdk.CreatePaymentReq(
        merchantOrderNo="M1", currency=currency, amount="1.00",
        paymentMethod=method, webhookUrl="https://m.example.com/w",
    )
    with pytest.raises(sdk.RequestError) as exc:
        client.create_payment(req)
    assert fragment in str(exc.value)


@pytest.mark.parametrize(
    "currency,method",
    [
        # PKR / PHP pay-in requires no extra fields; omitting extra entirely is valid
        ("PKR", {"code": "PK_JAZZCASH"}),
        ("PKR", {"code": "PK_JAZZCASH", "pkJazzcash": {"mobile": "03001234567"}}),
        ("PHP", {"code": "PH_GCASH"}),
        (
            "IDR",
            {"code": "ID_VA", "idVa": {"accountName": "Budi", "email": "b@example.com",
                                       "mobile": "0812", "bankCode": "BCA"}},
        ),
        ("XYZ", {"code": "WHATEVER"}),   # currency absent from the table is not blocked
        ("BRL", {"code": "PIX"}),        # no code allowlist for BRL; the code is not checked
    ],
)
def test_validate_payment_method_allows(client, currency, method):
    NEXT_RESPONSE.clear()
    req = sdk.CreatePaymentReq(
        merchantOrderNo="M1", currency=currency, amount="1.00",
        paymentMethod=method, webhookUrl="https://m.example.com/w",
    )
    client.create_payment(req)


def test_validate_payout_conditional_required(client):
    """Required extras differ per method within one currency; flattening them
    would wrongly block IN_UPI."""
    NEXT_RESPONSE.clear()

    def payout(method):
        return sdk.CreatePayoutReq(
            merchantOrderNo="M1", currency="INR", amount="1.00",
            payoutMethod=method, webhookUrl="https://m.example.com/w",
        )

    client.create_payout(payout({
        "code": "IN_UPI",
        "inUpi": {"account": "mary@upi", "name": "Mary", "email": "m@example.com", "mobile": "9871476369"},
    }))

    with pytest.raises(sdk.RequestError):
        client.create_payout(payout({
            "code": "IN_IFSC",
            "inIfsc": {"name": "Mary", "email": "m@example.com", "mobile": "9871476369"},
        }))

    client.create_payout(payout({
        "code": "IN_IFSC",
        "inIfsc": {"account": "123456789", "ifsc": "HDFC0001234",
                   "name": "Mary", "email": "m@example.com", "mobile": "9871476369"},
    }))


IDR_WALLET_PAYOUTS = [
    ("ID_DANA", "idDana", "DANA"), ("ID_OVO", "idOvo", "OVO"), ("ID_GOPAY", "idGopay", "GOPAY"),
    ("ID_LINKAJA", "idLinkaja", "LINKAJA"), ("ID_SHOPEEPAY", "idShopeepay", "SHOPEEPAY"),
]


def idr_wallet_payout(method):
    return sdk.CreatePayoutReq(
        merchantOrderNo="M1", currency="IDR", amount="10000",
        payoutMethod=method, webhookUrl="https://m.example.com/w",
    )


def idr_wallet_extra(wallet):
    # accountNo is the wallet-registered phone number and receives the funds; mobile is a contact number.
    return {"bankCode": wallet, "accountNo": "081234567890", "accountName": "Budi",
            "email": "b@example.com", "mobile": "089999999999"}


@pytest.mark.parametrize("code,field,wallet", IDR_WALLET_PAYOUTS)
def test_validate_payout_idr_wallets_accepted(client, code, field, wallet):
    """The five IDR wallet payouts are accepted under their own extra field."""
    NEXT_RESPONSE.clear()
    client.create_payout(idr_wallet_payout({"code": code, field: idr_wallet_extra(wallet)}))


def test_validate_payout_idr_wallet_extra_must_match_code(client):
    NEXT_RESPONSE.clear()
    with pytest.raises(sdk.RequestError, match="does not match code"):
        client.create_payout(idr_wallet_payout({"code": "ID_DANA", "idOvo": idr_wallet_extra("OVO")}))


def test_validate_payout_idr_wallet_requires_account_no(client):
    """accountNo is required for wallets as well; mobile never stands in for it."""
    NEXT_RESPONSE.clear()
    extra = {**idr_wallet_extra("DANA"), "accountNo": ""}
    with pytest.raises(sdk.RequestError, match="extra.accountNo"):
        client.create_payout(idr_wallet_payout({"code": "ID_DANA", "idDana": extra}))


TESTDATA = pathlib.Path(__file__).resolve().parents[1] / "protocol" / "testdata"
_VALIDATION_REASON_FRAGMENT = {
    "missing_required_field": "required field is empty: {field}",
    "invalid_amount": "amount must be",
    "invalid_webhook_url": "webhookUrl must be",
}


def _validation_cases():
    for path in sorted((TESTDATA / "validation").glob("*.json")):
        vector = json.loads(path.read_text())
        for case in vector["cases"]:
            yield pytest.param(vector, case, id=f"{path.name}/{case['name']}")


@pytest.mark.parametrize("vector,case", list(_validation_cases()))
def test_validation_vectors(client, vector, case):
    """Top-level validation vectors shared by every SDK language. A failure here
    means the Python implementation disagrees with the protocol: fix the
    implementation, not the vectors."""
    NEXT_RESPONSE.clear()
    body = {**vector["base"], **case["override"]}
    if vector["direction"] == "payment":
        call = lambda: client.create_payment(sdk.CreatePaymentReq(**body))  # noqa: E731
    else:
        call = lambda: client.create_payout(sdk.CreatePayoutReq(**body))  # noqa: E731

    if case["expect"] == "accept":
        call()
        return
    with pytest.raises(sdk.RequestError) as exc:
        call()
    fragment = _VALIDATION_REASON_FRAGMENT[case["reason"]].format(field=case.get("field", ""))
    assert fragment in str(exc.value)


@pytest.mark.parametrize("bad", ["", "  ", "\t"])
def test_receipt_rejects_blank_order_no(client, bad):
    with pytest.raises(sdk.RequestError):
        client.get_payout_receipt(bad)


def test_receipt_trims_order_no(client):
    NEXT_RESPONSE.clear()
    client.get_payout_receipt("  P202608270001 ")
    assert CAPTURED["path"].startswith("/api/v1/payouts/P202608270001/receipt")


@pytest.mark.parametrize("account_type", ["CBU", "CVU"])
def test_ars_payout_optional_nullable_address(client, account_type):
    extra = {
        "firstName": "Ana", "lastName": "Perez", "email": "ana@example.com", "phone": "1123456789",
        "documentType": "DNI", "documentNumber": "30123456",
        "accountNo": "0000003100012345678901", "accountType": account_type,
    }

    def request(fields):
        return {
            "merchantOrderNo": "ars-address-001", "currency": "ARS", "amount": "1.00",
            "webhookUrl": "https://merchant.example.com/webhook",
            "payoutMethod": {"code": "BANK_TRANSFER", "bankTransfer": fields},
        }

    NEXT_RESPONSE.clear()
    for address_fields in [{}, {"address": None}, {"address": ""}, {"address": " Av Example 123 "}]:
        body = request({**extra, **address_fields})
        expected = json.loads(json.dumps(body))
        client.create_payout(sdk.CreatePayoutReq(**body))
        plaintext, _ = p.open_body_envelope(
            CAPTURED["body"], base64.b64decode(BODY["platformBodyPublicKeyBase64"]),
            base64.b64decode(BODY["platformBodyPrivateKeyBase64"]),
        )
        assert json.loads(plaintext) == expected
        assert body == expected, "caller input must remain unchanged"

    for address in [1, False, [], {}]:
        CAPTURED.clear()
        with pytest.raises(sdk.RequestError, match="extra.address"):
            client.create_payout(sdk.CreatePayoutReq(**request({**extra, "address": address})))
        assert CAPTURED == {}, "invalid address must fail before HTTP"
    for field in extra:
        missing = dict(extra)
        del missing[field]
        for invalid in [missing] + [{**extra, field: empty} for empty in [None, "", "  "]]:
            CAPTURED.clear()
            with pytest.raises(sdk.RequestError, match=f"extra.{field}"):
                client.create_payout(sdk.CreatePayoutReq(**request(invalid)))
            assert CAPTURED == {}, f"{field} must fail before HTTP"


_USD = json.loads((TESTDATA / "methods" / "001-usd-wallets.json").read_text())


@pytest.mark.parametrize("wallet_request", [_USD["payment"], *_USD["payouts"]])
def test_usd_wallet_contract(client, wallet_request):
    request = wallet_request
    import copy

    NEXT_RESPONSE.clear()
    method_field = "paymentMethod" if "paymentMethod" in request else "payoutMethod"
    method = request[method_field]
    branch = next(key for key in method if key != "code")

    def create(value):
        if method_field == "paymentMethod":
            return client.create_payment(sdk.CreatePaymentReq(**value))
        return client.create_payout(sdk.CreatePayoutReq(**value))

    create(request)
    plaintext, _ = p.open_body_envelope(
        CAPTURED["body"], base64.b64decode(BODY["platformBodyPublicKeyBase64"]),
        base64.b64decode(BODY["platformBodyPrivateKeyBase64"]),
    )
    assert json.loads(plaintext) == request
    last_body = CAPTURED["body"]
    for field in method[branch]:
        for empty in (None, "", "  "):
            invalid = copy.deepcopy(request)
            invalid[method_field][branch][field] = empty
            with pytest.raises(sdk.RequestError):
                create(invalid)
            assert CAPTURED["body"] == last_body, f"{field} must fail before HTTP"
    formats = copy.deepcopy(request)
    for field in method[branch]:
        formats[method_field][branch][field] = "format-is-checked-by-gateway"
    create(formats)


PH_WALLET_PAYOUTS = [("PH_GCASH", "phGcash"), ("PH_MAYA", "phMaya")]


def ph_payout(method):
    return sdk.CreatePayoutReq(
        merchantOrderNo="M1", currency="PHP", amount="100.00",
        payoutMethod=method, webhookUrl="https://m.example.com/w",
    )


def ph_extra():
    return {"accountNo": "09171234567", "accountName": "Juan",
            "email": "j@example.com", "mobile": "09171234567"}


@pytest.mark.parametrize("code,field", PH_WALLET_PAYOUTS)
def test_validate_payout_ph_wallets_need_no_bank_code(client, code, field):
    """One code per wallet works in both directions; the channel derives the wallet."""
    NEXT_RESPONSE.clear()
    client.create_payout(ph_payout({"code": code, field: ph_extra()}))


@pytest.mark.parametrize("code,field", [("PH_DF_BANK", "phDfBank"), ("PH_DF_WALLET", "phDfWallet")])
def test_validate_payout_ph_bank_code_still_required(client, code, field):
    """PH_DF_WALLET is kept for existing integrations; there bankCode names the wallet."""
    NEXT_RESPONSE.clear()
    with pytest.raises(sdk.RequestError, match="extra.bankCode"):
        client.create_payout(ph_payout({"code": code, field: ph_extra()}))


def test_payout_refund_query_and_signed_webhook(client, server):
    response = _load_response("005-payout-refunded.json")
    NEXT_RESPONSE.clear()
    NEXT_RESPONSE.update(status=response["httpStatus"], body=response["body"])
    order = client.query_payout_by_order_no("PO202609240001")
    vector = json.loads((TESTDATA / "webhook" / "003-payout-refunded.json").read_text())
    hook = _hook_client(server, vector=vector).parse_payout_webhook(
        method=vector["input"]["method"], path=vector["input"]["path"],
        raw_query=vector["input"]["rawQuery"], headers=vector["headers"], body=vector["body"].encode(),
    )
    for payload in (order, hook):
        assert payload.status == sdk.STATUS_REFUNDED
        assert payload.refundNo == "R202609240001"
        assert payload.refundAmount == "100.00"
        assert payload.refundTime == 1790208000000
