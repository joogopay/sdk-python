# Changelog — python

Versions follow SemVer. Tags are `vX.Y.Z` on this repository.

## v0.1.1 — 2026-09-15

- A malformed idempotency key is now a `RequestError`, like every other failure
  raised before the request goes out. It used to escape as an internal protocol
  error that the package does not export, so callers could neither match it nor
  tell it apart from an unknown outcome on an order that was never sent.
- Indonesia wallet payouts (`ID_DANA` / `ID_OVO` / `ID_GOPAY` / `ID_LINKAJA` /
  `ID_SHOPEEPAY`) validate under their own extra field (`idDana`, `idOvo`, ...),
  same shape as `idBankTransfer`. No API change.
- Documentation: `IDEMPOTENCY_CONFLICT` means the platform has the number but
  cannot return its order, so the caller keeps querying that number instead of
  allocating a new one. `merchant_order_no` is the only key the platform
  deduplicates on; the idempotency key is carried for tracing and takes a fresh
  value per request. `CHANNEL_BUSY`, already in `errors.py`, is now in the error
  table as the one channel error that can be resent without querying first.

## v0.1.0 — 2026-09-14

Initial public release.

- Ed25519 request signing (RFC 9421 HTTP Message Signatures) and X25519
  sealed-box body encryption for POST requests.
- Platform webhook verification: `verify_webhook`, `parse_payment_webhook`, `parse_payout_webhook`.
- Endpoints: `create_payment`, `create_payout`, `query_payment_by_order_no`, `query_payment_by_merchant_order_no`, `query_payout_by_order_no`, `query_payout_by_merchant_order_no`, `get_balance`, `get_usd_rate`, `get_payout_receipt`, `get_payment_checkout`, `submit_payment_trade_no`, `add_payment_extra_info`.
- Local validation before signing: top-level required fields, decimal-string
  amount within `DECIMAL(18,2)`, `https` webhook URL, method-code shape and
  per-currency required extras. Format checks (phone, e-mail, IFSC) stay with
  the gateway.
- Error taxonomy: `RequestError` (rejected before sending), `TransportError` (sent or possibly sent, no response), `APIError` (gateway business error), `ResponseError` (non-envelope response).
- Amounts, balances, fees and rates are decimal strings; idempotency key
  support.
