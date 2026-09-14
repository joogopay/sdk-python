# Changelog — python

Versions follow SemVer. Tags are `vX.Y.Z` on this repository.

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
