# Gennzee Shop Website

A dark, responsive Flask storefront built around the supplied Gennzee SQLite database.

## Important
The included `shop.db` is a working copy of the uploaded database. Do not point the website at the live Termux database while testing.

The website creates its own `web_users`, `web_orders`, and `web_order_items` tables in that copy. Product catalog and stock are read from the existing `products` and `stock` tables.

Products whose names explicitly contain `cracked` are excluded from the storefront.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Razorpay
Copy `.env.example` to `.env` or configure environment variables in your host. Never commit the secret key.

The checkout creates a Razorpay order server-side and verifies the payment signature server-side before reserving/delivering stock.

## Deployment
This project is intentionally a conventional Flask app so it can be moved to a supported Python host. A truly always-on, zero-cost backend is not guaranteed by most free hosting providers; free tiers may sleep or have quotas. For the Razorpay/live-order version, use a host and database/storage whose current free-tier terms meet your needs.

## Production next steps
- Put the website database in a proper production database rather than sharing a live SQLite file between devices.
- Add CSRF protection and rate limiting.
- Add password-reset/email verification.
- Add admin authentication and catalog management.
- Add a proper webhook handler and idempotency checks.
- Decide how website orders should synchronize with the Telegram bot before both systems sell from the same inventory.


## Turso / Render

For Render production, set these environment variables:
- `TURSO_DATABASE_URL=libsql://gennzee-shop-upload-gennzee.aws-ap-south-1.turso.io`
- `TURSO_AUTH_TOKEN` = a private database auth token for `gennzee-shop-upload`
- `SECRET_KEY` = a long random secret

The app uses Turso when both Turso variables are present; otherwise it falls back to local SQLite for local development.
