-- SecureAI billing layer — Stripe subscriptions and webhook idempotency.
--
-- Two tables back the Pro-tier ($12/mo) billing flow:
--   subscriptions  — one row per user mirroring the Stripe subscription state,
--                    so the tier the Worker grants is auditable against Stripe.
--   webhook_events — append-only dedupe ledger keyed by Stripe's `event.id`. A
--                    webhook is recorded here BEFORE it is acted on, so a replay
--                    (Stripe retries on any non-2xx) is a no-op (CLAUDE.md §2,
--                    idempotency).
--
-- All timestamps are ISO-8601 UTC strings. The user→customer link lives on
-- `users.stripe_customer_id` (migrations/0001_init.sql), already indexed for the
-- O(1) webhook customer lookup; these tables add the subscription mirror and the
-- idempotency guard.

CREATE TABLE IF NOT EXISTS subscriptions (
  user_id            TEXT PRIMARY KEY,
  status             TEXT NOT NULL,
  price_id           TEXT NOT NULL,
  current_period_end TEXT,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS webhook_events (
  event_id   TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  created_at TEXT NOT NULL
);
