-- SecureAI email-verification-at-signup layer — gate an account on proven email
-- control before it becomes usable.
--
-- A single surgical schema addition:
--   users.email_verified — whether the account has proven control of its email.
--                          NOT NULL DEFAULT 0 so a freshly INSERTed account that
--                          does NOT set the column is UNVERIFIED until a 2FA code
--                          is verified (handleRegister opens that challenge when
--                          an email provider is configured, and /api/login/verify
--                          flips this to 1). Both auth paths fail closed on 0: an
--                          UNVERIFIED account authenticates via NEITHER its API
--                          key (findUserByApiKey filters on = 1) NOR its session
--                          cookie (the middleware re-checks and downgrades to
--                          anonymous), so it has no working credential.
--
-- The backfill grandfathers every account that predates this feature: existing
-- rows are set to 1 so no live key or session is invalidated by the rollout. The
-- API-key signup path (createFreeUser) and password-register without a provider
-- both INSERT email_verified = 1 explicitly — they have no email step, so the
-- account is verified at creation.

ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;

-- Grandfather every pre-existing account as verified (predates the feature).
UPDATE users SET email_verified = 1;
