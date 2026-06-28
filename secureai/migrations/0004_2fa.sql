-- SecureAI email two-factor (2FA) layer — short-lived one-time-code challenges.
--
-- A successful password login opens an `otp_challenges` row instead of issuing a
-- session immediately, but ONLY when an email provider is configured (the gate
-- lives in the route). The row holds the SHA-256 hex of a 6-digit code (the code
-- itself is NEVER stored, mirroring the api_keys digest-only discipline), an
-- expiry, and an attempt counter so a brute force is capped.
--
--   id          — crypto.randomUUID() challenge id, returned to the client and
--                 echoed on /api/login/verify and /api/login/resend.
--   user_id     — the account the challenge authenticates (the session subject
--                 minted on success). A new login DELETEs the user's prior
--                 challenges so only the latest code is live.
--   code_hash   — hex SHA-256 of the 6-digit code (never the code).
--   expires_at  — ISO-8601 UTC instant past which the challenge is dead.
--   attempts    — verify attempts so far; at the configured max the challenge is
--                 spent (fail-closed) regardless of the presented code.
--   created_at  — ISO-8601 UTC mint instant.

CREATE TABLE IF NOT EXISTS otp_challenges (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  code_hash  TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

-- A fresh login invalidates a user's prior challenges by user_id; index it so
-- that delete stays O(k) on the user's (tiny) challenge set rather than a scan.
CREATE INDEX IF NOT EXISTS idx_otp_challenges_user_id ON otp_challenges (user_id);
