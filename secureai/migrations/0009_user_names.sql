-- SecureAI user names layer — give an account a human name so the app can greet
-- the person ("Hi Daniel!") instead of echoing their email.
--
-- Two nullable columns on `users`:
--   first_name / last_name — the account holder's name, collected at password
--                            registration. NULLable (no DEFAULT, no backfill) so
--                            every pre-existing account, and every API-key signup
--                            (createFreeUser, which has no name step), simply
--                            carries NULL until/unless a name is set. The /api/me
--                            profile read coerces a missing/empty value to null and
--                            the dashboard falls back to the email, so a nameless
--                            account renders exactly as before this feature.
--
-- Names are NOT credentials and NOT unique; they are display-only. They are never
-- logged (CLAUDE.md §6) and never used in an authorization decision.

ALTER TABLE users ADD COLUMN first_name TEXT;
ALTER TABLE users ADD COLUMN last_name TEXT;
