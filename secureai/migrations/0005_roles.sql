-- SecureAI role-based access control (RBAC) layer — a granted-role column.
--
-- A single surgical schema addition:
--   users.role — the granted role for an account: 'member' (default) or 'admin'.
--                The OWNER role is NOT stored here: owners are the bootstrap
--                superadmins defined by the SCANNER_ADMIN_EMAILS allowlist, so an
--                owner is always effective-owner regardless of this column and can
--                never be demoted via the API. Only an owner may promote a member
--                to 'admin' or demote an admin back to 'member'.
--                NOT NULL DEFAULT 'member' so every existing and future row reads
--                as a member until an owner grants a higher role.
--                A stored value outside {'member','admin'} is treated as a corrupt
--                record and fails closed to 'member' on read (never trusted).

ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
