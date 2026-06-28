/**
 * Role-based access control (RBAC) primitives, shared by the auth and admin
 * routes so a single definition governs every gate.
 *
 * Three roles, ordered by privilege: `owner` > `admin` > `member`.
 *   - OWNERS are the bootstrap superadmins defined by the `SCANNER_ADMIN_EMAILS`
 *     allowlist. An account whose email is in that set is ALWAYS effective-owner,
 *     regardless of its stored `role` column, and can never be demoted via the
 *     API. This is the immovable root of trust.
 *   - ADMIN / MEMBER are the assignable, DB-backed roles. An owner may promote a
 *     member to `admin` or demote an admin to `member`; those are the only two
 *     values {@link parseAssignableRole} accepts and {@link setUserRole} writes.
 *
 * Fail-closed discipline (CLAUDE.md §6): the stored role column is never trusted.
 * A value outside the assignable allowlist is a corrupt record and reads as the
 * least-privileged `member`, so a bad write or a manual DB edit can only ever
 * REDUCE privilege, never grant it.
 */

/** The three effective roles, ordered least- to most-privileged conceptually. */
export type Role = 'member' | 'admin' | 'owner'

/** The roles an owner may grant via the API (owner is never assignable). */
export type AssignableRole = 'member' | 'admin'

/**
 * The allowlist of assignable role values, as an O(1) membership set. `owner` is
 * deliberately ABSENT — it is conferred only by the email allowlist, never by a
 * write, so the role-change endpoint can never mint an owner.
 */
export const ASSIGNABLE_ROLES: ReadonlySet<string> = new Set<AssignableRole>([
  'member',
  'admin',
])

/**
 * Coerce a stored `role` column into the validated {@link AssignableRole} union,
 * failing closed to the least-privileged `member` on anything unrecognized
 * (`null`, a non-string, or a value outside the allowlist — including a stored
 * literal `'owner'`, which must never be honored from the column).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function parseStoredRole(value: unknown): AssignableRole {
  return typeof value === 'string' && ASSIGNABLE_ROLES.has(value)
    ? (value as AssignableRole)
    : 'member'
}

/**
 * Validate a caller-supplied role value against the assignable allowlist, or
 * `null` when it is not one of {`admin`, `member`}. Used by the role-change
 * endpoint to reject (422) anything an owner is not allowed to assign — notably
 * `owner` itself, which is never assignable.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function parseAssignableRole(value: unknown): AssignableRole | null {
  return typeof value === 'string' && ASSIGNABLE_ROLES.has(value)
    ? (value as AssignableRole)
    : null
}

/**
 * Resolve the EFFECTIVE role of an account from its email and stored role
 * column: `owner` when the (lowercased) email is in the owner allowlist,
 * otherwise the validated stored role (fail-closed to `member`). The allowlist
 * always wins, so an owner is an owner even if its column says `member`.
 *
 * Time complexity: O(1) — one set membership test. Space complexity: O(1).
 *
 * @param email - The account email (any case; lowercased internally).
 * @param roleColumn - The raw `users.role` value as read from the store.
 * @param adminEmails - The lowercased owner allowlist (`config.adminEmails`).
 */
export function effectiveRole(
  email: string,
  roleColumn: unknown,
  adminEmails: ReadonlySet<string>,
): Role {
  if (adminEmails.has(email.toLowerCase())) {
    return 'owner'
  }
  return parseStoredRole(roleColumn)
}

/**
 * Whether a role may VIEW the admin surface (the analytics overview and the
 * members directory): owners and admins, not members.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function canViewAdmin(role: Role): boolean {
  return role === 'owner' || role === 'admin'
}

/**
 * Whether a role may MANAGE other accounts' roles (promote/demote): owners only.
 * An admin can view the directory but cannot change roles.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function canManageRoles(role: Role): boolean {
  return role === 'owner'
}
