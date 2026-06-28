/**
 * Offline password-strength policy enforced at registration, BEFORE any network
 * call or PBKDF2 hashing. Two cheap, deterministic checks:
 *   1. Character-class diversity — the password must mix at least
 *      `minCharacterClasses` of {lowercase, uppercase, digit, symbol}, so a long
 *      single-class string (e.g. all-lowercase) is rejected.
 *   2. Common-password denylist — the candidate must not be one of the
 *      ubiquitous choices in `rules/commonPasswords.ts` (compared
 *      case-insensitively).
 *
 * Minimum LENGTH is enforced upstream by the register Zod schema
 * (`MIN_PASSWORD_LENGTH`), so it is not re-checked here. This layer is the
 * deterministic complement to the online HIBP breach check
 * (`auth/breachCheck.ts`), which catches passwords leaked in real breaches.
 *
 * The result is a typed assessment, never a throw: a weak password is a caller
 * decision (422 at the route), not a server fault.
 */

import { COMMON_PASSWORDS } from '../rules/commonPasswords'

/** The four character classes diversity is measured over. */
const LOWERCASE = /[a-z]/
const UPPERCASE = /[A-Z]/
const DIGIT = /[0-9]/
// Anything that is not a letter or digit counts as a symbol (Unicode-aware via
// the negation, so spaces and punctuation both qualify).
const SYMBOL = /[^A-Za-z0-9]/

/** Lowercased denylist set for O(1) membership tests. */
const DENYLIST: ReadonlySet<string> = new Set(COMMON_PASSWORDS.map((p) => p.toLowerCase()))

/** A password-policy verdict: `ok` true, or false with a user-facing `reason`. */
export interface PasswordAssessment {
  readonly ok: boolean
  readonly reason?: string
}

/** Count how many of the four character classes appear in `password`. */
function characterClassCount(password: string): number {
  let classes = 0
  if (LOWERCASE.test(password)) classes += 1
  if (UPPERCASE.test(password)) classes += 1
  if (DIGIT.test(password)) classes += 1
  if (SYMBOL.test(password)) classes += 1
  return classes
}

/**
 * Assess a plaintext password against the offline policy. Returns `{ ok: true }`
 * when it passes, or `{ ok: false, reason }` with a message safe to show the
 * user. The denylist check is case-insensitive.
 *
 * Time complexity: O(n) in the password length (regex scans + one set lookup).
 * Space complexity: O(1).
 *
 * @param password - The plaintext candidate (already length-validated upstream).
 * @param minCharacterClasses - Minimum distinct classes required (1..4).
 */
export function assessPasswordStrength(
  password: string,
  minCharacterClasses: number,
): PasswordAssessment {
  if (DENYLIST.has(password.toLowerCase())) {
    return { ok: false, reason: 'this password is too common; choose a less predictable one' }
  }
  if (characterClassCount(password) < minCharacterClasses) {
    return {
      ok: false,
      reason:
        `password must include at least ${minCharacterClasses} of: ` +
        'lowercase, uppercase, number, symbol',
    }
  }
  return { ok: true }
}
