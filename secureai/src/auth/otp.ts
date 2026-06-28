/**
 * One-time 6-digit codes for email two-factor authentication.
 *
 * A code is generated with cryptographic randomness, hashed (SHA-256 hex,
 * matching the audit chain / api_keys digest-only discipline), and only the
 * hash is ever persisted — the code itself lives only in the email and the
 * caller's memory, exactly like a raw API key. Verification re-hashes the
 * presented code and compares in constant time, so the stored value is useless
 * to anyone who reads the database.
 *
 * Credential discipline (CLAUDE.md §6): SHA-256 only; never log the code; the
 * generator is unbiased (reject-sampling, no modulo bias) so every code is
 * equiprobable across the 10^6 space.
 */

/** Number of decimal digits in a one-time code. */
const CODE_DIGITS = 6
/** Exclusive upper bound on the code's numeric value (10^CODE_DIGITS). */
const CODE_SPACE = 10 ** CODE_DIGITS
/**
 * Largest multiple of {@link CODE_SPACE} that fits in an unsigned 32-bit draw.
 * A draw `>=` this is rejected and re-sampled so the modulo is bias-free: every
 * value in `[0, CODE_SPACE)` maps from exactly `floor(2^32 / CODE_SPACE)` draws.
 */
const REJECTION_CEILING = Math.floor(0x1_0000_0000 / CODE_SPACE) * CODE_SPACE

const textEncoder = new TextEncoder()

/**
 * Generate a uniformly-random 6-digit code as a zero-padded decimal string
 * (e.g. `"042317"`), using {@link crypto.getRandomValues} with rejection
 * sampling so there is NO modulo bias. The loop draws a fresh unsigned 32-bit
 * value until one falls below {@link REJECTION_CEILING}; the rejection
 * probability per draw is below `CODE_SPACE / 2^32 ≈ 0.00023`, so it terminates
 * in expectation in ~1 draw.
 *
 * Time complexity: O(1) expected (geometric draw count). Space complexity: O(1).
 */
export function generateCode(): string {
  const buffer = new Uint32Array(1)
  let draw: number
  do {
    crypto.getRandomValues(buffer)
    // Non-null: the single-element typed array is always populated by the fill.
    draw = buffer[0] as number
  } while (draw >= REJECTION_CEILING)
  return String(draw % CODE_SPACE).padStart(CODE_DIGITS, '0')
}

/**
 * Lowercase-hex SHA-256 of a code string, matching the audit chain's hashing
 * approach (`audit/chain.ts`) and the api_keys digest (`db/accounts.sha256Hex`):
 * `sha256(utf8(code))`, hex-encoded. The stored challenge holds ONLY this hash.
 *
 * Time complexity: O(n) in `code` length. Space complexity: O(n).
 */
export async function hashCode(code: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(code))
  const view = new Uint8Array(digest)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Constant-time equality over two equal-length ASCII strings: returns `false`
 * immediately on a length mismatch (lengths are not secret), otherwise
 * XOR-accumulates every char code so the comparison time does not depend on
 * WHERE the first difference is — defeating timing side-channels on the stored
 * hash. Mirrors the constant-time compares in `auth/password` and `auth/session`.
 *
 * Time complexity: O(n). Space complexity: O(1).
 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

/**
 * Verify a presented code against a stored hash produced by {@link hashCode}.
 * Re-hashes the code and compares the two hex digests in constant time, so the
 * comparison leaks nothing about how close a wrong code was.
 *
 * Time complexity: O(n) in code length (one digest). Space complexity: O(1).
 *
 * @param code - The presented one-time code (caller-validated as 6 digits).
 * @param storedHash - The hex SHA-256 from the `otp_challenges` row.
 * @returns `true` iff the code hashes to `storedHash`.
 */
export async function verifyCode(code: string, storedHash: string): Promise<boolean> {
  const computed = await hashCode(code)
  return constantTimeEquals(computed, storedHash)
}
