/**
 * Password hashing via PBKDF2-HMAC-SHA256 over the Web Crypto API
 * (`crypto.subtle`), which is present in both the Workers runtime and the Node
 * test runtime — so the same code path runs in production and under `vitest`.
 *
 * Credential discipline (CLAUDE.md §6): a plaintext password is NEVER persisted
 * and never logged. {@link hashPassword} derives a salted, high-iteration digest;
 * the salt and iteration count are serialized INTO the stored string so a future
 * cost increase (raising `iterations`) never invalidates already-stored hashes —
 * each hash verifies against its own embedded parameters.
 *
 * Stored format (`$`-delimited, all components ASCII):
 *   `pbkdf2$<iterations>$<saltBase64>$<hashBase64>`
 * The `pbkdf2` tag is an algorithm allowlist guard: a stored string that does not
 * start with it is treated as unverifiable and fails closed.
 */

/** Algorithm tag prefixing every serialized hash; the only accepted scheme. */
const SCHEME_TAG = 'pbkdf2'
/** Field separator in the serialized hash. */
const FIELD_SEPARATOR = '$'
/** Salt length in bytes (128-bit), generated fresh per password. */
const SALT_BYTES = 16
/** Derived-key length in bits (256-bit, one SHA-256 block). */
const DERIVED_KEY_BITS = 256
/** The PBKDF2 underlying PRF. */
const PRF_HASH = 'SHA-256'
/** Number of `$`-delimited fields in a well-formed serialized hash. */
const SERIALIZED_FIELD_COUNT = 4

const textEncoder = new TextEncoder()

/** Encode bytes as standard (non-url) base64. Time/space O(n). */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/** Decode standard base64 to bytes. Time/space O(n). */
function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Derive the PBKDF2 bits for a plaintext password under a given salt and
 * iteration count. Imports the password as a raw key, then runs PBKDF2-HMAC with
 * {@link PRF_HASH}.
 *
 * Time complexity: O(iterations) HMAC evaluations (the deliberate cost).
 * Space complexity: O(1) beyond the derived bits.
 */
async function deriveBits(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  )
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: PRF_HASH },
    keyMaterial,
    DERIVED_KEY_BITS,
  )
  return new Uint8Array(derived)
}

/**
 * Hash a plaintext password into a self-describing, storable string.
 *
 * Generates a fresh random 128-bit salt, derives a 256-bit PBKDF2-HMAC-SHA256
 * key with `iterations` rounds, and serializes
 * `pbkdf2$<iterations>$<saltB64>$<hashB64>`. The plaintext is consumed only to
 * derive bits and is never returned or stored.
 *
 * Time complexity: O(iterations). Space complexity: O(1).
 *
 * @param plain - The plaintext password (caller-validated for length).
 * @param iterations - PBKDF2 round count (from `config.pbkdf2Iterations`,
 *   spec-mandated `>= 100_000`).
 * @returns The serialized hash string to persist.
 */
export async function hashPassword(plain: string, iterations: number): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES))
  const derived = await deriveBits(plain, salt, iterations)
  return [
    SCHEME_TAG,
    String(iterations),
    bytesToBase64(salt),
    bytesToBase64(derived),
  ].join(FIELD_SEPARATOR)
}

/**
 * Constant-time equality over two byte arrays. Returns `false` immediately on a
 * length mismatch (the lengths are not secret), otherwise XOR-accumulates every
 * byte so the comparison time does not depend on WHERE the first difference is —
 * defeating timing side-channels on the stored digest.
 *
 * Time complexity: O(n). Space complexity: O(1).
 */
function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    // Non-null: both indices are in range under the equal-length guard above.
    diff |= (a[i] as number) ^ (b[i] as number)
  }
  return diff === 0
}

/**
 * Verify a plaintext password against a serialized hash produced by
 * {@link hashPassword}.
 *
 * Re-derives the PBKDF2 bits using the salt and iteration count embedded in
 * `stored`, then compares in constant time. A malformed stored string (wrong
 * scheme tag, wrong field count, non-integer iterations, undecodable base64)
 * fails closed to `false` rather than throwing — an unverifiable credential is a
 * rejected login, not a server fault.
 *
 * Time complexity: O(iterations). Space complexity: O(1).
 *
 * @param plain - The presented plaintext password.
 * @param stored - The serialized hash from the store.
 * @returns `true` iff `plain` matches; `false` on mismatch or malformed input.
 */
export async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  const parts = stored.split(FIELD_SEPARATOR)
  if (parts.length !== SERIALIZED_FIELD_COUNT) {
    return false
  }
  const [tag, iterationsRaw, saltB64, hashB64] = parts
  if (tag !== SCHEME_TAG || iterationsRaw === undefined || saltB64 === undefined || hashB64 === undefined) {
    return false
  }
  const iterations = Number(iterationsRaw)
  if (!Number.isInteger(iterations) || iterations < 1) {
    return false
  }
  let salt: Uint8Array
  let expected: Uint8Array
  try {
    salt = base64ToBytes(saltB64)
    expected = base64ToBytes(hashB64)
  } catch {
    return false
  }
  const derived = await deriveBits(plain, salt, iterations)
  return constantTimeEquals(derived, expected)
}
