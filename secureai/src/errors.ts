/**
 * Typed error hierarchy for SecureAI, rooted at {@link ScannerError}. One class
 * per subsystem fault so callers can map failures to HTTP status / verdicts
 * without string matching. Never throw a bare `Error` (CLAUDE.md §4).
 */

/** Base class for every SecureAI fault. */
export class ScannerError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    // new.target.name keeps the concrete subclass name after transpilation, so
    // logs and `error.name` stay accurate (e.g. "InferenceError", not "Error").
    this.name = new.target.name
  }
}

/** Invalid or out-of-range runtime configuration (fail-closed at load). */
export class ConfigError extends ScannerError {}

/** A value could not be canonicalized to hash-stable bytes. */
export class CanonicalizationError extends ScannerError {}

/** A proof-chain construction invariant was violated. */
export class ProofError extends ScannerError {}

/** Inbound content could not be parsed into a scannable shape. */
export class ParseError extends ScannerError {}

/** The scan source (e.g. a GitHub URL) could not be resolved. */
export class SourceResolutionError extends ScannerError {}

/** A redirect hop failed, timed out, or was rejected by the SSRF guard. */
export class RedirectResolutionError extends ScannerError {}

/** A known-bad indicator lookup failed (feed/cache fault). Fail-closed. */
export class ReputationError extends ScannerError {}

/** The Workers AI injection model failed or returned malformed output. */
export class InferenceError extends ScannerError {}

/**
 * An account / persistence fault: a failed credential operation, a malformed
 * stored record, or a database error in the accounts layer. Never used to
 * signal a merely-invalid caller key — an unknown key is anonymous, not an
 * error (see {@link ../middleware/auth.authenticate}).
 */
export class AuthError extends ScannerError {}

/** A subject exceeded its per-tier daily cap. Mapped to HTTP 429. */
export class QuotaExceededError extends ScannerError {}

/**
 * A billing-provider fault: a failed Stripe API call (checkout/portal session
 * creation), or a webhook the provider could not process. Mapped to HTTP 502 —
 * the upstream payment provider is unreachable or rejected the request. Never
 * used to signal an unverified webhook signature, which is a fail-closed 400.
 */
export class BillingError extends ScannerError {}

/**
 * A failure in the admin analytics aggregation layer: a database error while
 * computing sitewide counts/sums. Wraps the underlying store fault so the admin
 * route fails closed (HTTP 500) rather than leaking an internal error.
 */
export class AdminError extends ScannerError {}

/**
 * An email-provider fault: the transactional email API (Resend) rejected the
 * send or was unreachable. Mapped to HTTP 502 by the login route so a 2FA code
 * that could not be delivered fails closed — NO session is issued. Only the
 * upstream status / error class is ever logged, never the code.
 */
export class EmailError extends ScannerError {}

/**
 * A two-factor (OTP) challenge fault in the persistence layer: a database error
 * while creating, reading, incrementing, or deleting an `otp_challenges` row.
 * Wraps the underlying store fault so the verify/resend routes fail closed
 * rather than leaking an internal error. A merely-missing or expired challenge
 * is NOT an error — it is a generic 401 the route returns directly.
 */
export class OtpError extends ScannerError {}
