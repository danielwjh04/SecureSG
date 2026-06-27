/**
 * Typed error hierarchy for the scanner.
 *
 * Mirrors the discipline of `secureSG/exceptions.py`: never throw a bare string
 * or a plain `Error`. Every failure carries a class whose name is logged on I/O
 * faults, so an operator can tell a config fault from a reputation-provider
 * fault from a proof-integrity fault at a glance.
 *
 * `ScannerError` is the root. Subclasses partition by subsystem. The proof core
 * (`shared/`) only ever raises `CanonicalizationError` and `ProofError`; the
 * other classes belong to worker subsystems and are declared here so the whole
 * hierarchy lives in one place.
 */

/** Root of every scanner-raised error. */
export class ScannerError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    // Preserve the concrete class name across the transpile target so logs and
    // `instanceof` both report the real subclass.
    this.name = new.target.name
  }
}

/** Invalid or out-of-range runtime configuration. */
export class ConfigError extends ScannerError {}

/** A JSON value was not safe to canonicalize for hashing. */
export class CanonicalizationError extends ScannerError {}

/** The proof chain could not be built or its invariants were violated. */
export class ProofError extends ScannerError {}

/** SKILL.md / source content could not be parsed. */
export class ParseError extends ScannerError {}

/**
 * A source URL could not be resolved to a fetchable skill manifest — e.g. a
 * GitHub repository that contains no `SKILL.md`, or the GitHub API was
 * unreachable while locating one. Distinct from `ParseError` (the content was
 * fetched but is unscannable) so an operator can tell "could not find a skill to
 * fetch" from "fetched a document with nothing to scan".
 */
export class SourceResolutionError extends ScannerError {}

/** A redirect cascade could not be resolved (network, timeout, SSRF guard). */
export class RedirectResolutionError extends ScannerError {}

/** The reputation provider (Exa) failed or returned an unusable response. */
export class ReputationError extends ScannerError {}

/** The injection judge (OpenAI) failed or returned an unusable response. */
export class JudgeError extends ScannerError {}
