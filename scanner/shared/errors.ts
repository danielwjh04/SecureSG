/** Typed errors shared by the browser proof verifier and shared proof core. */

/** Raised when a value cannot be serialized into proof-stable canonical JSON. */
export class CanonicalizationError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = 'CanonicalizationError'
  }
}

/** Raised when proof construction or verification receives invalid input. */
export class ProofError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = 'ProofError'
  }
}
