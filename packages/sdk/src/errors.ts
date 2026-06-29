/** Base class for all SDK-raised errors. */
export class SecureAiError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SecureAiError'
  }
}

/** Raised when required SDK configuration is missing or invalid. */
export class SecureAiConfigError extends SecureAiError {
  constructor(message: string) {
    super(message)
    this.name = 'SecureAiConfigError'
  }
}

/** Raised when the SecureAI API does not respond before the configured timeout. */
export class SecureAiTimeoutError extends SecureAiError {
  constructor(message: string) {
    super(message)
    this.name = 'SecureAiTimeoutError'
  }
}

/** Raised for non-2xx API responses and network-level request failures. */
export class SecureAiHttpError extends SecureAiError {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'SecureAiHttpError'
    this.status = status
  }
}

/** Raised when an API response does not match the stable public shape. */
export class SecureAiParseError extends SecureAiError {
  constructor(message: string) {
    super(message)
    this.name = 'SecureAiParseError'
  }
}
