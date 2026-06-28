import { describe, expect, it } from 'vitest'
import { loadConfig } from './env'
import { ConfigError } from '../errors'

describe('loadConfig', () => {
  it('returns a valid config from defaults (empty env)', () => {
    const config = loadConfig({})
    expect(config.hashAlgorithm).toBe('SHA-256')
    expect(config.genesisSeed).toBe('secureai-scanner-genesis-v1')
    expect(config.allowedSchemes.has('https')).toBe(true)
    expect(config.reviewThreshold).toBeLessThan(config.blockThreshold)
    // Default subrequest budget invariant holds.
    expect(config.maxUrls * config.maxRedirectHops + 2).toBeLessThanOrEqual(config.subrequestCap)
  })

  it('parses overrides from string vars', () => {
    const config = loadConfig({ SCANNER_MAX_REDIRECT_HOPS: '5', SCANNER_AI_MODEL: '@cf/x/y' })
    expect(config.maxRedirectHops).toBe(5)
    expect(config.aiModel).toBe('@cf/x/y')
  })

  it('defaults the verdict-cache TTL to 300s and parses an override', () => {
    expect(loadConfig({}).verdictCacheTtlSeconds).toBe(300)
    expect(loadConfig({ SCANNER_VERDICT_CACHE_TTL_S: '0' }).verdictCacheTtlSeconds).toBe(0)
    expect(loadConfig({ SCANNER_VERDICT_CACHE_TTL_S: '600' }).verdictCacheTtlSeconds).toBe(600)
  })

  it('rejects an out-of-range verdict-cache TTL', () => {
    expect(() => loadConfig({ SCANNER_VERDICT_CACHE_TTL_S: '-1' })).toThrow(ConfigError)
    expect(() => loadConfig({ SCANNER_VERDICT_CACHE_TTL_S: '86401' })).toThrow(ConfigError)
  })

  it('defaults the caught-scan detail byte cap to 16384 and parses an in-range override', () => {
    expect(loadConfig({}).detailMaxBytes).toBe(16384)
    expect(loadConfig({ SCANNER_DETAIL_MAX_BYTES: '256' }).detailMaxBytes).toBe(256)
    expect(loadConfig({ SCANNER_DETAIL_MAX_BYTES: '262144' }).detailMaxBytes).toBe(262144)
  })

  it('rejects an out-of-range caught-scan detail byte cap', () => {
    expect(() => loadConfig({ SCANNER_DETAIL_MAX_BYTES: '255' })).toThrow(ConfigError)
    expect(() => loadConfig({ SCANNER_DETAIL_MAX_BYTES: '262145' })).toThrow(ConfigError)
  })

  it('rejects review >= block thresholds', () => {
    expect(() =>
      loadConfig({ SCANNER_REVIEW_THRESHOLD: '0.8', SCANNER_BLOCK_THRESHOLD: '0.5' }),
    ).toThrow(ConfigError)
  })

  it('rejects out-of-range integers', () => {
    expect(() => loadConfig({ SCANNER_MAX_REDIRECT_HOPS: '0' })).toThrow(ConfigError)
    expect(() => loadConfig({ SCANNER_MAX_URLS: '-1' })).toThrow(ConfigError)
  })

  it('rejects a subrequest budget that exceeds the cap', () => {
    expect(() =>
      loadConfig({ SCANNER_MAX_URLS: '20', SCANNER_MAX_REDIRECT_HOPS: '10', SCANNER_SUBREQUEST_CAP: '50' }),
    ).toThrow(ConfigError)
  })

  it('rejects an empty scheme allowlist', () => {
    expect(() => loadConfig({ SCANNER_ALLOWED_SCHEMES: '' })).toThrow(ConfigError)
  })

  it('rejects a non-integer value', () => {
    expect(() => loadConfig({ SCANNER_MAX_URLS: '3.5' })).toThrow(ConfigError)
  })

  it('exposes auth tunables with defaults and overrides', () => {
    const defaults = loadConfig({})
    // Default = the Cloudflare Workers PBKDF2 ceiling (100k); anything higher
    // throws at runtime in the Workers crypto, so the config caps it here.
    expect(defaults.pbkdf2Iterations).toBe(100000)
    expect(defaults.sessionTtlSeconds).toBe(604800)

    const overridden = loadConfig({
      SCANNER_PBKDF2_ITERATIONS: '50000',
      SCANNER_SESSION_TTL_SECONDS: '3600',
    })
    expect(overridden.pbkdf2Iterations).toBe(50000)
    expect(overridden.sessionTtlSeconds).toBe(3600)
  })

  it('rejects a PBKDF2 iteration count outside the Workers-safe range', () => {
    // Above the Workers 100k cap (would throw in the live crypto) -> fail closed.
    expect(() => loadConfig({ SCANNER_PBKDF2_ITERATIONS: '200000' })).toThrow(ConfigError)
    // Below the practical floor.
    expect(() => loadConfig({ SCANNER_PBKDF2_ITERATIONS: '5000' })).toThrow(ConfigError)
  })

  it('exposes billing config with defaults and overrides', () => {
    const defaults = loadConfig({})
    expect(defaults.stripePricePro).toBe('price_REPLACE')
    expect(defaults.appBaseUrl).toBe('https://secureai.zurielst.com')

    const overridden = loadConfig({
      STRIPE_PRICE_PRO: 'price_live_123',
      SCANNER_APP_BASE_URL: 'https://app.example.com',
    })
    expect(overridden.stripePricePro).toBe('price_live_123')
    expect(overridden.appBaseUrl).toBe('https://app.example.com')
  })

  it('parses the admin allowlist (lowercased, default empty)', () => {
    expect(loadConfig({}).adminEmails.size).toBe(0)

    const config = loadConfig({ SCANNER_ADMIN_EMAILS: 'Owner@Example.com, two@example.com' })
    expect(config.adminEmails.has('owner@example.com')).toBe(true)
    expect(config.adminEmails.has('two@example.com')).toBe(true)
    expect(config.adminEmails.size).toBe(2)
  })

  it('defaults the email-2FA tunables and accepts in-range overrides', () => {
    const defaults = loadConfig({})
    expect(defaults.emailFrom).toBe('SecureAI <noreply@zurielst.com>')
    expect(defaults.otpTtlSeconds).toBe(600)
    expect(defaults.otpMaxAttempts).toBe(5)

    const overridden = loadConfig({
      SCANNER_EMAIL_FROM: 'Acme <auth@acme.test>',
      SCANNER_OTP_TTL_SECONDS: '120',
      SCANNER_OTP_MAX_ATTEMPTS: '3',
    })
    expect(overridden.emailFrom).toBe('Acme <auth@acme.test>')
    expect(overridden.otpTtlSeconds).toBe(120)
    expect(overridden.otpMaxAttempts).toBe(3)
  })

  it('rejects out-of-range OTP tunables (fail-closed at load)', () => {
    expect(() => loadConfig({ SCANNER_OTP_TTL_SECONDS: '30' })).toThrow()
    expect(() => loadConfig({ SCANNER_OTP_TTL_SECONDS: '5000' })).toThrow()
    expect(() => loadConfig({ SCANNER_OTP_MAX_ATTEMPTS: '0' })).toThrow()
    expect(() => loadConfig({ SCANNER_OTP_MAX_ATTEMPTS: '50' })).toThrow()
  })

  it('defaults the contact recipients + rate, trimmed/lowercased/deduped', () => {
    const defaults = loadConfig({})
    expect(defaults.contactRecipients).toEqual([
      'zuriel.shanley@gmail.com',
      'danielwjh04@gmail.com',
    ])
    expect(defaults.contactRatePerHour).toBe(5)

    const overridden = loadConfig({
      SCANNER_CONTACT_RECIPIENTS: ' One@Example.com , two@example.com , one@example.com ',
      SCANNER_CONTACT_RATE_PER_HOUR: '20',
    })
    // Lowercased, trimmed, and deduped (the repeat is collapsed by the set).
    expect(overridden.contactRecipients).toEqual(['one@example.com', 'two@example.com'])
    expect(overridden.contactRatePerHour).toBe(20)
  })

  it('rejects an empty contact-recipients list (fail-closed at load)', () => {
    expect(() => loadConfig({ SCANNER_CONTACT_RECIPIENTS: '' })).toThrow(ConfigError)
    expect(() => loadConfig({ SCANNER_CONTACT_RECIPIENTS: '  ,  ' })).toThrow(ConfigError)
  })

  it('rejects an out-of-range contact rate (fail-closed at load)', () => {
    expect(() => loadConfig({ SCANNER_CONTACT_RATE_PER_HOUR: '0' })).toThrow(ConfigError)
    expect(() => loadConfig({ SCANNER_CONTACT_RATE_PER_HOUR: '101' })).toThrow(ConfigError)
  })
})
