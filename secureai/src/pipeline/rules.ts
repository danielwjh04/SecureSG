/**
 * Deterministic hard rules — the explainable baseline verdict.
 *
 * Before any sponsor call (Exa reputation, OpenAI judge), the traced redirect
 * cascades and the parser's exec-pattern findings are run through a fixed set of
 * structural rules. Each rule that fires emits a `RuleFinding`; the baseline
 * verdict is the maximum severity across all findings. These rules are reliable,
 * cheap, and offline — they are why the scanner produces a safe BLOCK even with
 * no API keys configured. The semantic stages can only *tighten* this baseline
 * (see `escalate` in `../verdict`).
 *
 * The rule IDs and their severities are the contract with the UI and the proof,
 * so they are spelled out as named constants rather than inlined at the call
 * site.
 */

import type { LinkChain, RuleFinding, Verdict } from '../schemas/contract'
import { escalate } from '../verdict'

/**
 * The slice of the runtime config these rules depend on. Declaring exactly the
 * fields consumed (rather than the whole config) keeps the rule engine decoupled
 * and trivially testable: a caller supplies just the shortener allowlist.
 */
export interface RulesConfig {
  /**
   * Known URL-shortener hosts. A `frozenset`-equivalent: a `ReadonlySet` so
   * membership is O(1), never a list scan (see CLAUDE.md §2 denylist target).
   * Hosts are compared lowercased.
   */
  shortenerHosts: ReadonlySet<string>
}

/** Stable rule identifiers — the contract with the UI and the proof. */
const RULE_REDIRECT_DEPTH_EXCEEDED = 'redirect.depth_exceeded'
const RULE_REDIRECT_LOOP_DETECTED = 'redirect.loop_detected'
const RULE_HOST_RAW_IP = 'host.raw_ip'
const RULE_HOST_PUNYCODE = 'host.punycode'
const RULE_URL_SHORTENER = 'url.shortener'
const RULE_REDIRECT_CROSS_ORIGIN_HOP = 'redirect.cross_origin_hop'
const RULE_SSRF_BLOCKED_HOST = 'ssrf.blocked_host'
const RULE_SKILL_CURL_BASH_EXEC = 'skill.curl_bash_exec'

/** The IDNA ACE prefix; a host containing it is punycode-encoded. */
const PUNYCODE_MARKER = 'xn--'

/** ALLOW is the floor before any rule fires. */
const BASELINE_FLOOR: Verdict = 'ALLOW'

/**
 * Parse a URL string, or `null` if it does not parse. Returning `null` (rather
 * than throwing) lets the caller treat an unparseable URL as simply not matching
 * host rules; an unparseable URL never reaches here in practice because the
 * redirect tracer only records URLs it successfully resolved.
 *
 * Time complexity: O(n) in the URL length (one parse). Space complexity: O(1).
 */
function parseUrl(url: string): URL | null {
  try {
    return new URL(url)
  } catch {
    return null
  }
}

/**
 * Lowercased hostname of a URL string, or `null` if it does not parse.
 *
 * Time complexity: O(n) in the URL length. Space complexity: O(1).
 */
function hostOf(url: string): string | null {
  const parsed = parseUrl(url)
  return parsed === null ? null : parsed.hostname.toLowerCase()
}

/**
 * True when `host` is a raw IP-address literal (IPv4 dotted-quad or a bracketed
 * IPv6 form). The redirect tracer's SSRF guard already rejects private/loopback
 * literals during tracing; this rule additionally flags *any* bare-IP host in a
 * resolved cascade, because a skill that points its links at numeric IPs rather
 * than names is, on its own, a strong supply-chain risk signal.
 *
 * `URL.hostname` strips the surrounding brackets from IPv6 hosts but leaves the
 * colons, so an IPv6 literal is detected by the presence of a colon. IPv4 is a
 * strict four-octet dotted-decimal check.
 *
 * Time complexity: O(1) (bounded host length). Space complexity: O(1).
 */
function isRawIpHost(host: string): boolean {
  // IPv6 literal: URL.hostname yields the address with colons (brackets removed).
  if (host.includes(':')) {
    return true
  }
  // IPv4 dotted-quad: exactly four octets, each 0-255.
  const octets = host.split('.')
  if (octets.length !== 4) {
    return false
  }
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) {
      return false
    }
    const value = Number(octet)
    if (value > 255) {
      return false
    }
  }
  return true
}

/**
 * The ordered list of every URL that appears in a traced chain: the origin, the
 * `to` of each hop, and the final URL. This is what host-level rules scan. Each
 * URL appears once even though a hop's `to` equals the next hop's `from`,
 * because only `to` and the endpoints are enumerated.
 *
 * Time complexity: O(h) in the hop count. Space complexity: O(h).
 */
function urlsInChain(chain: LinkChain): readonly string[] {
  const urls: string[] = [chain.origin]
  for (const hop of chain.hops) {
    urls.push(hop.to)
  }
  urls.push(chain.finalUrl)
  return urls
}

/**
 * Evaluate the deterministic hard rules over the traced chains and the parser's
 * exec-pattern findings.
 *
 * Every rule that fires appends a `RuleFinding{ ruleId, severity, detail }`; the
 * returned `verdict` is the maximum severity across all findings (folded through
 * `escalate`, so the result is monotonic and tie-stable starting from ALLOW).
 * The function is pure: same input → same `{ verdict, findings }`, with no
 * network, time, or randomness — a prerequisite for it sitting inside the hashed
 * proof pipeline and for the hermetic gallery build.
 *
 * Rule set (rule id → severity):
 *   - redirect.depth_exceeded     → BLOCK  (chain hit the hop cap)
 *   - redirect.loop_detected      → BLOCK  (a cycle was seen in the cascade)
 *   - host.raw_ip                 → BLOCK  (a URL host is a bare IP literal)
 *   - host.punycode               → BLOCK  (a URL host contains `xn--`)
 *   - url.shortener               → HUMAN_APPROVAL_REQUIRED (host in allowlist)
 *   - redirect.cross_origin_hop   → HUMAN_APPROVAL_REQUIRED (a hop changes origin)
 *   - ssrf.blocked_host           → BLOCK  (a hop tripped the SSRF guard)
 *   - skill.curl_bash_exec        → BLOCK  (an exec pattern is present)
 *
 * Findings are emitted in a deterministic order: all per-chain rules in chain
 * order (and within a chain, the order rules are checked), then the single
 * exec-pattern rule last.
 *
 * Time complexity: O(C·H) where C = chains and H = max hops per chain — a single
 *   pass over every URL in every cascade, with O(1) set/regex tests per URL.
 * Space complexity: O(F) in the number of findings emitted.
 *
 * @param input.chains - The traced redirect cascades.
 * @param input.execPatterns - Exec-pattern excerpts the parser surfaced
 *   (e.g. piped `curl … | bash`); a non-empty list fires `skill.curl_bash_exec`.
 * @param input.config - The shortener allowlist these rules consult.
 * @returns The baseline `verdict` and the ordered `findings`.
 */
export function evaluateRules(input: {
  chains: LinkChain[]
  execPatterns: string[]
  config: RulesConfig
}): { verdict: Verdict; findings: RuleFinding[] } {
  const { chains, execPatterns, config } = input
  const findings: RuleFinding[] = []
  let verdict: Verdict = BASELINE_FLOOR

  const record = (finding: RuleFinding): void => {
    findings.push(finding)
    verdict = escalate(verdict, finding.severity)
  }

  for (const chain of chains) {
    if (chain.depthExceeded) {
      record({
        ruleId: RULE_REDIRECT_DEPTH_EXCEEDED,
        severity: 'BLOCK',
        detail: `redirect cascade for ${chain.origin} exceeded the hop cap`,
      })
    }

    if (chain.loopDetected) {
      record({
        ruleId: RULE_REDIRECT_LOOP_DETECTED,
        severity: 'BLOCK',
        detail: `redirect cascade for ${chain.origin} forms a loop`,
      })
    }

    // A hop the SSRF guard marked dangerous during tracing.
    if (chain.dangerousHopIndex !== null) {
      const dangerousHop = chain.hops[chain.dangerousHopIndex]
      const reason = dangerousHop?.reason ?? 'SSRF host guard tripped'
      record({
        ruleId: RULE_SSRF_BLOCKED_HOST,
        severity: 'BLOCK',
        detail: `hop ${chain.dangerousHopIndex} of ${chain.origin} blocked: ${reason}`,
      })
    }

    // Host-level rules over every URL in the cascade.
    for (const url of urlsInChain(chain)) {
      const host = hostOf(url)
      if (host === null) {
        continue
      }
      if (isRawIpHost(host)) {
        record({
          ruleId: RULE_HOST_RAW_IP,
          severity: 'BLOCK',
          detail: `${url} resolves through a raw-IP host (${host})`,
        })
      }
      if (host.includes(PUNYCODE_MARKER)) {
        record({
          ruleId: RULE_HOST_PUNYCODE,
          severity: 'BLOCK',
          detail: `${url} uses a punycode host (${host})`,
        })
      }
      if (config.shortenerHosts.has(host)) {
        record({
          ruleId: RULE_URL_SHORTENER,
          severity: 'HUMAN_APPROVAL_REQUIRED',
          detail: `${url} is a known URL shortener (${host})`,
        })
      }
    }

    // Cross-origin hop: a redirect whose destination origin (scheme + host +
    // port) differs from its source origin. A full `URL.origin` comparison is
    // used rather than a host-only check so a port or scheme change is not
    // silently treated as same-origin.
    for (const [hopIndex, hop] of chain.hops.entries()) {
      const fromUrl = parseUrl(hop.from)
      const toUrl = parseUrl(hop.to)
      if (fromUrl === null || toUrl === null) {
        continue
      }
      if (fromUrl.origin !== toUrl.origin) {
        record({
          ruleId: RULE_REDIRECT_CROSS_ORIGIN_HOP,
          severity: 'HUMAN_APPROVAL_REQUIRED',
          detail: `hop ${hopIndex} of ${chain.origin} crosses origin (${fromUrl.origin} -> ${toUrl.origin})`,
        })
      }
    }
  }

  if (execPatterns.length > 0) {
    record({
      ruleId: RULE_SKILL_CURL_BASH_EXEC,
      severity: 'BLOCK',
      detail: `skill contains shell exec pattern(s): ${execPatterns.join(', ')}`,
    })
  }

  return { verdict, findings }
}
