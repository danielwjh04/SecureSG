/**
 * Known-bad host indicator lookup — a license-clean {@link ReputationClient}
 * that matches a scan's final destination URLs against a curated host/domain
 * denylist (our own data) plus, optionally, a Cloudflare KV namespace for
 * dynamic entries.
 *
 * Why a host denylist rather than IP-netblock data (e.g. Spamhaus DROP): a
 * Cloudflare Worker cannot resolve a URL hostname to an IP, so IP-range feeds
 * add nothing here — and raw-IP URL hosts are already refused upstream by the
 * SSRF guard's `host.raw_ip` structural rule. A host/domain denylist is matched
 * O(1)/O(d) against the *final* URL of every traced redirect cascade, is
 * curated by us (no third-party license), and is pluggable: a paid
 * URL-reputation API (e.g. Google Web Risk) can later implement the very same
 * {@link ReputationClient} interface with no change to the orchestrator.
 *
 * Matching is parent-domain aware: a denylist entry `evil.com` flags both
 * `evil.com` and any subdomain `x.evil.com`, by walking the host's label
 * suffixes. The lookup is therefore O(1) for an exact hit and O(d) worst case
 * (d = label count) for the parent-domain walk.
 *
 * Safety posture (CLAUDE.md §1, §6):
 *   - Fail-closed per URL: a URL whose hostname cannot be parsed is flagged
 *     (status `unparseable`) — an unverifiable destination is treated as bad,
 *     never waved through.
 *   - Fail-closed on infrastructure fault: a KV read error is not swallowed;
 *     it is raised as {@link ReputationError} so the orchestrator escalates the
 *     whole scan toward HUMAN_APPROVAL_REQUIRED rather than silently clearing.
 *   - Tighten-only by construction: this client only ever *flags*; the
 *     orchestrator folds a flag through `escalate`, so it can only raise the
 *     verdict, never relax it.
 */

import type { ReputationClient, ReputationReport } from '../schemas/contract'
import { ReputationError } from '../errors'

/**
 * The minimal Cloudflare KV surface this client reads. Declared structurally
 * (rather than depending on the full `KVNamespace` type) so the module stays
 * decoupled and a test can inject a tiny `{ get }` fake. A dynamic denylist
 * entry lives under the key `host:<hostname>`; any non-null value marks the
 * host as denylisted (the value itself is not interpreted).
 */
export interface IndicatorKv {
  get(key: string): Promise<string | null>
}

/** KV key prefix under which a single dynamic host denylist entry is stored. */
const KV_HOST_PREFIX = 'host:'

/** The stringified reputation score for a denylisted (maximally bad) host. */
const SCORE_FLAGGED = '1.00'

/** The stringified reputation score for a clean host. */
const SCORE_CLEAN = '0.00'

/**
 * A {@link ReputationClient} that assesses each final URL against a curated
 * host/domain denylist and an optional KV namespace of dynamic entries.
 *
 * Construction is side-effect free; all work happens in
 * {@link assessFinalUrls}.
 */
export class DenylistReputationClient implements ReputationClient {
  /**
   * @param denylist - Lowercased denylisted hosts/domains. A `ReadonlySet` so
   *   membership is O(1) and the set cannot be mutated through this reference.
   *   An entry `evil.com` denylists `evil.com` and every subdomain of it.
   * @param kv - Optional KV namespace of dynamic per-host entries, checked when
   *   the static set does not already flag a host. Omit it (or pass `null`) to
   *   run on the static denylist alone.
   */
  public constructor(
    private readonly denylist: ReadonlySet<string>,
    private readonly kv: IndicatorKv | null = null,
  ) {}

  /**
   * Assess each final destination URL and return one {@link ReputationReport}
   * per input, in input order.
   *
   * For each URL:
   *   1. Parse `new URL(url).hostname`, lowercased. An unparseable URL is
   *      flagged with status `unparseable` (fail-closed) and skips all lookups.
   *   2. Static check: the host equals a denylist entry, OR is a subdomain of
   *      one (parent-domain suffix walk over the labels).
   *   3. KV check (only if a namespace was provided and the static check
   *      missed): a non-null `KV.get('host:' + hostname)` flags the host. A KV
   *      read error is raised as {@link ReputationError} (never swallowed).
   * A flagged host yields `{ flagged: true, score: '1.00', status:
   * 'denylisted' | 'unparseable', ... }`; a clean host yields `{ flagged:
   * false, score: '0.00', status: 'clean', ... }`. `score` is always a STRING
   * so it never enters a hashed proof payload as a float.
   *
   * Time complexity: O(n · d) where n = url count and d = max label count per
   *   host (the parent-domain walk); O(n) when every host is an exact hit. Plus
   *   at most one KV read per non-statically-flagged URL.
   * Space complexity: O(n) for the returned reports.
   *
   * @param urls - The final destination URLs to assess.
   * @returns One {@link ReputationReport} per input URL, in order.
   * @throws {ReputationError} If a KV read fails (fail-closed: the orchestrator
   *   escalates the scan rather than treating the host as clean).
   */
  public async assessFinalUrls(urls: string[]): Promise<ReputationReport[]> {
    const reports: ReputationReport[] = []
    for (const url of urls) {
      reports.push(await this.assessOne(url))
    }
    return reports
  }

  /**
   * Assess a single URL. Split out so {@link assessFinalUrls} stays a thin
   * ordered fold; see that method for the full algorithm and complexity.
   *
   * Time complexity: O(d) in the host label count. Space complexity: O(1).
   *
   * @throws {ReputationError} If the KV read fails.
   */
  private async assessOne(url: string): Promise<ReputationReport> {
    let hostname: string
    try {
      hostname = new URL(url).hostname.toLowerCase()
    } catch {
      // An unparseable destination cannot be verified — flag it, never clear it.
      return {
        url,
        score: SCORE_FLAGGED,
        summary: 'destination URL could not be parsed for reputation lookup',
        title: url,
        flagged: true,
        status: 'unparseable',
      }
    }

    if (this.isStaticallyDenylisted(hostname) || (await this.isKvDenylisted(hostname))) {
      return {
        url,
        score: SCORE_FLAGGED,
        summary: 'host on known-bad denylist',
        title: hostname,
        flagged: true,
        status: 'denylisted',
      }
    }

    return {
      url,
      score: SCORE_CLEAN,
      summary: 'host not on any known-bad denylist',
      title: hostname,
      flagged: false,
      status: 'clean',
    }
  }

  /**
   * Report whether `hostname` is denylisted by the static set: an exact match,
   * or a subdomain of a denylisted parent. The parent-domain walk strips one
   * leading label at a time (`a.b.evil.com` → `b.evil.com` → `evil.com`) and
   * tests each suffix against the O(1) set.
   *
   * Time complexity: O(d) in the label count (one set lookup per suffix).
   * Space complexity: O(1) — index walk, no per-label allocation of the whole
   *   suffix beyond the substring slice.
   *
   * @param hostname - A lowercased hostname.
   * @returns `true` if the host or any parent domain is on the static denylist.
   */
  private isStaticallyDenylisted(hostname: string): boolean {
    if (this.denylist.has(hostname)) {
      return true
    }
    // Walk parent domains by advancing past each leading label's dot. Each
    // suffix (e.g. "evil.com") is tested against the O(1) set; a hit means the
    // host is a subdomain of a denylisted parent.
    let dotIndex = hostname.indexOf('.')
    while (dotIndex !== -1) {
      const parent = hostname.slice(dotIndex + 1)
      if (this.denylist.has(parent)) {
        return true
      }
      dotIndex = hostname.indexOf('.', dotIndex + 1)
    }
    return false
  }

  /**
   * Report whether `hostname` has a dynamic denylist entry in KV under
   * `host:<hostname>`. Returns `false` when no KV namespace is configured.
   *
   * Time complexity: O(1) lookups (one KV read). Space complexity: O(1).
   *
   * @param hostname - A lowercased hostname.
   * @returns `true` if KV holds a non-null entry for this exact host.
   * @throws {ReputationError} If the KV read fails (fail-closed; never swallowed).
   */
  private async isKvDenylisted(hostname: string): Promise<boolean> {
    if (this.kv === null) {
      return false
    }
    try {
      const value = await this.kv.get(KV_HOST_PREFIX + hostname)
      return value !== null
    } catch (error: unknown) {
      const className = error instanceof Error ? error.constructor.name : typeof error
      throw new ReputationError(
        `KV denylist read failed for host '${hostname}' (${className})`,
        { cause: error },
      )
    }
  }
}
