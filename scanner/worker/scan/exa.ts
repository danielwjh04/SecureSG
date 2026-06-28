/**
 * Exa-backed reputation client.
 *
 * Exa is the scanner's sandboxed fetcher: rather than the Worker pulling a
 * (possibly attacker-controlled) destination page into its own runtime, Exa
 * crawls each final URL and returns structured reputation evidence — page text,
 * a safety-focused summary, and a per-URL crawl status. This is the
 * compensating control for the hostname-only SSRF posture documented in
 * `./redirect` (Workers cannot inspect resolved IPs).
 *
 * Safety posture (CLAUDE.md §1, §6):
 *   - Fail-closed signal: a non-success crawl status for a URL is mapped to a
 *     `flagged` report. `runScan` reads `flagged` and escalates the verdict — a
 *     destination Exa could not vet is never silently treated as clean.
 *   - Float-free at the boundary: the contract's `ReputationReport.score` is a
 *     STRING so it can enter a hashed proof step without introducing float
 *     non-determinism (see `shared/contract.ts`).
 *   - Fail-loud on total failure: a thrown SDK error (auth, network, quota)
 *     surfaces as `ReputationError` with the exact underlying class name logged,
 *     never swallowed into an empty "clean" result. `runScan` turns that throw
 *     into a fail-closed escalation.
 *
 * Context7 facts used (verified against `/llmstxt/exa_ai_llms_txt` and
 * `/exa-labs/exa-js`):
 *   - Default export: `import Exa from "exa-js"`; `new Exa(apiKey)`.
 *   - `exa.getContents(urls, opts)` is ONE batched call returning
 *     `{ results, statuses }`; `text`/`summary` are option objects.
 *   - `results[]` carry `{ url, id, title, text, summary }`.
 *   - `statuses[]` carry `{ id, status: "success" | "error",
 *     error?: { tag, httpStatusCode } }`, keyed by the requested URL (`id`).
 *     Non-"success" => the crawl failed (CRAWL_NOT_FOUND, CRAWL_TIMEOUT, …).
 */

import Exa from 'exa-js'
import type { ReputationClient, ReputationReport } from '../../shared/contract'
import { ReputationError } from '../errors'

/**
 * The slice of runtime config this client needs. Declared structurally (like
 * `RedirectTraceConfig` in `./redirect`) so the module stays decoupled from the
 * full `ScannerConfig` and is trivially testable; the real config satisfies it.
 */
export interface ExaReputationConfig {
  /** Max characters of page text Exa returns per URL. */
  readonly exaMaxCharacters: number
  /** Exa content freshness ceiling, hours (0 = always livecrawl). */
  readonly exaMaxAgeHours: number
  /** Exa livecrawl timeout, milliseconds. */
  readonly exaLivecrawlTimeoutMs: number
}

/**
 * Minimal structural shape of the Exa SDK surface this client touches. Declared
 * locally so the module does not couple to the SDK's full (and evolving) type
 * surface and so unit tests can substitute a fake without importing `exa-js`.
 * The real `Exa` instance from `new Exa(apiKey)` satisfies this shape.
 */
interface ExaContentsSdk {
  getContents(
    urls: string[],
    options: ExaGetContentsOptions,
  ): Promise<ExaContentsResponse>
}

/** Options passed to `getContents` (the subset the scanner sets). */
interface ExaGetContentsOptions {
  text: { maxCharacters: number }
  livecrawlTimeout: number
  summary: { query: string }
  /** Freshness ceiling; only sent when > 0 (0 would force a livecrawl). */
  maxAgeHours?: number
}

/** One entry of the `results` array Exa returns for a successfully read URL. */
interface ExaContentsResult {
  url?: string
  id?: string
  title?: string
  text?: string
  summary?: string
}

/** One entry of the `statuses` array — per-URL crawl outcome, keyed by `id`. */
interface ExaContentsStatus {
  id: string
  status: string
  error?: { tag?: string; httpStatusCode?: number }
}

/** The `getContents` response envelope. */
interface ExaContentsResponse {
  results?: ExaContentsResult[]
  statuses?: ExaContentsStatus[]
}

/** Factory the constructor uses to build the real SDK client. */
type ExaFactory = (apiKey: string) => ExaContentsSdk

/** Crawl status string the scanner treats as a successful read. */
const STATUS_OK = 'OK' as const

/**
 * The reputation-summary query handed to Exa. A single, fixed query keeps the
 * batched call deterministic (same input -> same proof). It is intentionally
 * blunt: ask Exa to characterise the destination's safety so the summary text
 * is directly judgeable downstream.
 */
const REPUTATION_QUERY =
  'reputation, safety, phishing, malware of this site' as const

/**
 * Construct a {@link ReputationClient} over the real `exa-js` SDK.
 *
 * This is the stable factory name the scan handler imports (`buildExaClient`);
 * keep it in sync with `handlers/scan.ts`. The full `ScannerConfig` structurally
 * satisfies the {@link ExaReputationConfig} slice, so the handler passes its
 * resolved config straight through.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @param apiKey - The Exa API key (from the `EXA_API_KEY` secret).
 * @param config - The reputation config slice (the full config satisfies it).
 * @returns A reputation client over the Exa SDK.
 */
export function buildExaClient(
  apiKey: string,
  config: ExaReputationConfig,
): ReputationClient {
  return new ExaReputationClient(apiKey, config)
}

/**
 * Reputation client backed by Exa's `getContents` Contents API.
 *
 * One instance is constructed per request from the configured key. The
 * `assessFinalUrls` call issues exactly ONE batched subrequest regardless of
 * URL count, keeping the scan inside the Cloudflare free-plan subrequest budget
 * (`config.ts` reserves one subrequest for this call).
 */
export class ExaReputationClient implements ReputationClient {
  private readonly client: ExaContentsSdk
  private readonly config: ExaReputationConfig

  /**
   * @param apiKey - The Exa API key. A blank key is rejected eagerly so a
   *   missing secret fails loud at construction rather than as an opaque SDK
   *   401 deep in a request.
   * @param config - The reputation config slice (chars/freshness/timeout).
   * @param factory - Injectable SDK factory; defaults to the real `exa-js`
   *   default export. Tests pass a fake to avoid the network.
   * @throws {ReputationError} If `apiKey` is blank.
   */
  public constructor(
    apiKey: string,
    config: ExaReputationConfig,
    factory: ExaFactory = defaultExaFactory,
  ) {
    if (apiKey.trim().length === 0) {
      throw new ReputationError('Exa API key is empty')
    }
    this.client = factory(apiKey)
    this.config = config
  }

  /**
   * Assess every final destination URL in a single batched Exa call and map the
   * response to `ReputationReport[]` aligned 1:1 with the input order.
   *
   * Mapping rules:
   *   - A URL whose status entry is missing or non-`OK` (a crawl failure) yields
   *     `flagged: true` with the failure tag as `status` — the fail-closed
   *     signal `runScan` escalates on. We never fetch its content ourselves.
   *   - A successfully crawled URL is `flagged: false` (clean); the OpenAI judge
   *     is the semantic backstop and reads the returned summary.
   *   - `score` is a STRING in `[0,1]` (`'1.00'` = safest, `'0.00'` =
   *     flagged/failed) so the value can enter a hashed proof step without a
   *     float.
   *
   * Empty input short-circuits to `[]` with no network call (no URLs => nothing
   * to vet). A thrown SDK error becomes `ReputationError`; `runScan` catches it
   * and fails closed.
   *
   * Time complexity: O(n) over the URL count — one pass to index statuses by id
   *   plus one pass to build reports; the network call is a single batched
   *   request. Space complexity: O(n) for the status index and reports.
   *
   * @param urls - The final destination URLs to assess.
   * @returns Reports aligned 1:1 with `urls`.
   * @throws {ReputationError} On total SDK failure (auth, network, quota, …).
   */
  public async assessFinalUrls(urls: string[]): Promise<ReputationReport[]> {
    if (urls.length === 0) {
      return []
    }

    const options: ExaGetContentsOptions = {
      text: { maxCharacters: this.config.exaMaxCharacters },
      livecrawlTimeout: this.config.exaLivecrawlTimeoutMs,
      summary: { query: REPUTATION_QUERY },
    }
    // Only send a freshness ceiling when one is configured: maxAgeHours: 0 would
    // force a livecrawl on every call, so a 0 default means "let Exa decide".
    if (this.config.exaMaxAgeHours > 0) {
      options.maxAgeHours = this.config.exaMaxAgeHours
    }

    let response: ExaContentsResponse
    try {
      response = await this.client.getContents(urls, options)
    } catch (error: unknown) {
      // Fail-loud: log the exact underlying class (CLAUDE.md §1) and re-raise as
      // a typed reputation fault. `runScan` translates this into a fail-closed
      // escalation — it is never swallowed into an empty (falsely clean) result.
      const className =
        error instanceof Error ? error.constructor.name : typeof error
      console.warn(
        `[ExaReputationClient] getContents failed (${className}); raising ReputationError`,
      )
      throw new ReputationError('Exa getContents call failed', { cause: error })
    }

    const resultByUrl = indexByUrl(response.results ?? [])
    const statusByUrl = indexStatusByUrl(response.statuses ?? [])

    return urls.map((url) =>
      buildReport(url, resultByUrl.get(url), statusByUrl.get(url)),
    )
  }
}

/**
 * Index `results` by their URL (preferring `url`, falling back to `id`) for O(1)
 * lookup when building reports in input order. A duplicate URL keeps the first
 * occurrence — `getContents` returns one result per requested URL.
 *
 * Time complexity: O(n). Space complexity: O(n).
 */
function indexByUrl(
  results: readonly ExaContentsResult[],
): Map<string, ExaContentsResult> {
  const index = new Map<string, ExaContentsResult>()
  for (const result of results) {
    const key = result.url ?? result.id
    if (key !== undefined && !index.has(key)) {
      index.set(key, result)
    }
  }
  return index
}

/**
 * Index `statuses` by their `id` (the requested URL) for O(1) lookup.
 *
 * Time complexity: O(n). Space complexity: O(n).
 */
function indexStatusByUrl(
  statuses: readonly ExaContentsStatus[],
): Map<string, ExaContentsStatus> {
  const index = new Map<string, ExaContentsStatus>()
  for (const status of statuses) {
    if (!index.has(status.id)) {
      index.set(status.id, status)
    }
  }
  return index
}

/**
 * Build one `ReputationReport` for a URL from its (optional) result and status entries.
 *
 * A missing or non-success status is the fail-closed branch: the crawl could
 * not be completed, so the destination is unvetted and is flagged with the
 * failure tag as `status`. A successful crawl is recorded as clean; the OpenAI
 * judge reads the returned summary and is the semantic reputation backstop.
 *
 * Time complexity: O(t) where t = summary+text length scanned. Space: O(1).
 *
 * @param url - The requested URL (drives report alignment).
 * @param result - The matching result entry, if Exa returned content.
 * @param status - The matching status entry, if present.
 * @returns The mapped report; `score` is always a stringified float.
 */
function buildReport(
  url: string,
  result: ExaContentsResult | undefined,
  status: ExaContentsStatus | undefined,
): ReputationReport {
  const crawlOk = isCrawlSuccessful(status)

  if (!crawlOk) {
    // Fail-closed: an unreadable destination is flagged with the failure tag so
    // `runScan` escalates and the proof records why.
    return {
      url,
      score: '0.00',
      summary: '',
      title: result?.title ?? '',
      flagged: true,
      status: failureStatus(status),
    }
  }

  // A successful crawl is recorded as clean. The OpenAI judge is the semantic
  // backstop: it reads this summary (see judge.ts buildInput) and raises caution
  // on bad reputation. We deliberately do NOT lexically flag on the summary —
  // the reputation query asks Exa about "phishing/malware", so those terms
  // appear in nearly every summary and a substring match would false-positive on
  // safe sites (e.g. a summary stating "no evidence of phishing or malware").
  return {
    url,
    score: '1.00',
    summary: result?.summary ?? '',
    title: result?.title ?? '',
    flagged: false,
    status: STATUS_OK,
  }
}

/**
 * Whether a status entry represents a successful crawl. A *missing* status is
 * treated as a failure (fail-closed): no evidence of success is not success.
 * The Exa wire value `"success"` and the contract's `"OK"` convention both pass.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function isCrawlSuccessful(status: ExaContentsStatus | undefined): boolean {
  if (status === undefined) {
    return false
  }
  const normalized = status.status.trim().toUpperCase()
  return normalized === STATUS_OK || normalized === 'SUCCESS'
}

/**
 * Derive the human-readable failure status string for a flagged report: the
 * Exa error tag when present (e.g. `CRAWL_TIMEOUT`), else a generic marker for a
 * missing/blank status. Float-free string, safe for the hashed proof payload.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function failureStatus(status: ExaContentsStatus | undefined): string {
  const tag = status?.error?.tag?.trim()
  if (tag !== undefined && tag.length > 0) {
    return tag
  }
  const raw = status?.status?.trim()
  return raw !== undefined && raw.length > 0 ? raw.toUpperCase() : 'CRAWL_FAILED'
}

/**
 * Default SDK factory: lazily construct the real `exa-js` client. Isolated so
 * the only place the concrete SDK import lives is one line, and so unit tests
 * never load `exa-js`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function defaultExaFactory(apiKey: string): ExaContentsSdk {
  // The Exa default export is a class; its instance satisfies `ExaContentsSdk`.
  return new Exa(apiKey) as unknown as ExaContentsSdk
}
