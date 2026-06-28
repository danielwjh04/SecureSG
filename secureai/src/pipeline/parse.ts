/**
 * Deterministic extraction of URLs and download-execute patterns from a
 * `SKILL.md` (or any pasted skill text).
 *
 * The scanner's threat model is supply-chain: a skill document can smuggle a
 * malicious link (markdown link, autolink, bare URL, reference definition) or a
 * `curl … | bash` style one-liner that downloads and runs remote code. This
 * module surfaces both, deterministically, so the same input always yields the
 * same proof.
 *
 * Design choice (per CLAUDE.md "No Shortcuts"): extraction is a *tokenizing*
 * scan, not one giant catch-all regex. Each URL syntax has its own anchored
 * matcher run over the raw text; results are merged, deduped, and order-preserved
 * by first appearance. A single mega-regex would be unreadable, hard to reason
 * about for correctness, and prone to catastrophic backtracking on adversarial
 * input — unacceptable in a security path.
 *
 * Config is passed in by the caller; no cap, byte limit, or pattern is
 * hardcoded here. The module is typed against the structural {@link ParserConfig}
 * slice it needs, which the full runtime config satisfies.
 */

import { ParseError } from '../errors'

/**
 * The slice of the runtime config the parser depends on. The full config object
 * structurally satisfies this interface.
 */
export interface ParserConfig {
  /** Maximum number of URLs extracted per skill (subrequest budget). */
  readonly maxUrls: number
  /** Hard ceiling on skill text size in UTF-16 code units; larger -> ParseError. */
  readonly skillMaxBytes: number
}

/** The deterministic extraction result for a single skill document. */
export interface ParseResult {
  /** Distinct extracted URLs, in order of first appearance, capped at maxUrls. */
  readonly urls: string[]
  /** Distinct download-execute one-liners, in order of first appearance. */
  readonly execPatterns: string[]
}

/**
 * A single URL token discovered by one of the syntax matchers, tagged with the
 * index at which it first appears so the final ordering is stable regardless of
 * which matcher found it.
 */
interface UrlToken {
  readonly url: string
  readonly at: number
}

// One matcher per URL syntax. None is anchored to line start so URLs embedded
// mid-line are caught; each carries the global flag so every occurrence is
// visited. Kept separate (not unioned) so each can be reasoned about in
// isolation and extended without destabilizing the others.

/** Markdown inline link: `[text](https://host/path "optional title")`. */
const MARKDOWN_LINK = /\[[^\]]*\]\(\s*(https?:\/\/[^\s)]+)/g

/** Markdown autolink / angle-bracketed URL: `<https://host/path>`. */
const AUTOLINK = /<\s*(https?:\/\/[^>\s]+)\s*>/g

/** Reference-style link definition: `[label]: https://host/path`. */
const REFERENCE_DEFINITION = /^\s*\[[^\]]+\]:\s*(https?:\/\/\S+)/gm

/**
 * Bare URL not already inside markdown link syntax. The leading lookbehind-free
 * guard is handled by deduplication: a bare match that coincides with a
 * markdown-link match resolves to the same trimmed URL and collapses in the set.
 */
const BARE_URL = /https?:\/\/[^\s<>()[\]"'`]+/g

// Download-execute matchers. Anchored to the `curl`/`wget` invocation so a mere
// mention of the word "bash" elsewhere does not trip a finding. Both require the
// fetch tool and a pipe into a shell interpreter (sh/bash/zsh/dash).
//
// Examples caught:
//   curl https://x.sh | bash
//   wget -qO- https://x.sh | sh
//   curl -fsSL https://x.sh | sudo bash
const CURL_PIPE_SHELL =
  /\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/gi
const WGET_PIPE_SHELL =
  /\bwget\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/gi

/**
 * Trailing characters that are valid URL bytes but are almost always sentence
 * or markdown punctuation when they terminate a token. Stripped from bare/ref
 * matches so `see https://x.com/.` yields `https://x.com/` not `…/.`.
 */
const TRAILING_PUNCTUATION = /[.,;:!?)\]}>'"]+$/

/**
 * Extract URLs and download-execute patterns from skill text, deterministically.
 *
 * Algorithm:
 *   1. Reject oversize input up front (fail-loud) before any scanning.
 *   2. Run each anchored URL matcher; record (url, firstSeenIndex) tokens.
 *   3. Dedupe by URL, preserving first-appearance order; cap at `maxUrls`
 *      (URLs beyond the cap are dropped entirely — nothing extra is recorded).
 *   4. Run the curl/wget download-execute matchers; dedupe, preserve order.
 *   5. If nothing actionable was found (no URLs AND no exec patterns), raise
 *      `ParseError` — there is nothing to scan, and silently returning an empty
 *      result would let an unparseable document masquerade as benign.
 *
 * Determinism: no randomness, no clock; identical text -> identical result,
 * which is what keeps the downstream proof reproducible.
 *
 * Time complexity: O(n) in the text length n. Each matcher is a single linear
 *   pass with no nested quantifier backtracking; dedup uses O(1) set/map ops.
 * Space complexity: O(u + e) for the deduped URL and exec-pattern collections
 *   (u <= maxUrls), plus O(n) transient for the matcher scans.
 *
 * @param text - The raw skill document.
 * @param config - The {@link ParserConfig} slice (cap + byte limit).
 * @returns The deduped, order-preserved {@link ParseResult}.
 * @throws {ParseError} If the text exceeds `skillMaxBytes`, or if no URL and no
 *   download-execute pattern is present.
 */
export function parseSkill(text: string, config: ParserConfig): ParseResult {
  if (text.length > config.skillMaxBytes) {
    throw new ParseError(
      `skill text length ${text.length} exceeds limit ${config.skillMaxBytes}`,
    )
  }

  const tokens: UrlToken[] = []
  collectUrlTokens(text, MARKDOWN_LINK, tokens, true)
  collectUrlTokens(text, AUTOLINK, tokens, true)
  collectUrlTokens(text, REFERENCE_DEFINITION, tokens, true)
  collectUrlTokens(text, BARE_URL, tokens, false)

  const urls = dedupeCappedUrls(tokens, config.maxUrls)
  const execPatterns = collectExecPatterns(text)

  if (urls.length === 0 && execPatterns.length === 0) {
    throw new ParseError(
      'no URLs and no download-execute patterns found — nothing to scan',
    )
  }

  return { urls, execPatterns }
}

/**
 * Run one URL matcher over the text and push (url, index) tokens.
 *
 * `captured` selects whether the URL is in capture group 1 (markdown/autolink/
 * reference syntaxes wrap the URL) or is the whole match (bare URLs). Bare and
 * reference matches have trailing sentence punctuation stripped; bracket-wrapped
 * syntaxes do not need it because their delimiters already bound the URL.
 *
 * Time complexity: O(n) — one linear regex pass, no backtracking quantifiers.
 * Space complexity: O(m) in the number of matches appended.
 */
function collectUrlTokens(
  text: string,
  matcher: RegExp,
  tokens: UrlToken[],
  captured: boolean,
): void {
  // Each matcher carries the global flag and is module-scoped, so reset
  // lastIndex to keep calls independent and idempotent.
  matcher.lastIndex = 0
  for (
    let match = matcher.exec(text);
    match !== null;
    match = matcher.exec(text)
  ) {
    const raw = captured ? match[1] : match[0]
    if (raw === undefined) {
      continue
    }
    const url = captured ? raw : raw.replace(TRAILING_PUNCTUATION, '')
    if (url.length === 0) {
      continue
    }
    tokens.push({ url, at: match.index })
  }
}

/**
 * Dedupe URL tokens by URL string, preserving first-appearance order, then cap
 * at `maxUrls`. Sorting by first-seen index makes ordering independent of the
 * matcher run order, so a bare URL appearing before a markdown link keeps its
 * earlier position.
 *
 * Time complexity: O(t log t) in the token count t (the stable sort); dedup is
 *   O(t) with an O(1) `Set` membership test. t is bounded by the URL density of
 *   the input, not by maxUrls.
 * Space complexity: O(t) for the seen-set and result.
 */
function dedupeCappedUrls(tokens: UrlToken[], maxUrls: number): string[] {
  const ordered = [...tokens].sort((a, b) => a.at - b.at)
  const seen = new Set<string>()
  const urls: string[] = []
  for (const token of ordered) {
    if (seen.has(token.url)) {
      continue
    }
    seen.add(token.url)
    urls.push(token.url)
    // Stop accumulating once the cap is hit — record nothing extra.
    if (urls.length >= maxUrls) {
      break
    }
  }
  return urls
}

/**
 * Collect distinct curl/wget download-execute one-liners, order-preserved.
 *
 * Time complexity: O(n) — two linear regex passes, sorted merge of the matches.
 * Space complexity: O(e) in the number of distinct patterns.
 */
function collectExecPatterns(text: string): string[] {
  const tokens: { value: string; at: number }[] = []
  collectExecTokens(text, CURL_PIPE_SHELL, tokens)
  collectExecTokens(text, WGET_PIPE_SHELL, tokens)

  const ordered = tokens.sort((a, b) => a.at - b.at)
  const seen = new Set<string>()
  const patterns: string[] = []
  for (const token of ordered) {
    const normalized = token.value.trim()
    if (seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    patterns.push(normalized)
  }
  return patterns
}

/**
 * Run one download-execute matcher and push (value, index) tokens.
 *
 * Time complexity: O(n) — single linear pass. Space complexity: O(m).
 */
function collectExecTokens(
  text: string,
  matcher: RegExp,
  tokens: { value: string; at: number }[],
): void {
  matcher.lastIndex = 0
  for (
    let match = matcher.exec(text);
    match !== null;
    match = matcher.exec(text)
  ) {
    tokens.push({ value: match[0], at: match.index })
  }
}
