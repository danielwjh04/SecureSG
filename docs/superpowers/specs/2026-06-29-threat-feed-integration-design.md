# Threat-feed integration (URLhaus + ThreatFox) — design

**Status:** approved (brainstorm 2026-06-29). **Scope:** one implementation cycle.

## Goal

Feed abuse.ch known-bad indicators into the scanner's reputation stage so a scan
of a skill/link pointing at a known-malicious **host/domain or URL** returns
`BLOCK`. Internal-lookup-only: we never redistribute raw feed rows or place them
in a proof — a hit records only that a known-bad feed matched, with a source
label, in the report (the proof keeps its existing `denylisted` REPUTATION shape).

## Decisions (settled in brainstorm)

- **Commercial use** of abuse.ch is cleared by the operator (registered Auth-Key).
- **Match scope:** host/domain **and** exact URL (a new lookup beside today's host engine).
- **Architecture:** hybrid — a versioned **D1** `feed_indicators` table holds the
  bulk feed; the existing static `SCANNER_BAD_HOSTS` set + KV `host:<hostname>`
  overrides are unchanged. KV is not used for the bulk feed (per-write cost).
- **Coverage / cadence (config defaults):** URLhaus *online* + ThreatFox *recent*
  endpoints (recency is encoded by the endpoint, tunable via the source-URL vars);
  refresh **hourly** via a Cron Trigger. Not full historical dumps (a v2).
- **Verdict:** a feed hit reuses `{flagged:true, score:'1.00', status:'denylisted'}`,
  so it BLOCKs exactly like the curated denylist and the **proof contract is unchanged**.

## Data model — migration `0011_feed_indicators.sql`

```sql
CREATE TABLE IF NOT EXISTS feed_indicators (
  version  INTEGER NOT NULL,        -- monotonic; the cron's scheduledTime (ms)
  kind     TEXT NOT NULL,           -- 'host' | 'url'
  value    TEXT NOT NULL,           -- lowercased host, or normalized URL
  source   TEXT NOT NULL,           -- 'urlhaus' | 'threatfox'
  PRIMARY KEY (version, kind, value)
);
CREATE TABLE IF NOT EXISTS feed_meta (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  current_version INTEGER,          -- NULL until the first successful refresh
  updated_at      TEXT
);
INSERT INTO feed_meta (id, current_version, updated_at)
  VALUES (1, NULL, NULL) ON CONFLICT (id) DO NOTHING;
```

Lookup is one indexed query joined to the pointer, so reads only ever see a
complete version:

```sql
SELECT fi.source FROM feed_indicators fi
  JOIN feed_meta fm ON fm.id = 1 AND fi.version = fm.current_version
 WHERE (fi.kind = 'host' AND fi.value IN (<= 8 host suffixes>))
    OR (fi.kind = 'url'  AND fi.value = ?)
 LIMIT 1;
```

## Components

- **`src/pipeline/normalizeUrl.ts`** (pure, shared by ingest + match): parse with
  `new URL()`, return `host + pathname + search` (host lowercased, default port
  dropped — both by the URL API; scheme and fragment dropped by construction;
  path/query exact), or `null` if unparseable. Byte-identical on both sides, like
  the proof's canonical bytes.
- **`src/pipeline/feedParse.ts`** (pure): map raw feed bodies to
  `{kind, value, source}[]`. URLhaus hostfile → `host` (skip `#` comments);
  URLhaus text_online → `url` (normalized); ThreatFox CSV → `domain`→`host`,
  `url`→`url` (normalized); skip ip/hash IOC types. Dedupe; bound to `feedMaxRows`
  (drop-with-log past the cap — never silent truncation).
- **`src/db/feed.ts`**: `d1FeedStore(db)` implementing `FeedIndicatorStore`
  (`match(hostSuffixes, normalizedUrl)` → source|null) and `replaceFeed(db,
  version, indicators)` (chunked batched inserts → flip pointer → delete
  non-current). Over the narrow `Database` seam (testable with the in-memory fake).
- **`src/scanner/feedIngest.ts`**: `ingestFeeds(deps)` — fetch each configured
  source (`AbortSignal` timeout + `Auth-Key` header), parse, accumulate, then
  `replaceFeed`. Per-source failure is logged + metered + skipped; if **zero**
  indicators were gathered (all sources failed) the pointer is **not** flipped —
  the last good version stays live, never an emptied denylist.
- **`src/pipeline/indicators.ts`** (augment): `DenylistReputationClient` gains an
  optional `feed: FeedIndicatorStore | null` ctor param. `assessOne` checks
  static set → KV → **feed** (host suffixes + normalized URL). A feed read error
  raises `ReputationError` (fail-closed, mirroring the KV path). The parent-domain
  suffix walk is extracted to a helper reused by the static check and the feed lookup.
- **`src/index.ts`** (augment): add a `scheduled(event, env, ctx)` export. Loads
  config; no-op + log when `!feedEnabled` or `DB` unbound; else `await
  ingestFeeds(...)` with `env.URLHAUS_AUTH_KEY` (secret), `event.scheduledTime` as
  the version, inside try/catch (a cron throw is logged + metered, never unhandled).
- **`src/routes/scan.ts` + `src/routes/guard.ts`** (augment): build the feed store
  when `config.feedEnabled && db !== null` and pass it as the third
  `DenylistReputationClient` arg.

## Config & secrets (`config/env.ts` + `wrangler.jsonc`)

New `ScannerConfig` fields (validated in `loadConfig`, defaults in `wrangler.jsonc`):
`feedEnabled` (`SCANNER_FEED_ENABLED`, bool, **default false** — safe rollout),
`feedUrlhausUrls` / `feedUrlhausHosts` / `feedThreatfox` (source URLs, string),
`feedMaxRows` (`SCANNER_FEED_MAX_ROWS`, int 1..2_000_000, default 200_000),
`feedFetchTimeoutMs` (`SCANNER_FEED_FETCH_TIMEOUT_MS`, int 1000..120000, default 20000).
`wrangler.jsonc` gains `"triggers": { "crons": ["0 * * * *"] }`.
`URLHAUS_AUTH_KEY` is a **secret** (read from `env` in `scheduled`, never config,
never source — mirrors `RESEND_API_KEY`).

## Error handling / fail-closed

- Scan-time D1 feed read failure → `ReputationError` → the orchestrator escalates
  toward `HUMAN_APPROVAL_REQUIRED` (never clears a host on a DB blip).
- Refresh: atomic via insert-new-version → flip pointer → delete-old. A crash
  before the flip leaves the prior version live. Zero-row refresh never flips.
- A feed hit is high-confidence → `BLOCK` (score `1.00`, status `denylisted`).

## Observability

Metrics: `feed.refresh` (labels: source, ok/fail), `feed.rows` per source,
`feed.hit` on a scan match. Structured logger only (no PII, no feed rows logged).

## Testing (Vitest; ≥85% on new code)

- `normalizeUrl`: case/port/fragment/query handling; unparseable → null; ingest==match.
- `feedParse`: hostfile comments skipped; URLs normalized; ThreatFox ioc_type filter;
  dedupe; cap enforcement logs the drop.
- `db/feed` (in-memory fake): ingest+match host (incl. subdomain via suffixes),
  match URL, miss; version swap hides the old version; not-found pointer → no match.
- `indicators`: feed host hit, feed URL hit, miss, feed error → `ReputationError`,
  precedence (static/KV before feed).
- `feedIngest`: injected fetch with canned bodies → expected indicators written;
  one failing source skipped; all-fail → no pointer flip (last good version kept).
- E2E: feed contains `evil.com` → scanning content linking to it → `BLOCK`.

## Out of scope (v2)

Full historical dumps (need chunked/queued ingest), IP/hash indicators,
RPZ/Snort/ClamAV formats, any feed-management UI.

## Rollout (manual, per the no-auto-deploy rule)

1. Land + merge to `main`.
2. `cd secureai && npx wrangler d1 migrations apply secureai --remote`.
3. `npx wrangler secret put URLHAUS_AUTH_KEY`.
4. `npm run deploy`.
5. Let the hourly cron load a version (or trigger once), confirm `feed_meta.current_version`.
6. Set `SCANNER_FEED_ENABLED=true` and redeploy.
