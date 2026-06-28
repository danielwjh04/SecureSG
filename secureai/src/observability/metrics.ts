/**
 * Lightweight metrics over a Cloudflare Analytics Engine dataset (the optional
 * `METRICS` binding). Each `count()` writes one data point; absent a binding it
 * is a no-op, so metrics are free to call unconditionally and degrade gracefully
 * when Analytics Engine is not configured.
 *
 * Use for low-cardinality counters worth trending — scan verdicts, breaker state
 * transitions, dependency failures, cap rejections. Never put PII in a blob/index
 * (CLAUDE.md §6); use stable enum-like tokens only.
 */

/** Structural subset of `AnalyticsEngineDataset` (so a `{ writeDataPoint }` fake injects). */
export interface MetricsDataset {
  writeDataPoint(event: { blobs?: string[]; doubles?: number[]; indexes?: string[] }): void
}

/** The metrics surface used across the codebase. */
export interface Metrics {
  /**
   * Record one occurrence of `name`. `index` (optional) is the high-cardinality
   * sampling key; `labels` are low-cardinality stable tokens. Never PII.
   */
  count(name: string, options?: { index?: string; labels?: readonly string[] }): void
}

/**
 * Build a {@link Metrics} over an Analytics Engine dataset, or a NO-OP when the
 * binding is `null` (unbound). A `writeDataPoint` fault is swallowed so metrics
 * never break a request.
 *
 * Time complexity: O(1) per point. Space complexity: O(1).
 */
export function createMetrics(dataset: MetricsDataset | null): Metrics {
  if (dataset === null) {
    return { count: () => {} }
  }
  return {
    count(name, options) {
      try {
        dataset.writeDataPoint({
          blobs: [name, ...(options?.labels ?? [])],
          doubles: [1],
          ...(options?.index !== undefined ? { indexes: [options.index] } : {}),
        })
      } catch {
        // Metrics are best-effort; a dataset fault must never fail a request.
      }
    },
  }
}

/**
 * The module-level metrics sink, pointed at the request's dataset once per request
 * by {@link setMetricsDataset} (mirroring the logger's module singleton), so call
 * sites can `metrics.count(...)` without threading a dataset through signatures.
 * Defaults to a no-op until a dataset is set.
 */
let active: Metrics = createMetrics(null)

/** Point the module {@link metrics} at a dataset (or `null` to disable), per request. */
export function setMetricsDataset(dataset: MetricsDataset | null): void {
  active = createMetrics(dataset)
}

/** The default metrics instance used across the codebase. */
export const metrics: Metrics = {
  count: (name, options) => active.count(name, options),
}
