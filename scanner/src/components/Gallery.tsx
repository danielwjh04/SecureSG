import type { ReactNode } from 'react'
import { useCallback } from 'react'
import type { GalleryData, GalleryEntry, ScanResult } from '../api/types'
import {
  GALLERY_DATA_PATH,
  GALLERY_FETCH_ATTEMPTS,
  GALLERY_FETCH_TIMEOUT_MS,
} from '../config'
import { useApiResource } from '../hooks/useApiResource'

interface GalleryProps {
  /** Called with a recorded result when a card is picked. No network occurs. */
  onPick: (result: ScanResult) => void
}

/** The empty dataset used whenever the gallery file is absent or unreadable. */
const EMPTY_GALLERY: GalleryData = { generatedAt: '', entries: [] }

/**
 * Fetch the prebuilt gallery dataset, degrading to an empty gallery on any
 * failure. The dataset is generated in a later phase, so a 404 (or malformed
 * body) is an expected, non-error state: it resolves to {@link EMPTY_GALLERY}
 * and the UI shows a "coming soon" empty state rather than an error panel.
 *
 * Each attempt is bounded by {@link GALLERY_FETCH_TIMEOUT_MS}: a bare `fetch`
 * has no timeout, so a stalled request (e.g. the connection pool busy after a
 * heavy result view) would strand the gallery on its loading line forever. A
 * timed-out or failed attempt is retried up to {@link GALLERY_FETCH_ATTEMPTS}
 * times so a transient stall recovers; a definitive 404 is not retried.
 *
 * Time complexity: O(a · n) for a = attempts, n = response body size.
 * Space complexity: O(n).
 */
async function fetchGallery(): Promise<GalleryData> {
  for (let attempt = 1; attempt <= GALLERY_FETCH_ATTEMPTS; attempt += 1) {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), GALLERY_FETCH_TIMEOUT_MS)
    try {
      const response = await fetch(GALLERY_DATA_PATH, { signal: controller.signal })
      // A 404 (gallery not shipped yet) is definitive, not transient: degrade.
      if (!response.ok) return EMPTY_GALLERY
      const data = (await response.json()) as GalleryData
      return Array.isArray(data.entries) ? data : EMPTY_GALLERY
    } catch {
      // Network failure or a per-attempt timeout (the stalled-fetch case):
      // retry, and only after the final attempt degrade to the empty state.
      if (attempt === GALLERY_FETCH_ATTEMPTS) return EMPTY_GALLERY
    } finally {
      clearTimeout(timeout)
    }
  }
  return EMPTY_GALLERY
}

/** The verdict-neutral pill copy for an entry's tag. */
function tagLabel(tag: GalleryEntry['tag']): string {
  return tag === 'attack' ? 'Attack' : 'Benign'
}

/**
 * The curated scan gallery: a grid of recorded benign/attack scans. Clicking a
 * card replays its `result` instantly via `onPick` (no scan request). While the
 * dataset loads it shows a loading line; when it is missing or empty it shows a
 * tasteful "coming soon" state — it never surfaces a fetch error or crashes.
 *
 * Time complexity: O(e) in the entry count. Space complexity: O(e).
 */
export function Gallery({ onPick }: GalleryProps): ReactNode {
  const { data, loading } = useApiResource<GalleryData>(fetchGallery, 0)

  const handlePick = useCallback(
    (entry: GalleryEntry): void => {
      onPick(entry.result)
    },
    [onPick],
  )

  const entries = data?.entries ?? []

  return (
    <section className="gallery" aria-label="Example scans">
      <div className="panel__head">
        <h2>Example Scans</h2>
        {entries.length > 0 && <span className="panel__count">{entries.length}</span>}
      </div>
      {entries.length === 0 ? (
        <div className="panel__state">
          {loading ? 'Loading examples…' : 'Gallery coming soon. No example scans yet.'}
        </div>
      ) : (
        <div className="gallery__grid">
          {entries.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className="gallery__card"
              onClick={() => handlePick(entry)}
            >
              <span className={`gallery__tag gallery__tag--${entry.tag}`}>
                {tagLabel(entry.tag)}
              </span>
              <strong>{entry.title}</strong>
            </button>
          ))}
        </div>
      )}
    </section>
  )
}
