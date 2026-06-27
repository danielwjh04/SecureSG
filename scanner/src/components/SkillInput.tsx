/**
 * The scan entry point: a mono SKILL.md paste box, a secondary source-URL input,
 * and a file upload (button plus drag-and-drop onto the box). Exactly one input
 * path is sent: pasted or uploaded text takes precedence; otherwise a trimmed
 * URL is used. An uploaded file is read into the same `content` path, so the
 * user can review or edit it before scanning. Every control is inert while a
 * scan is in flight (`busy`) so a single run can't be double-submitted.
 */

import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent, FormEvent } from 'react'
import { UPLOAD_MAX_BYTES } from '../config'
import type { ScanRequest } from '../api/types'

interface SkillInputProps {
  /** Emits the request to scan. Exactly one of `content` / `sourceUrl` is set. */
  onScan: (request: ScanRequest) => void
  /** True while a scan is running; disables every control. */
  busy: boolean
}

export function SkillInput({ onScan, busy }: SkillInputProps) {
  const [content, setContent] = useState('')
  const [sourceUrl, setSourceUrl] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const trimmedContent = content.trim()
  const trimmedUrl = sourceUrl.trim()
  const canScan = !busy && (trimmedContent.length > 0 || trimmedUrl.length > 0)

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (!canScan) return
    const request: ScanRequest =
      trimmedContent.length > 0 ? { content } : { sourceUrl: trimmedUrl }
    onScan(request)
  }

  /**
   * Read a dropped/selected file into the content box. Rejects an oversized file
   * before loading it (the worker enforces the authoritative cap); a read error
   * surfaces as a message rather than a silent failure.
   */
  const loadFile = async (file: File): Promise<void> => {
    setUploadError(null)
    if (file.size > UPLOAD_MAX_BYTES) {
      const limitKb = Math.round(UPLOAD_MAX_BYTES / 1000)
      setUploadError(`${file.name} is too large to scan (max ${limitKb} KB).`)
      return
    }
    try {
      const text = await file.text()
      setContent(text)
      setFileName(file.name)
    } catch {
      setUploadError(`Could not read ${file.name}.`)
    }
  }

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.[0]
    if (file !== undefined) void loadFile(file)
    // Clear the value so re-selecting the same file fires `change` again.
    event.target.value = ''
  }

  const handleDrop = (event: DragEvent<HTMLFormElement>): void => {
    event.preventDefault()
    setDragging(false)
    if (busy) return
    const file = event.dataTransfer.files?.[0]
    if (file !== undefined) void loadFile(file)
  }

  const handleDragOver = (event: DragEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (!busy) setDragging(true)
  }

  const handleContentChange = (
    event: ChangeEvent<HTMLTextAreaElement>,
  ): void => {
    setContent(event.target.value)
    setFileName(null)
    setUploadError(null)
  }

  const hint =
    uploadError !== null ? (
      <span className="scan-input__hint--error">{uploadError}</span>
    ) : fileName !== null ? (
      `Loaded ${fileName}. Edit above or scan.`
    ) : (
      'Paste the skill text, drop a .md file, or point us at the URL your agent would fetch.'
    )

  return (
    <form
      className={`scan-input${dragging ? ' scan-input--dragging' : ''}`}
      onSubmit={handleSubmit}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={() => setDragging(false)}
    >
      <textarea
        className="scan-input__area"
        value={content}
        onChange={handleContentChange}
        placeholder={
          dragging
            ? 'Drop your SKILL.md to load it…'
            : 'Paste SKILL.md here, or drop a .md file…'
        }
        spellCheck={false}
        disabled={busy}
        aria-label="SKILL.md content"
      />
      <input
        className="scan-input__url"
        type="url"
        value={sourceUrl}
        onChange={(event) => setSourceUrl(event.target.value)}
        placeholder="…or a source URL to fetch and scan (incl. a GitHub repo)"
        disabled={busy}
        aria-label="Source URL"
      />
      <input
        ref={fileInputRef}
        className="scan-input__file"
        type="file"
        accept=".md,.markdown,text/markdown,text/plain"
        onChange={handleFileChange}
        disabled={busy}
        aria-label="Upload SKILL.md file"
      />
      <div className="scan-input__actions">
        <span className="scan-input__hint">{hint}</span>
        <button
          type="button"
          className="btn btn--ghost"
          onClick={() => fileInputRef.current?.click()}
          disabled={busy}
        >
          Upload .md
        </button>
        <button className="btn" type="submit" disabled={!canScan}>
          {busy ? 'Scanning…' : 'Scan skill'}
        </button>
      </div>
    </form>
  )
}
