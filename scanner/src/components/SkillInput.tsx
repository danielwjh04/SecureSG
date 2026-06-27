/**
 * The hero's scan control: a glass card with a segmented selector (Paste / URL /
 * Upload .md) that expands the chosen input. Exactly one request is emitted per
 * mode: paste and file load into `content`, URL emits `sourceUrl`. The component
 * is presentational over the scan controller, so it owns only its draft input
 * and never the scan lifecycle; every control is inert while `busy`.
 */

import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent, FormEvent } from 'react'
import { motion } from 'motion/react'
import { FileText, Link2, Upload, ScanLine, Check } from 'lucide-react'
import { INPUT_MODES, UPLOAD_MAX_BYTES } from '../config'
import type { InputModeId } from '../config'
import type { ScanRequest } from '../api/types'

interface SkillInputProps {
  /** Emits the request to scan. Exactly one of `content` / `sourceUrl` is set. */
  onScan: (request: ScanRequest) => void
  /** True while a scan is running; disables every control. */
  busy: boolean
}

const MODE_ICON: Record<InputModeId, typeof FileText> = {
  paste: FileText,
  url: Link2,
  file: Upload,
}

export function SkillInput({ onScan, busy }: SkillInputProps) {
  const [mode, setMode] = useState<InputModeId>('paste')
  const [content, setContent] = useState('')
  const [sourceUrl, setSourceUrl] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const activeValue = mode === 'url' ? sourceUrl.trim() : content.trim()
  const canScan = !busy && activeValue.length > 0

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (!canScan) return
    onScan(mode === 'url' ? { sourceUrl: sourceUrl.trim() } : { content })
  }

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
    event.target.value = ''
  }

  const handleDrop = (event: DragEvent<HTMLFormElement>): void => {
    event.preventDefault()
    setDragging(false)
    if (busy) return
    const file = event.dataTransfer.files?.[0]
    if (file !== undefined) {
      setMode('file')
      void loadFile(file)
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      onDrop={handleDrop}
      onDragOver={(event) => {
        event.preventDefault()
        if (!busy) setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      className={`liquid-glass rounded-3xl w-full max-w-xl mx-auto p-2.5 text-left transition-shadow duration-300 ${
        dragging ? 'glow-allow' : ''
      }`}
    >
      {/* Segmented mode selector. */}
      <div className="glass-pill flex items-center gap-1 p-1 mb-2.5">
        {INPUT_MODES.map(({ id, label }) => {
          const Icon = MODE_ICON[id]
          const selected = mode === id
          return (
            <button
              key={id}
              type="button"
              disabled={busy}
              onClick={() => setMode(id)}
              className={`relative flex-1 flex items-center justify-center gap-2 rounded-full px-4 py-2 text-[13px] font-medium transition-colors duration-200 cursor-pointer ${
                selected ? 'text-white' : 'text-white/55 hover:text-white/80'
              }`}
            >
              {selected && (
                <motion.span
                  layoutId="mode-pill"
                  className="absolute inset-0 rounded-full bg-white/10"
                  transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                />
              )}
              <Icon className="relative w-4 h-4" />
              <span className="relative">{label}</span>
            </button>
          )
        })}
      </div>

      {/* Active input. */}
      <div className="px-1.5 pt-1">
        <motion.div
          key={mode}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.18 }}
        >
            {mode === 'paste' && (
              <textarea
                value={content}
                onChange={(event) => {
                  setContent(event.target.value)
                  setFileName(null)
                  setUploadError(null)
                }}
                placeholder="Paste SKILL.md here, or drop a .md file anywhere on this panel."
                spellCheck={false}
                disabled={busy}
                aria-label="SKILL.md content"
                className="w-full min-h-[150px] resize-none bg-transparent text-white/90 placeholder-white/35 font-mono text-[13px] leading-relaxed outline-none"
              />
            )}

            {mode === 'url' && (
              <div className="min-h-[150px] flex flex-col justify-center gap-3">
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={(event) => setSourceUrl(event.target.value)}
                  placeholder="https://github.com/owner/skill-repo"
                  disabled={busy}
                  aria-label="Source URL"
                  className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-3 text-white/90 placeholder-white/35 font-mono text-[13px] outline-none focus:border-white/30 transition-colors"
                />
                <p className="text-white/45 text-[12px] leading-relaxed">
                  A GitHub repo, a <span className="font-mono">/blob/</span> link,
                  or a raw URL. We resolve it to the skill the agent would
                  actually learn, never the web page around it.
                </p>
              </div>
            )}

            {mode === 'file' && (
              <button
                type="button"
                disabled={busy}
                onClick={() => fileInputRef.current?.click()}
                className="w-full min-h-[150px] rounded-xl border border-dashed border-white/15 hover:border-white/30 bg-white/[0.02] flex flex-col items-center justify-center gap-3 text-center transition-colors cursor-pointer"
              >
                {fileName === null ? (
                  <>
                    <Upload className="w-6 h-6 text-white/55" />
                    <span className="text-white/75 text-sm font-medium">
                      Drop a SKILL.md, or click to browse
                    </span>
                    <span className="text-white/40 text-[12px] font-mono">
                      .md / .markdown
                    </span>
                  </>
                ) : (
                  <>
                    <span className="flex items-center gap-2 text-allow text-sm font-medium">
                      <Check className="w-4 h-4" /> Loaded {fileName}
                    </span>
                    <span className="text-white/45 text-[12px] font-mono">
                      {content.length.toLocaleString()} chars ready to scan
                    </span>
                  </>
                )}
              </button>
            )}
        </motion.div>

        <input
          ref={fileInputRef}
          type="file"
          accept=".md,.markdown,text/markdown,text/plain"
          onChange={handleFileChange}
          disabled={busy}
          aria-label="Upload SKILL.md file"
          className="hidden"
        />

        {/* Footer: hint + scan action. */}
        <div className="flex items-center justify-between gap-3 mt-2 pt-2.5 border-t border-white/[0.06]">
          <span className="text-[12px] leading-snug">
            {uploadError !== null ? (
              <span className="text-block font-medium">{uploadError}</span>
            ) : (
              <span className="text-white/40">
                Fail-closed. Tamper-evident proof. Nothing trusted blindly.
              </span>
            )}
          </span>
          <button
            type="submit"
            disabled={!canScan}
            className="shrink-0 flex items-center gap-2 rounded-full bg-white text-black px-6 py-2.5 text-[13px] font-semibold hover:bg-white/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer"
          >
            <ScanLine className="w-4 h-4" />
            {busy ? 'Scanning…' : 'Scan skill'}
          </button>
        </div>
      </div>
    </form>
  )
}
