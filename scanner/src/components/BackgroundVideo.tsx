/**
 * Fullscreen background video for the dark hero. The source is an HLS (`.m3u8`)
 * stream: Safari plays HLS natively, every other browser needs hls.js to attach
 * the stream to the `<video>` element.
 *
 * Autoplay note: browsers only allow muted autoplay, and React's `muted`
 * *attribute* does not reliably set the `muted` DOM *property*, so without
 * setting it imperatively the browser blocks autoplay and shows a play overlay.
 * We set `muted`/`playsInline` on the element and call `play()` once the media
 * is ready, on both the native and hls.js paths.
 *
 * On top of the video sit three non-interactive overlays that give the page its
 * "security instrument" feel and keep text legible: a dark wash, a faint HUD
 * grid, and a vertical vignette.
 */

import { useEffect, useRef } from 'react'
import Hls from 'hls.js'
import { BACKGROUND_VIDEO_SRC } from '../config'

export function BackgroundVideo() {
  const videoRef = useRef<HTMLVideoElement>(null)

  useEffect(() => {
    const video = videoRef.current
    if (video === null) return

    // Force muted autoplay (the attribute alone is unreliable in React).
    video.muted = true
    video.defaultMuted = true
    video.playsInline = true
    const play = (): void => {
      void video.play().catch(() => {
        /* autoplay refused (e.g. Low Power Mode); a user gesture retries below */
      })
    }

    // Some states block autoplay outright even for muted video — notably Safari
    // Low Power Mode, where no muted autoplay is permitted. A user gesture lifts
    // the block, so the first interaction anywhere on the page starts playback;
    // once it is actually playing we stop listening. The video wrapper is
    // pointer-events-none, so the gesture is captured on the window wherever it
    // lands, and play() is retried on each gesture until one succeeds.
    const interactionEvents = ['pointerdown', 'touchstart', 'keydown'] as const
    const stopInteractionRetry = (): void => {
      for (const event of interactionEvents) {
        window.removeEventListener(event, play)
      }
    }
    for (const event of interactionEvents) {
      window.addEventListener(event, play, { passive: true })
    }
    video.addEventListener('playing', stopInteractionRetry, { once: true })

    // Attach the stream and kick off the initial autoplay attempt: native HLS on
    // Safari / iOS, hls.js everywhere else.
    let detachStream: () => void = () => {}
    if (video.canPlayType('application/vnd.apple.mpegurl') !== '') {
      video.src = BACKGROUND_VIDEO_SRC
      video.addEventListener('loadedmetadata', play, { once: true })
      play()
      detachStream = () => video.removeEventListener('loadedmetadata', play)
    } else if (Hls.isSupported()) {
      const hls = new Hls()
      hls.loadSource(BACKGROUND_VIDEO_SRC)
      hls.attachMedia(video)
      hls.on(Hls.Events.MANIFEST_PARSED, play)
      detachStream = () => hls.destroy()
    }

    return () => {
      stopInteractionRetry()
      video.removeEventListener('playing', stopInteractionRetry)
      detachStream()
    }
  }, [])

  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none">
      <video
        ref={videoRef}
        autoPlay
        muted
        loop
        playsInline
        preload="auto"
        className="background-video w-full h-full object-cover opacity-100"
      />
      {/* Legibility wash + security HUD grid + vertical vignette. */}
      <div className="absolute inset-0 bg-black/55" />
      <div className="absolute inset-0 hud-grid opacity-70" />
      <div className="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-black/85" />
    </div>
  )
}
