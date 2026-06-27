/**
 * Fullscreen static background for the scanner shell.
 *
 * This intentionally avoids mounting a `<video>` element. Some browsers flash
 * native media controls during muted autoplay, which makes the first paint feel
 * noisy. A static black base plus the existing HUD grid/vignette keeps the hero
 * clean and deterministic on load.
 */

export function BackgroundVideo() {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none bg-black">
      <div className="absolute inset-0 hud-grid opacity-70" />
      <div className="absolute inset-0 bg-gradient-to-b from-black/25 via-black/5 to-black/80" />
    </div>
  )
}
