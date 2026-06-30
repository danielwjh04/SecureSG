# Release Integrity

SecureAI publishes local installer and guard assets as a small, verifiable
bundle. The bundle is built by `.github/workflows/release-integrity.yml`.

## What Is Included

The release bundle contains:

- `secureai-install.sh`
- `secureai-install.ps1`
- `secureai-browser-guard.mjs`
- `secureai-claude-code-guard.mjs`
- `secureai-cursor-guard.mjs`
- `secureai-codex-guard.mjs`
- `SHA256SUMS.txt`

The bundle is generated from source by:

```bash
npm --prefix scanner run build
node scripts/release-checksums.mjs release-assets
```

`scanner/dist` is generated first. The bundle script rejects a stale or mismatched
browser asset if `scanner/dist/install.sh`, `scanner/dist/install.ps1`, or
`scanner/dist/secureai-guard.mjs` differs from the matching file in
`scanner/public`.

## When It Runs

The workflow runs on:

- Pull requests that change installer, guard, checksum, release docs, or the
  workflow itself.
- Manual `workflow_dispatch` runs.
- Tags matching `v*`.

Pull requests run the adapter tests, check shared redaction drift, build the
scanner, build the bundle, verify checksums, parse both installers, run
`--health` on all four packaged guard assets, and check release docs style.
Manual and tag runs also produce GitHub artifact attestations. Tag runs publish
the bundle files to the matching GitHub release.

## Verify A Download

After downloading all release files into one directory, run:

```bash
sha256sum -c SHA256SUMS.txt
```

Every listed file should return `OK`.

For PowerShell:

```powershell
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $parts = $_ -split '\s+', 2
  $hash = (Get-FileHash -Algorithm SHA256 ".\$($parts[1])").Hash.ToLowerInvariant()
  if ($hash -ne $parts[0]) { throw "Checksum mismatch: $($parts[1])" }
  "OK: $($parts[1])"
}
```

## Installer Verification

The Bash and PowerShell installers fetch `SHA256SUMS.txt` from the release base
URL before installing guard adapters. Each selected adapter is downloaded to a
temporary file, hashed with SHA-256, compared to its manifest entry, then moved
into place only after a match.

The default release base URL is
`https://github.com/danielwjh04/SecureAI/releases/latest/download`.
Set `SECUREAI_RELEASE_BASE_URL` when testing a local bundle or pinning a
specific release directory.

Installation stops on:

- missing checksum manifest
- empty or malformed manifest
- missing or duplicate asset entry
- malformed hash
- failed download
- hash mismatch
- failed local install or hook write

`SECUREAI_DRY_RUN=1` remains network-free and checksum-free. It writes local
placeholder adapters and hook config only in the configured paths.

## Attestations

Manual and tag release runs request GitHub artifact attestations for the bundle.
Use GitHub's artifact attestation verification against the repository when you
need provenance beyond checksums.

## Hook Health

The release workflow runs the packaged Claude Code, Cursor, Codex, and browser
guard assets with `--health` and confirms the output is secret-free. Health
output reports status using these values:

- `enabled`
- `disabled`
- `unknown`

It also reports whether auth, device id, API URL, privacy mode, and integration
version are present or configured. It does not print the API key, raw API URL,
or raw device id.

## Protection Boundary

Release integrity proves the downloaded local files match the published bundle
and that installers verify adapter bytes before installing them. It does not
prove a machine is clean, rotate credentials, remove packages, or protect
actions that never pass through a SecureAI hook, browser extension, or API
integration.
