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
node scripts/release-checksums.mjs release-assets
```

## When It Runs

The workflow runs on:

- Pull requests that change installer, guard, checksum, release docs, or the
  workflow itself.
- Manual `workflow_dispatch` runs.
- Tags matching `v*`.

Pull requests build the bundle and verify checksums. Manual and tag runs also
produce GitHub artifact attestations. Tag runs publish the bundle files to the
matching GitHub release.

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

## Attestations

Manual and tag release runs request GitHub artifact attestations for the bundle.
Use GitHub's artifact attestation verification against the repository when you
need provenance beyond checksums.

## Hook Health

The release workflow runs the Claude Code guard with `--health` and confirms the
output is secret-free. Health output reports status using these values:

- `enabled`
- `disabled`
- `unknown`

It also reports whether auth, device id, privacy mode, and integration version
are present. It does not print the API key or raw device id.

## Protection Boundary

Release integrity proves the downloaded local files match the published bundle.
It does not prove a machine is clean, rotate credentials, remove packages, or
protect actions that never pass through a SecureAI hook, browser extension, or
API integration.
