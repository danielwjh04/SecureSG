# Subsystem 3 Plan: Installer And Release Integrity

Date: 2026-06-30
Branch: codex/guard-capability-policy
Issues: #23
Status: Planned

## Mission

Close the release-integrity gaps for SecureAI installers and guard assets before PR #24 is merged. The release bundle must be deterministic, checksummed, attested by CI, and tied to the exact assets users install. The local installers must be correct on Bash and PowerShell, verify downloaded guard adapters end to end, and fail closed when integrity cannot be proven.

## Assumptions

- No push, no deploy, no PR merge. Commit locally only.
- `scanner/dist` is a build artifact and must never be hand-edited.
- `scanner/public/secureai-guard.mjs` is the source browser guard; `scanner/dist/secureai-guard.mjs` must match it after `npm --prefix scanner run build`.
- The installer can fetch a checksum manifest from a configured release base URL. Tests will use local files so no live network is needed.
- Existing adapter single-source redaction rules remain untouched in this subsystem.
- Deferred redaction prefix expansion, BOM cleanup, and `mapGuardDecision` unification stay in subsystem 6.

## Global Constraints

- No em dashes or en dashes in code, comments, docs, workflow text, or README.
- No hardcoded secrets. Configurable URLs and paths stay driven by environment variables or the release asset manifest.
- Installer failures must fail closed. Missing checksums, bad hashes, malformed manifests, failed downloads, and hook-write errors stop installation.
- Do not log API keys, device credentials, raw device ids, hook payloads, or file contents.
- Do not hand-edit `scanner/dist`.
- Every task starts with a failing or missing test, then implementation, then direct verification by the main Codex thread.

## Task 1: Make Release Assets Deterministic And Dist-Aware

Goal: `scripts/release-checksums.mjs` must produce a deterministic release bundle from an explicit asset manifest and prove the served scanner assets in `scanner/dist` match `scanner/public`.

Files:

- `scripts/release-checksums.mjs`
- `scripts/release-checksums.test.mjs`
- `scanner/package.json`
- `.github/workflows/release-integrity.yml`

Tests first:

- Add `scripts/release-checksums.test.mjs` with Node test cases for:
  - stable sorted `SHA256SUMS.txt` output
  - output directory cleanup or stale-file rejection
  - failure when `scanner/dist/install.sh`, `scanner/dist/install.ps1`, or `scanner/dist/secureai-guard.mjs` differs from the matching `scanner/public` file
  - release bundle contains the browser guard copied from `scanner/dist`, not from a stale source path

Implementation:

- Refactor `scripts/release-checksums.mjs` into small exported functions while preserving CLI behavior.
- Use an explicit release asset manifest with source path, release filename, and optional parity path.
- Require dist parity for served browser assets.
- Write `SHA256SUMS.txt` from the copied release files only.
- Add a `scanner` package script if it helps keep build and release checks repeatable.

Verification:

```bash
node --test scripts/release-checksums.test.mjs
npm --prefix scanner run build
node scripts/release-checksums.mjs release-assets
```

## Task 2: Add End-To-End Checksum Verification To Bash Installer

Goal: `scanner/public/install.sh` must verify every downloaded adapter against `SHA256SUMS.txt` before moving it into place.

Files:

- `scanner/public/install.sh`
- `scripts/release-checksums.test.mjs`

Tests first:

- Extend the release checksum tests or add installer-focused Node tests that run the Bash installer in dry local mode with:
  - a valid local checksum manifest and valid adapter files
  - a tampered adapter file that must fail
  - a missing checksum entry that must fail
  - `SECUREAI_DRY_RUN=1`, which must not require network or checksums

Implementation:

- Add configurable `SECUREAI_RELEASE_BASE_URL` and `SECUREAI_CHECKSUMS_URL`.
- Add per-adapter release filenames that map to `SHA256SUMS.txt`.
- Download each adapter to a temp file, compute SHA-256, compare to the manifest, then move into place.
- Keep override URLs supported, but require a matching expected hash through the same manifest unless dry run is active.
- Keep config and hook writes idempotent.

Verification:

```bash
node --test scripts/release-checksums.test.mjs
bash -n scanner/public/install.sh
```

## Task 3: Repair And Verify PowerShell Installer Integrity

Goal: `scanner/public/install.ps1` must parse, run, verify adapter hashes, and mirror the Bash installer behavior.

Files:

- `scanner/public/install.ps1`
- `scripts/release-checksums.test.mjs`

Tests first:

- Add Node tests that run PowerShell with local test assets when PowerShell is available:
  - valid manifest succeeds
  - tampered adapter fails
  - missing checksum fails
  - dry run succeeds without network
- Include a parse check using PowerShell so nested here-string regressions fail fast.

Implementation:

- Fix the current nested here-string breakage around `Write-SecureAiConfig` and `Register-GuardDevice`.
- Add checksum manifest parsing and SHA-256 verification before moving downloaded adapters into place.
- Fail closed on malformed JSON, failed hook writes, failed downloads, missing hashes, and mismatched hashes.
- Preserve user-configurable paths and agent selection.

Verification:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scanner/public/install.ps1
node --test scripts/release-checksums.test.mjs
```

Use installer environment variables in tests so no real user hook paths are touched.

## Task 4: Expand Hook Health And Release CI Checks

Goal: CI must validate the full release slice, not only one health command.

Files:

- `.github/workflows/release-integrity.yml`
- `integrations/claude-code/secureai-guard.mjs`
- `integrations/codex/secureai-guard.mjs`
- `integrations/cursor/secureai-guard.mjs`
- `scanner/public/secureai-guard.mjs`
- Existing adapter tests under `integrations/**` and `scanner/public`

Tests first:

- Add or extend Node adapter tests so all four adapters prove:
  - `--health` exits successfully
  - health output reports enabled status when auth and device id are configured
  - health output never prints raw API keys or raw device ids
  - health output includes provider and integration version status

Implementation:

- If any adapter lacks equivalent health output, align it with the existing pattern without changing verdict behavior.
- Update release workflow to:
  - run scanner build before checksums
  - run `node --test` for release and adapter health tests
  - run checksum verification
  - run installer parse checks
  - keep attestation and tag publish behavior

Verification:

```bash
node --test integrations/shared/secureai-redact.test.mjs integrations/codex/secureai-guard.test.mjs integrations/cursor/secureai-guard.test.mjs integrations/claude-code/secureai-guard.test.mjs scanner/public/secureai-guard.test.mjs scripts/sync-adapter-redaction.test.mjs scripts/release-checksums.test.mjs
node scripts/sync-adapter-redaction.mjs --check
```

## Task 5: Update Release Integrity Docs And Final Gate

Goal: README and release docs must describe the actual integrity boundary, verification flow, checksum manifest, and protection limits plainly.

Files:

- `README.md`
- `docs/release-integrity.md`
- `.superpowers/sdd/progress.md`

Tests first:

- Add a docs style check if not already covered by the workflow.
- Verify no em dashes or en dashes in touched docs and release files.

Implementation:

- Document how to verify downloaded release files before install.
- Document how installers verify adapter downloads.
- Document that checksum verification does not prove the host machine is clean and does not cover actions outside configured hooks, browser extension, or API integration.
- Update the SDD progress ledger with task status, commit hashes, and any deferred items.

Final verification:

```bash
node --test integrations/shared/secureai-redact.test.mjs integrations/codex/secureai-guard.test.mjs integrations/cursor/secureai-guard.test.mjs integrations/claude-code/secureai-guard.test.mjs scanner/public/secureai-guard.test.mjs scripts/sync-adapter-redaction.test.mjs scripts/release-checksums.test.mjs
node scripts/sync-adapter-redaction.mjs --check
npm --prefix scanner run build
node scripts/release-checksums.mjs release-assets
npm --prefix secureai run test:run
npm --prefix secureai run typecheck
npm --prefix secureai run lint
rg -n "[\u2013\u2014]" README.md docs scanner/public scripts .github integrations
git status --short
```

## Checkpoint

After task 5 and whole-slice review, stop and report the subsystem 3 result to the user before starting subsystem 4.
