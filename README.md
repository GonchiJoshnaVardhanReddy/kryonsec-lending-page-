# Kryonsec landing page

This is the standalone static website for [kryonsec.in](https://kryonsec.in). It is intentionally separate from the Kryonsec agent repository and can be deployed without a backend.

## Local development

From this directory, run:

```powershell
python -m http.server 8765
```

Open [http://localhost:8765/](http://localhost:8765/). There is no build step, package manager, or runtime dependency.

## Cloudflare Pages deployment

Recommended free host: Cloudflare Pages.

1. Create a Pages project named `kryonsec-landing` and connect the landing-page directory or its separate repository.
2. Select **None** for the framework preset.
3. Leave the build command blank.
4. Set the output directory to the project root (`/`) and deploy the contents of this directory.
5. Add the custom domain `kryonsec.in` in Pages and enable HTTPS after the certificate is issued.

The production output is this entire directory. `_headers`, `robots.txt`, `sitemap.xml`, `index.html`, `feedback.html`, `roadmap.html`, `style.css`, `script.js`, `theme-init.js`, and `assets/` must be deployed together.

The feedback form posts to `/api/feedback`, a Pages Function in this repository. It is same-origin, so there is no CORS to configure and the page's script reads the real status code — a dropped submission shows as a failure rather than a false "thank you". Submissions are written to a KV namespace (see below).

The homepage install section embeds the walkthrough video from `https://www.youtube.com/embed/ZnH-U8DG3Y0`, so `_headers` allows `https://www.youtube.com` in `frame-src`. Changing the video ID means updating the iframe `src` in `index.html`; embedding a different host also means updating that CSP entry.

## DNS

Use Cloudflare DNS for `kryonsec.in`. The Cloudflare Pages custom-domain wizard is the source of truth for the exact Pages target. If Cloudflare requests a manual record, create the apex CNAME shown by the wizard (usually `@` → the project’s `*.pages.dev` hostname). Do not guess or replace that hostname.

Nothing else needs a DNS record. The site, the download endpoint, and the feedback endpoint are all served by this one Pages project; `n8n.kryonsec.in` is no longer used and its tunnel and DNS record can be deleted.

The existing `CNAME` file contains `kryonsec.in`. Cloudflare Pages does not require it, but leaving it in place is harmless.

## Files

- `index.html` — main landing page
- `feedback.html` — feedback and feature request form
- `roadmap.html` — planned improvements
- `style.css`, `script.js`, `theme-init.js` — shared presentation and behavior
- `assets/` — brand and favicon assets
- `functions/api/download.js` — the key-gated wheel download at `/api/download`
- `functions/api/license/verify.js` — the key check the app phones home to, at `/api/license/verify`
- `functions/api/feedback.js` — the feedback sink at `/api/feedback`
- `install.sh`, `install.ps1` — the member installer, served at `/install.sh` and `/install.ps1`
- `tests/` — endpoint checks (`node --test "tests/*.test.mjs"`)
- `_headers` — Cloudflare Pages security headers and CSP
- `robots.txt`, `sitemap.xml` — crawler metadata

## The download endpoint

`functions/api/download.js` gates the closed-source Kryonsec wheel behind a
membership key. Cloudflare Pages picks up `functions/` automatically, so there
is no routing to configure — it just needs two encrypted environment variables
in the Pages project:

| Variable | Value |
| --- | --- |
| `KRYONSEC_KEYS` | Allowed membership keys, comma-separated |
| `KRYONSEC_GITHUB_TOKEN` | Fine-grained GitHub token, `Contents: Read-only` on the private `kryon-sec` repo |

Environment variables only apply to a new deployment, so redeploy after
changing them. The full setup, and how a release reaches members, is in the
private repo's `RELEASING.md`.

**`install.sh` and `install.ps1` are copies.** The canonical versions live in
the private kryonsec repo and Cloudflare serves these. A change to the
installer does nothing until it is copied here.

## The license endpoint

`functions/api/license/verify.js` is where the app asks whether a key is still
good. The app is hardcoded to `https://kryonsec.in/api/license/verify`, calls it
at most once a day per machine, and **cannot activate at all without it** — a
machine that never reaches this endpoint never gets past the Purple Team gate.

It reads the same `KRYONSEC_KEYS` as the download gate, so there is nothing
extra to configure, and adding or removing a member is still one setting.

**It answers `200` even when it refuses** — the response body carries the
verdict:

```json
{"valid": true}
{"valid": false, "reason": "not recognised"}
```

This is deliberately the opposite of the download endpoint. The app treats any
non-200 from here as *"the network is down"* and falls back to a multi-day grace
period based on the last successful check. Serving a refusal as `403` would
therefore mean a key deleted from `KRYONSEC_KEYS` keeps working for that whole
grace period. The `200` is what makes revocation actually stick, and
`tests/verify.test.mjs` asserts it on every rejection path.

## The feedback endpoint

`functions/api/feedback.js` replaces the n8n webhook. It needs one **KV
namespace binding** — not an environment variable, so it lives under a
different heading in the dashboard:

1. Cloudflare dashboard → **Workers & Pages** → **KV** → create a namespace,
   any name (e.g. `kryonsec-feedback`).
2. Your **kryonsec-landing** project → Settings → **Functions** → **KV namespace
   bindings** → add one for **Production**:

   | Variable name | KV namespace |
   | --- | --- |
   | `KRYONSEC_FEEDBACK` | the namespace from step 1 |

3. Redeploy, then submit the form once and confirm it appears:

   ```bash
   npx wrangler kv key list --namespace-id <id> --remote
   ```

The binding name must be exactly `KRYONSEC_FEEDBACK`; the Function returns `503`
and stores nothing if it is missing or misnamed, rather than reporting a
submission it did not keep.

Read submissions with `wrangler kv key list` / `wrangler kv key get`, or in the
dashboard. Keys are `feedback/<timestamp>-<suffix>`, so listing is in
chronological order.
