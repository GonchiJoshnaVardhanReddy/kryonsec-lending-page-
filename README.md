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

The feedback form posts to the production webhook `https://n8n.kryonsec.in/webhook/kryon/feedback` as a plain HTML form POST into a hidden iframe, so no CORS configuration is needed. If the webhook path ever changes, update the `action` attribute of `#feedback-form` in `feedback.html`, plus the matching CSP `form-action`/`frame-src` entries in `_headers`.

The homepage install section embeds the walkthrough video from `https://www.youtube.com/embed/ZnH-U8DG3Y0`, so `_headers` allows `https://www.youtube.com` in `frame-src`. Changing the video ID means updating the iframe `src` in `index.html`; embedding a different host also means updating that CSP entry.

## DNS

Use Cloudflare DNS for `kryonsec.in`. The Cloudflare Pages custom-domain wizard is the source of truth for the exact Pages target. If Cloudflare requests a manual record, create the apex CNAME shown by the wizard (usually `@` → the project’s `*.pages.dev` hostname). Do not guess or replace that hostname.

Keep the n8n service separate and unchanged:

```text
n8n.kryonsec.in  →  your existing n8n Cloudflare Tunnel configuration
```

Do not point `n8n.kryonsec.in` at Cloudflare Pages, and do not change the tunnel configuration. The feedback form posts directly to the configured webhook, so it does not require frontend CORS configuration.

The existing `CNAME` file contains `kryonsec.in`. Cloudflare Pages does not require it, but leaving it in place is harmless.

## Files

- `index.html` — main landing page
- `feedback.html` — feedback and feature request form
- `roadmap.html` — planned improvements
- `style.css`, `script.js`, `theme-init.js` — shared presentation and behavior
- `assets/` — brand and favicon assets
- `_headers` — Cloudflare Pages security headers and CSP
- `robots.txt`, `sitemap.xml` — crawler metadata
