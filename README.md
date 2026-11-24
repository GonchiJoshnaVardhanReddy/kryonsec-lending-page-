# Kryonsec landing page

This is the standalone static website for [kryonsec.in](https://kryonsec.in). It is intentionally separate from the Kryonsec agent repository and can be deployed without a backend.

The site now also serves the beta: applications, review, per-account access,
and the sign-in `kryonsec login` uses. Two documents cover it:

- **[DEPLOYING-BETA.md](DEPLOYING-BETA.md)** — migrations, environment,
  the first administrator, deploy, rollback, and the post-deploy smoke test.
  Read this before touching production.
- **[SECURITY-NOTES.md](SECURITY-NOTES.md)** — the credential model, and an
  explicit list of what is *not* enforced. Read this before promising anyone
  that access can be taken away.
- **[API.md](API.md)** — every route, what authorises it, and what it answers.
- **[BETA-IMPLEMENTATION-REPORT.md](BETA-IMPLEMENTATION-REPORT.md)** — what was
  built, what was verified, and what is still blocked.

Nothing about the membership-key path changed. Existing keys and published
install scripts keep working.

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
- `migrations/` — D1 schema, applied in order. See [DEPLOYING-BETA.md](DEPLOYING-BETA.md).
- `.dev.vars.example` — local environment template (`.dev.vars` is git-ignored)
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
installer does nothing until it is copied here. `tests/install-script.test.mjs`
checks the served copy's contract (no embedded credential, browser approval,
hash verification); the CLI repo's pytest suite exercises its behavior.

## Installing Kryonsec (Linux or WSL2)

This is what `install.sh` is for, written out so the operator can tell a broken
install from an unprepared machine. Run it from inside a WSL2 Ubuntu terminal:
the installer reads its approvals and the setup wizard from `/dev/tty`, so a
`wsl -- bash -c '...'` one-liner has a terminal but nobody watching it.

Two shapes exist. **Copilot (Mode A)** is the interactive CLI and needs nothing
but Python. **Purple Team (Mode B)** is the sandboxed engagement engine, is
Linux/WSL2 only, and needs a native Docker Engine with a registered gVisor
runtime. There is no `runc` fallback: if `runsc` is not on the daemon you
selected, the install stops rather than quietly running you with weaker
isolation.

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates python3.12 python3.12-venv python3-pip
```

Python 3.11+ is required; 3.12 is the fast path. On 3.14 pip may compile
dependencies from source, which looks like a hung install for many minutes.
Don't run the installer as root — it would install into `/root/.kryonsec` and
the command would exist only for root.

Preview without touching anything:

```bash
curl -fsSL https://kryonsec.in/install.sh -o install.sh
bash install.sh --dry-run --profile=purple
```

### Docker Engine, native inside WSL2

```bash
sudo apt-get install -y docker.io
sudo systemctl enable --now docker      # or: sudo service docker start
sudo usermod -aG docker "$USER"         # then reopen the WSL terminal
docker info --format '{{.OperatingSystem}}'
```

`docker info` must work as your user, and must not report `Docker Desktop`.
A `runsc` installed inside WSL cannot be loaded by the Docker Desktop daemon, so
the installer refuses that daemon outright — it will not switch contexts or
reconfigure Desktop on your behalf. With more than one context present, say
which one you mean (`export DOCKER_CONTEXT=<name>`); an unambiguous choice is
required, not guessed.

### gVisor

```bash
curl -fsSL https://gvisor.dev/archive.key |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" |
  sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
sudo runsc install && sudo systemctl restart docker
docker info --format '{{json .Runtimes}}' | grep -o runsc
```

The installer performs the same steps itself, each behind a consent prompt, and
backs up `/etc/docker/daemon.json` before `runsc install` edits it — so this
section is the manual path, not a hidden requirement.

### Install and activate

```bash
bash install.sh --profile=purple
```

`--profile=auto` installs Copilot and asks before the optional host changes,
`--profile=copilot` never touches Docker, `--profile=purple` requires the full
isolated path. `--yes` pre-approves prompts, `--no-wizard` skips the setup
wizard, `--repair` preserves an incomplete virtualenv (or a malformed gVisor apt
source) before replacing it — it moves the old one to a timestamped backup and
deletes nothing.

The wheel is fetched with your credential in an `X-Kryonsec-Key` header, never
in a URL (a URL lands in proxy and access logs), then checked against the
release's `X-Kryonsec-Wheel-SHA256`; a missing or wrong hash is not installed.
The download is stored under the name the release advertises in
`Content-Disposition`, because pip takes a wheel's identity from its filename
and refuses one it cannot name. The Purple path then pulls the release-matched
sandbox image and saves the resolved `@sha256:` digest — a mutable tag is never
accepted as the runtime.

When it finishes it asks how to activate: paste a key, register the machine in
a browser, or skip. **Prefer pasting the key.** Typing it at that prompt is
hidden and never reaches shell history, while `KRYONSEC_KEY=... bash install.sh`
writes it to `~/.bash_history`. One key covers both modes: `/api/license/verify`
answers a beta key with the shared identity, and Purple Team requires that
identity to be present, which is why a key alone unlocks Mode B and a bare
download link does not.

`kryonsec login` is the browser path, and it is live — but its approval page
only accepts a signed-in member with a beta entitlement. Until the first
entitlement row exists (see [DEPLOYING-BETA.md §5](DEPLOYING-BETA.md), "The
first administrator"), nobody can approve a login, so use the key or
`kryonsec connect`.

### Verify and test

```bash
export PATH="$HOME/.kryonsec/venv/bin:$PATH"
kryonsec doctor --deep --strict; echo "rc=$?"
kryonsec auth
kryonsec                                  # Mode A: interactive Copilot
kryonsec purple --target <authorized-target>   # Mode B, inside the gVisor sandbox
kryonsec purple --target <authorized-target> --code ~/src/myapp
```

`--deep` creates and removes a network-disabled `runsc` smoke container. That is
the check that proves Mode B really runs, and the pass condition is no FAIL rows
with `rc=0`. `--code` mounts a folder read-only into the sandbox for blue-team
static scanning. Point `--target` only at systems the operator is authorised to
test.

### When it fails

| Message | What it actually means |
| --- | --- |
| `the selected daemon is Docker Desktop` | The wrong daemon is selected. Pick a native Linux Docker Engine context. |
| `multiple Docker contexts are available and none was explicitly selected` | Set `DOCKER_CONTEXT`. The installer will not choose for you. |
| `could not create a virtualenv` | `python3-venv` is missing; the installer asks to install it and says so when the answer is no. |
| `sandbox image has no registry digest` | A local or tag-only ref was supplied through `KRYONSEC_SANDBOX_IMAGE`. Let the installer resolve the digest. |
| an unrelated `apt-get install` fails | A malformed `/etc/apt/sources.list.d/gvisor.list` blocks all of apt; the symptom is a Docker install error whose cause is gVisor. Use `--repair`. |
| `~/.kryonsec/venv exists but is incomplete` | Re-run with `--repair` after reviewing the backup plan. |
| Purple FAIL from `doctor --deep` | `runsc` is not registered with the daemon the CLI actually talks to. Register it on that host, then re-run. |

## The Windows install command

The documented Windows command is short, stable, and carries no credential:

```powershell
irm https://kryonsec.in/install.ps1 -OutFile "$env:TEMP\kryonsec-install.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TEMP\kryonsec-install.ps1"
```

The installer posts to `/api/beta/device/start`, prints and opens the approval
page, and polls with `purpose: "download"`. A signed-in, entitled member
approves the machine in the browser; the poll then returns a fresh `dl_` link
that expires in 15 minutes and is spent on first use. The installer verifies
the wheel's `X-Kryonsec-Wheel-SHA256` against the bytes it received and refuses
to install a mismatch or a release with no hash. Membership keys, prepared
`KRYONSEC_DOWNLOAD_URL` links, and the `KRYONSEC_WHEEL` override still work;
the key is sent as a header, not in the query string.

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

## Sculptural website release

The homepage and static account screens come from Sites version 5 (source commit
3d93ef1cdcf89249afd09db0a859c8a52f7b3f04). The complete authored static site,
separate account Worker, schema, build script and tests live in `site-source/`.
The new theme uses `sculptural.css`; `style.css` is retained for existing server
pages. Existing Pages Functions, installers, and account data remain intact.

The separate account portal is not activated: `/api/config` explicitly returns
`ready: false`. See `site-source/cloudflare/DEPLOYMENT.md` for its outstanding
OAuth, isolated database and policy configuration. Do not point this Worker's
DB binding at the existing CLI membership database. Legacy accounts remain
available at `/signin`; the new account screen does not use those accounts.
