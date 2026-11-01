# Deploying the beta

How to take the beta onboarding, approval, and command-line sign-in from this
working tree to kryonsec.in — and how to put it back.

Nothing in this repository deploys itself. Every step below is a person
running a command or clicking once in the dashboard, on purpose.

> **Status: preview only.** As verified on 2026-10-28, `feat/beta-onboarding`
> is deployed as a preview (`42d764b`); production still serves `main` at
> `f99136b`, which predates the beta code. The beta schema has already been
> applied to the production D1 database by hand: every table, trigger, and
> index from `0001_beta.sql` and `0002_cli_login.sql` is present, `beta_program`
> is active, and there are no `users`, `admins`, or `cli_login_codes` rows yet.
> There is **no** `d1_migrations` ledger — do not run `wrangler d1 migrations
> apply` (see §3). GitHub OAuth is configured; Google OAuth is not. See §9 for
> what is waiting on a decision.

---

## 1. What this adds

| | before | after |
|---|---|---|
| who can get the software | anyone with a membership key | anyone with a key **or** an approved beta account |
| signing in on the site | 6-digit code mailed to you | Google or GitHub OAuth |
| signing in on a machine | `kryonsec connect` with a key | `kryonsec login` — a code you approve in a browser |
| turning access off | edit an environment variable | a row per account, revocable per user |

The membership-key path is untouched. Every existing member, and every install
script already published, keeps working exactly as it did.

---

## 2. Prerequisites

- Cloudflare account with the Pages project `kryonsec-landing` and the domain
  `kryonsec.in` already serving the static site.
- `wrangler` logged in: `npx wrangler login`.
- A **D1** database bound to the Pages project as `KRYONSEC_DB`.
- The existing **KV** namespace bound as `KRYONSEC_FEEDBACK` (feedback form;
  also holds the review desk's admin token).
- Google and GitHub OAuth apps — see §4. The GitHub app exists; the Google
  app still needs to be created.

---

## 3. Migrations

Three files, applied in order. They are additive: nothing alters or drops an
existing table, which is what makes them safe to apply while members are using
the site.

```bash
# local, for development
npx wrangler d1 execute KRYONSEC_DB --local  --file migrations/0000_existing.sql
npx wrangler d1 execute KRYONSEC_DB --local  --file migrations/0001_beta.sql
npx wrangler d1 execute KRYONSEC_DB --local  --file migrations/0002_cli_login.sql
```

`0000_existing.sql` is a no-op on any database that already has the legacy
tables (`CREATE TABLE IF NOT EXISTS`). Run it locally so a dev database
matches.

**Production is already migrated by hand.** The database `kryonsec-members`
holds every object from `0001` and `0002`; `beta_program` is active; there are
zero users and zero administrators. There is **no `d1_migrations` ledger** on
it, so `wrangler d1 migrations apply` must not be used: it would try to run
`0001_beta.sql` again, and `0001` is not idempotent — the first `CREATE TABLE`
fails. Apply any future schema change by hand with
`wrangler d1 execute KRYONSEC_DB --remote --file …`, in the same order. A
genuinely fresh production database would take all three files this way,
`0000` first.

To confirm the production schema before deploying (read-only):

```bash
npx wrangler d1 execute KRYONSEC_DB --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','cli_login_codes','cli_sessions')"
```

### Order matters in one direction

**`0002` must be applied before the code that reads `cli_sessions` is live.**
`dashboard.js` queries `cli_sessions` on the `active` branch — which is the
branch every currently-working account sees. Deploy the code first and those
accounts get a 500 instead of their dashboard.

So the safe order is always: **migrate, then deploy.** Never the other way
around. On production the tables already exist ahead of the code, so this
constraint is already satisfied.

The reverse is safe: an older deployment runs fine against the newer schema,
because the migrations only add tables. That is what makes §7 possible.

---

## 4. Environment

Copy `.dev.vars.example` to `.dev.vars` for local work (`wrangler pages dev`).
In production, set the same names under **Pages → Settings → Variables and
Secrets**. Everything marked *secret* must be stored as an encrypted secret,
never as a plain-text variable.

| name | required | what it is |
|---|---|---|
| `KRYONSEC_DB` | yes | D1 binding (`KRYONSEC_DB`). The beta paths fail closed without it. |
| `KRYONSEC_KEYS` | yes | comma-separated membership-key allowlist. Unchanged. |
| `KRYONSEC_GOOGLE_CLIENT_ID` | for Google sign-in | Google OAuth client id; leave unset to offer GitHub only |
| `KRYONSEC_GOOGLE_CLIENT_SECRET` | for Google sign-in, *secret* | Google OAuth client secret |
| `KRYONSEC_GITHUB_CLIENT_ID` | yes | GitHub OAuth client id |
| `KRYONSEC_GITHUB_CLIENT_SECRET` | yes, *secret* | GitHub OAuth client secret |
| `KRYONSEC_ADMIN_TOKEN` | no, *secret* | legacy review-desk token; KV `admin/token` is the preferred home and already holds one |
| `KRYONSEC_FEEDBACK` | yes | KV binding for the feedback form |
| `KRYONSEC_REPO` | no | `owner/name` the release lookup reads; defaults to `GonchiJoshnaVardhanReddy/kryon-sec` |
| `KRYONSEC_GITHUB_TOKEN` | yes, *secret* | fine-grained PAT with Contents: Read; both download endpoints answer 502 without it |
| `KRYONSEC_EMAIL_PROVIDER` | no | leave unset: no adapter exists yet — see §9 |
| `KRYONSEC_EMAIL_FROM` | no | the From: address, once a provider exists |

As verified on 2026-10-28, production has the GitHub client id and encrypted
secret, the GitHub PAT, `KRYONSEC_KEYS`, and the D1/KV bindings. Google's two
variables are **not** set, so `/signin` names Google as unavailable and offers
GitHub only. The beta works in that state; Google can be added later without a
code change.

### OAuth app settings

Both apps need this exact callback URL. `[provider]` is literally `google` or
`github` — the route is `functions/api/auth/[provider]/callback.js`.

```
https://kryonsec.in/api/auth/google/callback
https://kryonsec.in/api/auth/github/callback
```

Scopes requested are `openid email` (Google) and `read:user user:email`
(GitHub). **Nothing that reads a private repository is requested** — reading
someone's private code is not a thing authenticating them requires, and asking
for it would be asking for more than the sign-in needs.

For local work, add `http://localhost:8788/api/auth/<provider>/callback` as
another allowed redirect URI. Google accepts several redirect URIs on one
client. A **classic GitHub OAuth App accepts exactly one callback URL**, so
local GitHub work needs a throwaway app unless the app is a GitHub App (which
allows several callback URLs).

### Preview deployments

Cloudflare Pages keeps **production** and **preview** variables and bindings
separately. A branch preview does not inherit the production values, so a
preview whose Preview environment has no `KRYONSEC_*_CLIENT_ID` /
`..._CLIENT_SECRET` (or no `KRYONSEC_DB` binding) renders `/signin` with both
providers marked unavailable, exactly as an unconfigured production would.

The callback URI is built from the request origin, so the provider has to
accept the preview origin too:

```
https://feat-beta-onboarding.kryonsec-landing.pages.dev/api/auth/github/callback
https://feat-beta-onboarding.kryonsec-landing.pages.dev/api/auth/google/callback
```

Google accepts several redirect URIs on one client, so add the preview URI to
the existing Google client. A **classic GitHub OAuth App has exactly one
callback URL**: do not replace the production one. Register a separate preview
app and put its client id and encrypted secret in the Preview environment
instead. (A GitHub App may hold several callback URLs and needs no second app.)
Until a valid preview app exists for a provider, leave its preview variables
unset — `/signin` will name that provider as unavailable rather than offering
a link that fails at the provider.

Set preview values under **Pages → Settings → Variables and Secrets →
Preview**. Never put the production client secret into a public fork's
preview; the preview environment is readable by anyone who can edit the
project.

This project has automatic preview deployments switched off
(`preview_deployment_setting: "none"`), so pushing a branch does not publish
it. Deploy the branch explicitly:

```
npx wrangler pages deploy . --project-name kryonsec-landing \
  --branch feat/beta-onboarding --commit-dirty=true
```

---

## 5. The first administrator

**There is no bootstrap route and there will not be one.** No form, no
environment variable, and no first-run wizard creates an admin, because every
one of those is something an outsider can reach. An admin is a row in `admins`,
inserted by a person with database access. Production currently has zero admin
rows, so nobody can open `/admin` until this is done once.

This is a production write. Do it only with explicit owner approval, outside a
deploy, and never as part of a code release. The steps below are the approved
shape of that operation; they are not authorisation to run it.

1. **Verify the operator can sign in.** Sign in through `/signin` with the
   intended account and confirm `/dashboard` loads. The account is not an
   administrator yet, so `/admin` will answer **403**. That is the correct
   pre-insert state.

2. **Identify the exact user id.** Match on the full email; do not pick a
   recent row by eye, and do not use a wildcard:

   ```bash
   npx wrangler d1 execute KRYONSEC_DB --remote \
     --command "SELECT id, email, email_verified FROM users WHERE email = 'you@example.com'"
   ```

   Require exactly one row, the expected email, and `email_verified = 1`.
   The `id` is an internal `u_` id; nothing the browser sends is trusted in
   its place.

3. **Back up the database first.** The export contains member emails, session
   hashes and key hashes. Keep it outside the repository and somewhere
   access-restricted; do not attach it to a ticket or commit it.

   ```bash
   npx wrangler d1 export KRYONSEC_DB --remote \
     --output=/secure/path/kryonsec-before-first-admin-$(date +%F).sql
   ls -l /secure/path/kryonsec-before-first-admin-*.sql
   ```

   Confirm the file exists and is not empty before continuing.

4. **Verify the schema and the current count.** Both must be read-only:

   ```bash
   npx wrangler d1 execute KRYONSEC_DB --remote --command "PRAGMA table_info(admins)"
   npx wrangler d1 execute KRYONSEC_DB --remote --command "SELECT COUNT(*) AS admins FROM admins"
   ```

   The table must have `user_id` (primary key), `email`, `granted_at` and
   `granted_by`. The count should be `0`; if it is not, stop — someone else has
   already granted an administrator, and this procedure does not apply.

5. **Insert only the verified account, with an audit trail.** Replace both
   `u_...` occurrences with the id from step 2 and the email with the exact
   address. `granted_by` is `'owner-runbook'` for this one row; every later
   grant names the acting administrator.

   ```bash
   npx wrangler d1 execute KRYONSEC_DB --remote --command "
   INSERT INTO admins (user_id, email, granted_at, granted_by)
   VALUES ('u_...', 'you@example.com', strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'owner-runbook');
   INSERT INTO admin_audit (actor, action, target, before, after, created_at)
   VALUES ('owner-runbook', 'admin.granted', 'u_...', NULL, 'owner-runbook', strftime('%Y-%m-%dT%H:%M:%fZ','now'));
   "
   ```

   Then read both rows back and check the id, email and audit target match
   exactly:

   ```bash
   npx wrangler d1 execute KRYONSEC_DB --remote \
     --command "SELECT user_id, email, granted_by FROM admins"
   npx wrangler d1 execute KRYONSEC_DB --remote \
     --command "SELECT actor, action, target FROM admin_audit ORDER BY id DESC LIMIT 1"
   ```

6. **Verify the administrator can open the desk.** Reload `/admin` in the
   signed-in browser. It must answer **200** with the dashboard, the operator's
   email in the header/lede, and a **SIGN OUT** control. No token is entered.

7. **Verify a normal account is still denied.** Sign in as a second,
   non-administrator account in a private window and open `/admin`. It must
   answer **403**, with no tabs, tables or review controls. A direct
   `POST /api/admin/action` from that account must answer **403** and leave the
   database unchanged.

8. **Roll back by deleting the row.** `DELETE FROM admins WHERE user_id = 'u_...'`.
   The account is refused on its next request. `admin_audit` keeps the record;
   deleting the row does not erase it.

### The legacy token door

`KRYONSEC_ADMIN_TOKEN`, or KV key `admin/token` when that variable is unset,
still authorises **`POST /admin`** with `token=<value>` and returns the
read-only legacy members and devices tables. It exists only for operator
tooling that already posts there.

- It cannot open the account dashboard, cannot mutate anything, and is not
  reachable from a form on the site — the token-entry page has been removed.
- A `GET /admin` never accepts a token: anonymous visitors are redirected to
  `/signin`, and signed-in non-administrators get 403.
- The token is never rendered, logged, or placed in a URL by the site. Do not
  put it in a query string. If you invoke the endpoint by hand, read it from an
  environment variable rather than typing it, so it does not land in shell
  history:

  ```bash
  curl -sS https://kryonsec.in/admin \
    --data-urlencode "token=${KRYONSEC_ADMIN_TOKEN:?set it in this shell}"
  ```

- Do not delete or rotate the secret or KV entry as part of a code change.
  Retire it only after the tooling that uses it is gone, and treat that as a
  separate, approved environment change.

---

## 6. Deploy

The Pages project deploys from git. Push the branch, merge, and Pages builds.

```bash
git push origin feat/beta-onboarding
```

Or deploy the working tree directly, skipping git:

```bash
npx wrangler pages deploy . --project-name kryonsec-landing
```

`wrangler pages deploy .` uploads whatever is in the directory, including
uncommitted and untracked files. Only run it from a clean checkout of the
commit being released; otherwise use the git path.

**Do this after the migrations, never before.** See §3.

Pages must serve `functions/` — no framework preset, no build command, output
directory is the project root. If `/api/license/verify` answers 404 in
production, the Functions directory was not picked up.

---

## 7. Rollback

**Code:** Pages → Deployments → pick the last good one → *Rollback to this
deployment*. Takes effect in seconds and needs no rebuild.

Rolling the code back is always safe. The migrations are additive, so the old
code runs against the new schema and the extra tables simply go unused. This
is the whole reason nothing here has an `ALTER` or a `DROP` in it.

**Schema:** there is deliberately no down-migration. If `0001` or `0002` has
to be undone, the tables are `users`, `identities`, `sessions`,
`applications`, `application_events`, `entitlements`, `entitlement_events`,
`cli_auth`, `cli_sessions`, `download_tokens`, `admins`, `admin_audit`,
`email_outbox`, `beta_program`, and `cli_login_codes`. Dropping them discards
every application and every decision recorded since the beta opened. Export
before you drop:

```bash
npx wrangler d1 export KRYONSEC_DB --remote --output=beta-backup-$(date +%F).sql
```

**Turning the beta off without a deploy:** set the programme flag off in
`beta_program`. `accessFor` then returns `programme_ended` for every beta
account at once, which stops the dashboard, the download gate and the CLI
together. Membership keys are unaffected — they do not consult it.

---

## 8. Smoke test after deploying

Run these in order. Each one failing names the step that was missed.

1. `/signin` shows **Sign in with GitHub** — and Google too, once its OAuth
   app exists. Until then Google is named as unavailable rather than offered
   as a dead link.
2. Sign in with one of them. You land on `/dashboard`.
3. A brand-new account sees "NOT APPLIED YET" and an **APPLY FOR ACCESS**
   button. It sees no install command and no machine list.
4. Submit the form at `/apply`. The dashboard says "IS IN REVIEW".
5. As the administrator, open `/admin` and approve it. The account's dashboard
   changes to "YOU ARE IN" with an install command.
6. On a Linux or WSL2 machine, run the Unix command from the dashboard. It
   installs using the one-time `dl_` link the dashboard minted.

   On a Windows machine, run the short command from the dashboard:

   ```powershell
   irm https://<site>/install.ps1 -OutFile "$env:TEMP\kryonsec-install.ps1"
   powershell -ExecutionPolicy Bypass -File "$env:TEMP\kryonsec-install.ps1"
   ```

   It opens `/beta/device` for approval, then polls with
   `purpose: "download"` and installs with the single-use link it receives.
   The Windows installer verifies `X-Kryonsec-Wheel-SHA256` and refuses a
   missing or mismatched hash. It is a copy of the CLI working tree: publish
   it only after the server that sends that header is live, or it will refuse
   the download by design. See `kryonsec/RELEASING.md`.

7. Run `kryonsec login` on that machine. It prints a link and a code.
8. Open the link, approve the machine. The terminal picks it up by itself and
   prints the email and a token prefix — never the token.
9. `kryonsec doctor` shows the account under Membership. `kryonsec login` on a
   *second* machine works the same way.
10. Back on `/dashboard`, the machine is listed with **1 SIGNED IN**. Press
    **SIGN OUT**, then wait for the next hourly check-in (or
    `kryonsec auth status` after an hour) — the machine is refused and told to
    run `kryonsec login` again.
11. `kryonsec logout` revokes from the terminal and says the token was revoked.
12. `kryonsec` on a machine with no account still opens Copilot mode. Purple
    Team still refuses, and now names both ways in.

Steps 7–11 are covered end to end by an automated check that runs the real CLI
against the real route handlers:
`node bridge-e2e.mjs` (kept outside this repository — it needs a Python
toolchain beside Node).

---

## 9. Waiting on a decision, not on code

These are the only things left, and none of them can be done from this
repository:

1. **Google OAuth app.** GitHub is configured in both environments and the
   beta works without Google; Google's client id and secret are not set
   anywhere. Create the app with the callback URLs in §4, then add the two
   variables to Production and Preview. Until then `/signin` offers GitHub
   only.
2. **An email provider and its API key.** `functions/_email.js` is a seam with
   exactly one working behaviour: log mode. With no provider configured,
   notification rows are marked sent and never delivered, so **applicants are
   not told anything** and must check the dashboard. Neither the subject lines
   nor the queue needs changing when a provider is chosen — one `switch` case
   in `send()` is the whole job.
3. **Deploying the beta code to production.** Production serves `main` at
   `f99136b`, which predates the beta; `feat/beta-onboarding` at `42d764b` is
   preview-only. The migrations are already applied (see §3), so only the code
   deploy remains — §6, when approved. Do not re-run the migrations.
4. **The first administrator.** §5. A person with database access, once.

Until 3 and 4 are done the beta is not usable on production; 1 adds a second
sign-in provider, and 2 only changes whether applicants are told about
decisions.
