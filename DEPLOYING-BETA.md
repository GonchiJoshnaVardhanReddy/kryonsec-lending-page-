# Deploying the beta

How to take the beta onboarding, approval, and command-line sign-in from this
working tree to kryonsec.in — and how to put it back.

Nothing in this repository deploys itself. Every step below is a person
running a command or clicking once in the dashboard, on purpose.

> **Status: not deployed.** As of this writing the code is committed to the
> `feat/beta-onboarding` branch and the migrations have been applied **locally
> only**. Nothing has been pushed, and production D1 has not been touched. See
> §9 for what is waiting on a decision.

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
- Google and GitHub OAuth apps — see §4. **Blocked: these do not exist yet.**

---

## 3. Migrations

Four files, applied in order. They are additive: nothing alters or drops an
existing table, which is what makes them safe to apply while members are using
the site.

```bash
# local, for development
npx wrangler d1 execute KRYONSEC_DB --local  --file migrations/0000_existing.sql
npx wrangler d1 execute KRYONSEC_DB --local  --file migrations/0001_beta.sql
npx wrangler d1 execute KRYONSEC_DB --local  --file migrations/0002_cli_login.sql

# production — only when you have read §9
npx wrangler d1 execute KRYONSEC_DB --remote --file migrations/0001_beta.sql
npx wrangler d1 execute KRYONSEC_DB --remote --file migrations/0002_cli_login.sql
```

`0000_existing.sql` is a no-op on production (`CREATE TABLE IF NOT EXISTS` for
tables that are already there). Run it locally so a dev database matches.

### Order matters in one direction

**`0002` must be applied before the code that reads `cli_sessions` is live.**
`dashboard.js` queries `cli_sessions` on the `active` branch — which is the
branch every currently-working account sees. Deploy the code first and those
accounts get a 500 instead of their dashboard.

So the safe order is always: **migrate, then deploy.** Never the other way
around.

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
| `KRYONSEC_GOOGLE_CLIENT_ID` | yes | Google OAuth client id |
| `KRYONSEC_GOOGLE_CLIENT_SECRET` | yes, *secret* | Google OAuth client secret |
| `KRYONSEC_GITHUB_CLIENT_ID` | yes | GitHub OAuth client id |
| `KRYONSEC_GITHUB_CLIENT_SECRET` | yes, *secret* | GitHub OAuth client secret |
| `KRYONSEC_ADMIN_TOKEN` | yes, *secret* | review-desk token (KV `admin/token`) |
| `KRYONSEC_FEEDBACK` | yes | KV binding for the feedback form |
| `KRYONSEC_REPO` | yes | `owner/name` the release lookup reads |
| `KRYONSEC_GITHUB_TOKEN` | no, *secret* | raises the GitHub API rate limit for release lookups |
| `KRYONSEC_EMAIL_PROVIDER` | no | leave unset: no adapter exists yet — see §9 |
| `KRYONSEC_EMAIL_FROM` | no | the From: address, once a provider exists |

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

For local work, add `http://localhost:8788/api/auth/<provider>/callback` as a
second allowed callback in each app.

---

## 5. The first administrator

**There is no bootstrap route and there will not be one.** No form, no
environment variable, and no first-run wizard creates an admin, because every
one of those is something an outsider can reach. An admin is a row, inserted
by a person with database access.

1. Sign in on the site with the account that should be the administrator. It
   will land on the dashboard with no access. That is expected.
2. Find the user id:

   ```bash
   npx wrangler d1 execute KRYONSEC_DB --remote \
     --command "SELECT id, email FROM users ORDER BY created_at DESC LIMIT 5"
   ```

3. Insert the row:

   ```bash
   npx wrangler d1 execute KRYONSEC_DB --remote \
     --command "INSERT INTO admins (user_id, email, granted_at, granted_by) \
                VALUES ('u_...', 'you@example.com', datetime('now'), 'bootstrap')"
   ```

   `granted_by` is `'bootstrap'` for this one row and the acting admin's id for
   every grant after it, so the audit trail names its own origin.

4. Reload `/admin`. The review desk appears.

Revoking an admin is deleting that row. `admin_audit` keeps the record of what
they did, and deleting the row does not erase it.

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

1. `/signin` shows **Sign in with Google** and **Sign in with GitHub**.
2. Sign in with one of them. You land on `/dashboard`.
3. A brand-new account sees "NOT APPLIED YET" and an **APPLY FOR ACCESS**
   button. It sees no install command and no machine list.
4. Submit the form at `/apply`. The dashboard says "IS IN REVIEW".
5. As the administrator, open `/admin` and approve it. The account's dashboard
   changes to "YOU ARE IN" with an install command.
6. On a Linux or WSL2 machine, run the command from the dashboard. It installs.
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

1. **Google and GitHub OAuth apps.** Client ids and secrets, callback URLs as
   in §4. Until they exist, `/signin` renders and every callback fails.
2. **An email provider and its API key.** `functions/_email.js` is a seam with
   exactly one working behaviour: log mode. With no provider configured,
   notification rows are marked sent and never delivered, so **applicants are
   not told anything** and must check the dashboard. Neither the subject lines
   nor the queue needs changing when a provider is chosen — one `switch` case
   in `send()` is the whole job.
3. **Applying the migrations to production D1.** Per the work brief, this is
   not something to do automatically. It is §3, run by hand, when you are
   ready.
4. **The first administrator.** §5. A person with database access, once.

Until 1–4 are done the beta is not usable by anyone but you, locally.
