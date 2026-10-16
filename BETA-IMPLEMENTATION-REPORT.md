# Early access beta — implementation report

What was built, where it lives, what was actually verified, and what is
waiting on you.

**Nothing is deployed and nothing is pushed.** Both repositories have the work
committed on a feature branch, on this machine only. Production D1 has not
been touched.

| | landing (`kryonsec-landing`) | CLI (`kryonsec`) |
|---|---|---|
| branch | `feat/beta-onboarding` | `feat/beta-login` |
| head | `ff644bd` | `2f8171c` |
| commits | 9 | 2 |
| diff vs. base | 51 files, +9115 / −50 | 4 files, +919 / −35 |

The landing branch, oldest first — the last four are from this session:

```
24459ea  identity, entitlement, and the access gate
cf02d61  the way in — sign-in, apply, and sign-out
49184fd  the download gate, the applicant dashboard, and the beta install path
08db479  the review desk, and tokens at the license endpoint
97ee8fd  the CLI sign-in handshake
2914fdb  sign a machine out, from either end          <- this session
39added  how to deploy it, and what it does not protect against
b15b5ac  the API contract, in one table
ff644bd  the implementation report
```

---

## 1. Architectural findings

Both repositories were inspected before anything was written. The findings that
changed the plan:

**The landing page and the API are the same deployment.** Cloudflare Pages
serves the static site and picks up `functions/` automatically. There is no
backend to stand up, no CORS to configure, and no second service to keep in
sync. Every route in this report is a file in `functions/`.

**There were already two access models, and only one could be replaced.** The
`members`/`KRYONSEC_KEYS` model (a key emailed to a person, shared by whoever
holds it) is what every published install script depends on. Rewriting it in
place would break every existing member and every install script already in
the wild — which the brief forbids. So the beta model (`users` +
`entitlements`, revocable per account) was layered *beside* it. The download
gate and the license endpoint accept either, and a key always wins, on both
sides of the wire.

**One function had to own the answer.** `accessFor()` in `functions/_store.js`
is the only thing that decides whether an account has access. The download
gate, the license endpoint, the dashboard, and the review desk all call it. A
second implementation that drifts is how a revocation stops revoking on one
path while still working on another — so adding a door means calling it, not
re-deriving it.

**The site is rendered as strings, not a template engine.** Escaping is
therefore per-call-site: a field rendered without `esc()` is an XSS bug. This
drove a convention in the new table helpers (`{html: …}` versus a bare string)
so the difference is visible where a value is interpolated.

**The migrations must be additive, and that constrains everything.**
No `ALTER`, no `DROP`. That is what makes it safe to apply to a production
database with members on it, and it is what makes a code rollback always safe.

---

## 2. What was built

End to end: a person arrives at the landing page, signs in with Google or
GitHub, applies, is read by a human, is approved, downloads the software from
a one-time link, signs a machine in with `kryonsec login`, and can have that
machine signed out again from either the dashboard or the terminal.

- **Identity** — OAuth 2.0 authorization code + PKCE (S256), hand-rolled
  against `fetch`. Identity is a **(provider, subject)** pair. An email match
  never merges two accounts.
- **Application and review** — one active application per identity, enforced
  by a partial unique index; a review desk where every decision is a guarded
  `UPDATE … WHERE` whose affected row count is the answer.
- **Entitlement** — per account, per person, revocable, with a full audit
  trail in `admin_audit`.
- **Downloads** — a 15-minute single-use token minted per dashboard page view,
  so the install command is copy-pasteable without a copy-pasteable permanent
  credential.
- **CLI sign-in** — the device authorization grant (RFC 8628): the CLI asks
  for a code, prints it, and polls. A person approves it in a browser. The
  same flow is the headless fallback; `--no-browser` only skips the launch
  attempt, and no second protocol was invented.
- **Signing out** — two doors into one guarded UPDATE: the dashboard (session
  + CSRF, id scoped by `user_id` in the same statement) and the terminal (the
  token is the credential and the subject, so there is no id to aim at anybody
  else's machine).

Full route list: **[API.md](API.md)**. Credential model and its limits:
**[SECURITY-NOTES.md](SECURITY-NOTES.md)**.

---

## 3. Files changed

### `kryonsec-landing` (branch `feat/beta-onboarding`)

**Schema — `migrations/`**

| file | contents |
|---|---|
| `0000_existing.sql` | `members`, `devices`, `device_codes` — the 2026-09 key model, written down so a dev database matches production. A no-op on production. |
| `0001_beta.sql` | `users`, `identities`, `sessions`, `applications`, `application_events`, `entitlements`, `entitlement_events`, `cli_auth`, `cli_sessions`, `download_tokens`, `admins`, `admin_audit`, `email_outbox`, `beta_program` |
| `0002_cli_login.sql` | `cli_login_codes` — the `kryonsec login` handshake |

**Shared logic — `functions/_*.js`**
All new except `_shared.js` (extended): `_auth.js` (users, identities,
sessions, CSRF), `_oauth.js` (the provider handshake), `_store.js` (the
entitlement layer and `accessFor`), `_cli.js` (CLI sessions and download
tokens), `_email.js` (the notification queue), `_pages.js` (the page shell and
components), `_release.js` (the release lookup)

**Routes — `functions/`**
`api/auth/[provider]/start.js`, `api/auth/[provider]/callback.js`,
`api/apply.js`, `api/admin/action.js`, `api/beta/download.js`,
`api/beta/device/{start,poll,approve}.js`, `api/beta/machines.js`,
`api/beta/cli/logout.js`, `api/license/verify.js` (extended),
`api/download.js`, `api/device/*`, `api/feedback.js`

**Pages** — `signin.js`, `apply.js`, `dashboard.js`, `admin.js`,
`beta/device.js`, `logout.js` (all new except `admin.js`, extended)

**Presentation** — `style.css` (+72 lines, **zero deletions**), `index.html`
(two lines: the early-access paragraph and the CTA href),
`install.sh` / `install.ps1` (the `KRYONSEC_DOWNLOAD_URL` branch)

**Docs** — `API.md`, `DEPLOYING-BETA.md`, `SECURITY-NOTES.md`,
`.dev.vars.example` (all new), `README.md` (pointers), `.gitignore`

**Tests** — 11 new test files plus `tests/verify.test.mjs` extended, and
`tests/helpers/d1.mjs`, which runs the real schema against `node:sqlite` so the
tests exercise the actual `CREATE TABLE` statements rather than a hand-written
fixture. The three test files that already existed are untouched.

### `kryonsec` (branch `feat/beta-login`)

| file | change |
|---|---|
| `src/kryonsec/auth.py` | new, 375 lines — `login`, `logout`, `status`, the credential file |
| `src/kryonsec/license.py` | +167/−35 — sends the bearer token, per-credential cache, two bug fixes (§7) |
| `src/kryonsec/cli.py` | +42 — the three subcommands |
| `tests/test_auth.py` | new, 370 lines, 24 tests |

---

## 4. Verified

Every number below is from a run during this work, not an estimate.

| suite | command | result |
|---|---|---|
| CLI, full | `py -3.13 -m pytest -q` | **1700 passed, 3 skipped** (4:29) |
| landing, full | `node --test "tests/*.test.mjs"` | **203 pass, 0 fail** (0.35s) |
| the whole journey | `node bridge-e2e.mjs` | **24/24 checks** |

**The bridge check is the one that matters.** The two suites each verify their
own half of the wire; neither can tell you the halves agree. That check starts
a real HTTP server backed by the real route handlers over the real schema,
runs the actual `kryonsec` process as a subprocess against it, and asserts the
field names, status strings and `Authorization` header line up. It covers:
not-signed-in, login, the token on disk, the server's view of the machine,
`auth status`, a dashboard revocation, the refusal that lands on the next
check-in, signing in again, and `logout`. It is deliberately not committed as
a test — it needs a Python toolchain beside Node, and the landing suite should
not.

No test was weakened to pass. Two assertions were strengthened after they
failed for the right reason; both are described in §7.

**Compatibility with what already existed.** The membership-key path is
unchanged and covered by its own tests, including one that asserts a key still
wins over a token. 1700 tests pass on the CLI, which is the whole of its
existing suite plus the new ones. No test was deleted or skipped.

---

## 5. Visual regression

**Honest scope: structural proof plus two screenshots, not a pixel-diff
suite.** There is no baseline-image harness in this repository and adding one
was not part of this work.

What was actually checked:

- `git diff main...HEAD -- style.css` → **72 insertions, 0 deletions.** Not a
  single rule changed or removed; every addition is a new class.
- `git diff main...HEAD -- index.html` → two lines, a paragraph's text and one
  `href`. No element, class, or attribute changed.
- The landing page was rendered at 1440px and at 390px on both `main` and the
  branch, from two local servers, and the early-access section compared. Same
  fonts, same colours, same button styling, same spacing, same responsive
  stacking. The only visible difference is the paragraph, which went from five
  lines to six.

One thing the comparison caught: the YouTube iframe renders oddly at phone
width. Rendering `main` showed the same thing, so it is pre-existing and
unrelated — and the artefact was a capture mid-load.

The new pages (sign-in, apply, dashboard, review desk) were built from the
existing component classes — `review-card`, `admin-table`, `install-command`,
`button`, `statusPill`, `notice` — so they read as the same design rather than
a second one. `style.css` gained only what genuinely did not exist.

---

## 6. Deployment and rollback

The runbook is **[DEPLOYING-BETA.md](DEPLOYING-BETA.md)**. The two things in
it worth knowing without opening it:

**Migrate, then deploy — never the reverse.** `dashboard.js` queries
`cli_sessions` on the `active` branch, which is the branch every currently
working account sees. Deploy the code first and those accounts get a 500
instead of their dashboard. The opposite order is always safe, because the
migrations only add tables.

**Rollback is a Pages deployment rollback**, and it is always safe for the same
reason. There is deliberately no down-migration: dropping those tables
discards every application and every decision recorded since the beta opened,
so the runbook says export first.

---

## 7. Bugs found and fixed along the way

Four of these were pre-existing, found by following the code I was changing
rather than by looking for them.

1. **The device id was thrown away daily.** `device_id()` minted an id into the
   state file, then `verify()` wrote a fresh dict over the whole file and
   dropped it. The review desk therefore saw a brand-new machine every day.
   Fixed by merging instead of replacing.
2. **The daily license cache could replay a revoked account's "valid".** It
   was keyed on the clock alone, so signing out and back in as a since-revoked
   account — or swapping a key in `config.toml` — would replay the previous
   account's answer for up to a day. That is exactly the window revocation
   exists to close. Now keyed on which credential was checked.
3. **The dashboard promised "immediately" and the code did not deliver it.**
   The card said signing out stops a token working immediately. It ends the
   session on the server immediately, but the machine is not connected to the
   dashboard and nothing is pushed to it — it asks once a day. The claim was
   false, and the fix was two-sided: the token's check interval is now hourly
   (`TOKEN_CHECK_INTERVAL_H`), and the copy says what actually happens. Offline
   behaviour is untouched, because a failed check falls through to the
   seven-day grace period, which is the offline mechanism.
4. **`.dev.vars` was not git-ignored.** It holds the same values the Pages
   project keeps encrypted, so a filled-in copy was one `git add .` from being
   a credential in the repository. Now ignored, with the example file exempted.
5. **A denial blamed the wrong party.** `poll` answers `denied` both when the
   person clicked no and when the entitlement behind the approval was withdrawn
   in the minutes since — and sends a reason for the second. The CLI discarded
   it and told people they had declined in a browser they had already closed.

---

## 8. Security limitations that need you

Full detail in **[SECURITY-NOTES.md](SECURITY-NOTES.md)**. The ones that are
decisions rather than bugs:

**Revocation is not instantaneous, and should not be sold as if it were.** The
session dies on the server the moment the button is pressed, but a machine
that holds the token keeps working for up to an hour, and offline for up to
seven days. A membership key is worse: up to a day online, and it is not
revocable in any meaningful sense at all. **An engagement already running is
never stopped** — the gate is checked when an engagement starts, because
killing a live scan mid-run is its own safety problem.

**There is no admin bootstrap, deliberately.** No form, no environment
variable, and no first-run route creates an administrator, because every one of
those is something an outsider can reach. Seeding it is a manual insert; the
runbook has the SQL. A fresh deployment has no admins until you run it, and the
review desk is unreachable until then.

**No email is sent.** `functions/_email.js` is a seam whose only working
behaviour is log mode: with no provider configured, notifications are marked
sent and never delivered, so **applicants are told nothing** and must check the
dashboard. One `switch` case is the whole job once you pick a provider.

**The sign-in code limiter is a global cap, not per-IP.** It stops a runaway
loop from filling the table; it does not stop a distributed flood. Per-IP
capping belongs on the Cloudflare zone, where it costs nothing and sees the
real client address.

**The membership-key model cannot be fixed from here** — keys are shared and
all-or-nothing. Changing that breaks every existing member and every published
install script, which the brief forbids. The beta layer sits beside it and the
difference is documented rather than hidden.

**Nothing here loosens Purple Team.** Beta access grants permission to use the
product; it does not grant authorisation to attack any target. Every existing
human-approval, target-authorisation, allowlist and Docker/gVisor control is
unchanged, and Purple Team tool execution was not run in this environment
because this environment cannot run it.

---

## 9. Blocked on you

Four things, and none of them can be done from either repository:

1. **Google and GitHub OAuth apps.** Client ids and secrets, with redirect
   URIs `https://kryonsec.in/api/auth/google/callback` and
   `https://kryonsec.in/api/auth/github/callback`. Until these exist, `/signin`
   renders and every callback fails. Scopes needed: `openid email` and
   `read:user user:email` — nothing that reads a private repository, because
   authenticating someone is not a reason to ask for their code.
2. **An email provider and its API key.** Until then, no applicant hears
   anything back.
3. **Applying the migrations to production D1.** Two commands, in the runbook.
   Deliberately not done automatically.
4. **The first administrator.** One `INSERT`, in the runbook.

Plus one decision from earlier that is still open: getting v1.3.7 onto your
WSL2 install. You chose to re-run the official installer, and that still needs
a membership key or a beta account — which is what item 1 unblocks.

---

## 10. Not done, and said plainly

- **Nothing is pushed.** The brief says not to deploy to production
  automatically; a push to the landing repository *is* a deploy. Both branches
  are local.
- **The `kryonsec` repository's `main` is one commit ahead of `origin/main`**
  (`f4ef1af`). That was true before this work started and I left it alone.
- **The CLI's browser-launch path is untested.** `--no-browser` and the printed
  path are covered; `webbrowser.open()` returning `False` on a headless box is
  handled in code and exercised only by hand.
- **No account unlinking.** A person who signs in with both providers is linked
  on first sight and there is no UI to undo it.
- **Sessions do not rotate.** 90 days, no rotation on privilege change.
- **The `02 / THE COMMAND LINE` card renders only in the dashboard's `active`
  state**, so an account in review never sees it. That is intentional; noting
  it so it is not mistaken for a bug.
