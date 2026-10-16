# Security notes

What the beta access system enforces, and — the part that matters more — what
it does not. Every limitation below is a real property of the deployed code,
not a roadmap item. If a sentence here stops being true, it is a bug.

Written against migrations `0001_beta.sql` and `0002_cli_login.sql`.

---

## 1. The credential model

Three credentials exist. They are not interchangeable, and each one has a
different revocation story.

| | what it is | how it is checked | revocable? |
|---|---|---|---|
| **membership key** | `KRYO-XXXX-XXXX-XXXX`, emailed, typed once | a flat allowlist (`KRYONSEC_KEYS`) | **no** — removing it takes effect at the next check-in, up to 7 days later offline |
| **browser session** | opaque cookie, hashed at rest, 90 days | `sessions` row, `revoked_at IS NULL` | yes, immediately |
| **CLI token** | `s_` + 64 hex, 90 days, one per `kryonsec login` | `cli_sessions` row, hashed at rest | yes — see §3 for the window |

Identity is a **(provider, subject) pair**, never an email address. Two
accounts are never merged because two providers returned the same email
string; a matching email is not evidence that the same person is on both
sides, and merging on it hands one person's access to whoever controls the
other provider's account with that address.

The download gate additionally accepts a **download token** (`dl_` + 64 hex,
15 minutes, single use). It is minted per dashboard page view, scoped to one
user, and is worthless after one use. It exists so an install command can be
copy-pasteable without a copy-pasteable permanent credential.

### Where the decisions are made

One function answers "may this account do this": `accessFor(db, userId)` in
`functions/_store.js`. The download gate, the license endpoint, the dashboard,
and the admin view all call it. Adding a fifth door means calling it too, not
re-deriving the answer — a second implementation that drifts is how a
revocation stops revoking on one path while working on another.

---

## 2. What is not stored

- No passwords. There is no password field anywhere in the schema, and no
  password is ever requested or accepted — OAuth or nothing.
- No provider tokens. The OAuth access/refresh tokens are used to read the
  subject and email during the callback and are then discarded.
- No raw session or CLI tokens. Both are stored as SHA-256 hashes; the
  plaintext exists only in the client's cookie or file. Revocation is a row
  delete or an update, and a database dump does not contain a usable
  credential.
- No email bodies. `email_outbox` stores the kind, the address, and a
  rendered subject/body at send time. Decision reasoning lives in
  `admin_audit`, not in mail.
- No secrets in URLs, except the download token — deliberately, see §4.

Logs carry envelope information only (`mail: log <kind> -> <id>`). No token,
no cookie, no OAuth code, no applicant free-text.

---

## 3. Revocation is not instantaneous

This is the most important honesty item in this file.

**A CLI token is checked hourly, not continuously.** `kryonsec` does not hold
a connection to the server and nothing is pushed to it. It phones home at most
once an hour (`TOKEN_CHECK_INTERVAL_H` in `src/kryonsec/license.py`) and
otherwise trusts the answer it cached in its own state file.

So when a machine is signed out from the dashboard:

- the `cli_sessions` row is dead **immediately** — every server-side check
  refuses it from that moment, including a fresh `kryonsec login` on that
  machine, the download gate, and any other client;
- the machine that holds the token keeps working **for up to an hour**, until
  its next check-in.

A membership key is worse: the daily interval applies (`CHECK_INTERVAL_H`),
and a failed network check falls back to a seven-day grace period, so removing
a key from `KRYONSEC_KEYS` can take up to a day online and longer offline.

**Offline is a deliberate hole.** `GRACE_DAYS = 7` exists so a member on a
plane or in an air-gapped network is not locked out by a check that cannot
run. The cost is that revocation cannot reach a machine that is not talking to
the server. That trade is intentional and this file is where it is admitted.

**Consequence for Purple Team:** an engagement already running is never
stopped. The gate is checked when an engagement *starts*
(`ensure_purple_allowed`), because killing a live scan mid-run is its own
safety problem. A revocation therefore means "no new engagements", not "stop
now".

---

## 4. Tokens in URLs

The install command on the dashboard embeds the download token in a query
string. That is a real exposure and it is bounded deliberately:

- 15-minute lifetime (`CODE_TTL_MIN`), single use, scoped to one user;
- minted per page view, so it is never a long-lived link that gets forwarded;
- it grants exactly one thing — one download of the release archive — and
  nothing else. It is not a session and cannot be exchanged for one.

Because query strings land in access logs, proxy logs and `Referer` headers,
**no other credential is ever passed in a URL.** The license endpoint reads
`X-Kryonsec-Key` as a header and only still accepts `?key=` for installs built
before the header existed.

---

## 5. The CLI login handshake

Modeled on the device authorization grant (RFC 8628), hand-rolled against
`fetch`, no dependency.

- The **short code** a person reads off the screen and the **secret
  `device_code`** the CLI polls with are separate values. Someone who glimpses
  the URL, a screenshot, or a shoulder-surfed code cannot collect the answer.
- The code grants **nothing** until a signed-in, entitled person approves it
  in a browser. `POST /api/beta/device/start` is therefore unauthenticated by
  design — the thing it hands out is inert.
- Approval **mints nothing**. Collection mints the token and claims the code
  in the same request (a guarded `UPDATE … WHERE approved_at IS NULL`), so a
  login approved and abandoned leaves no live credential, and two racing polls
  cannot produce two 90-day sessions.
- The entitlement is read **twice** — at the click and again at collection,
  minutes apart — so a revocation in between counts.
- A refusal is the same message for every dead-code shape (`unknown`,
  `expired`, `already collected`), so the endpoint cannot be polled to learn
  which codes were once real.
- **No improvised password protocol.** The manual/headless path is the printed
  URL and code — the same flow, with the browser launch skipped. There is no
  fallback that asks for a Google or GitHub password, a provider token, a
  membership key, or a website cookie in the terminal.

`kryonsec login` deliberately **refuses** on a machine that already holds a
membership key: the server checks the key first, so a token stored alongside
one would never be consulted, and accepting it would look like it worked.

---

## 6. Admin access

Authorisation is a row in `admins`, keyed on `user_id` — not an email
allowlist, and not a flag that a form can set. Hiding a button in the frontend
is not authorisation; every admin route re-reads the row.

Every admin mutation is a guarded `UPDATE … WHERE` whose affected row count is
the answer: 1 means you did it, 0 means someone already had. Two admins
deciding the same application at the same moment produce one decision and one
no-op, not two events.

Decisions are written to `admin_audit` with the acting `user_id` and email.

> **Not yet done: there is no admin bootstrap.** The `admins` table exists and
> nothing seeds it, so a fresh deployment has no administrators and the review
> desk is unreachable. Seeding it is a manual, deliberate insert performed by
> the founder — see `DEPLOYING-BETA.md` §5. No public form, environment
> variable, or first-run route creates an admin, and none should.

---

## 7. Browser-side defences

- Sessions are opaque 256-bit values; the cookie is `HttpOnly`, `Secure`,
  `SameSite=Lax`, and the database stores only its hash.
- **CSRF is derived, not stored**: `sha256(session_token + ":csrf")`. Nothing
  extra is written, and a token cannot be replayed against another session.
- CSRF is layered with `Origin` and `Sec-Fetch-Site` checks on every
  state-changing route. Note that both headers are supplied by the browser and
  are a second opinion, not the primary control; `SameSite=Lax` plus the
  derived token are what actually hold.
- Every revocation from the dashboard and the admin desk is a **POST form**,
  never a link. A `GET` that revokes is revocable by an `<img>` tag on any page
  on the internet.
- All interpolated values pass through `esc()`. The pages are rendered as
  strings, so escaping is per-call-site by construction — a new field rendered
  without `esc()` is an XSS bug, and the `{html: …}` convention in the table
  helpers exists to make the difference visible at the call site.
- Rendering is `style-src 'self'` / `script-src 'self'` via `_headers`. No
  inline script or style, so a stored XSS payload has no execution path.

---

## 8. Abuse and denial of service

- One active application per identity, enforced by a **partial unique index**
  (`idx_applications_active`) rather than a read-then-write. The database is
  what makes a double submit impossible; a check in the handler would only
  narrow the race.
- `POST /api/beta/device/start` is capped globally at 60 requests/minute.
  **`ponytail:` this is a global cap, not per-IP** — it stops a runaway loop
  from filling the table, and it does not stop a distributed flood. Per-IP
  capping belongs at the Cloudflare zone (rate limiting rules), where it
  costs nothing and sees the real client address.
- Unapproved login codes expire in 15 minutes; a code claimed at collection is
  deleted, not marked.
- Tokens are looked up by hash, and every lookup goes through a prepared
  statement with bound parameters. No string-built SQL anywhere in
  `functions/`.

---

## 9. Failure modes: what closes and what opens

The rule throughout is **fail closed where the answer is a decision, fail
soft where the answer is telemetry**.

| condition | behaviour |
|---|---|
| no `KRYONSEC_DB` bound | token and session paths return 503 / `valid: false`. Keys still work, exactly as before. |
| the license endpoint is unreachable | the CLI falls back to grace (up to 7 days), never to "allowed" |
| the download gate cannot authorise | no download |
| the dashboard cannot record a machine | the check-in still succeeds; a table row is not worth a refused member |
| the email provider is not configured | messages are marked sent and the envelope is logged. **They are not delivered.** See §10. |
| `admins` has no rows | no admin routes; the review desk renders nothing |

---

## 10. Known limitations, by name

These are real. Each one is either blocked on the founder or accepted on
purpose.

1. **No email is actually sent.** `send()` in `functions/_email.js` is a seam
   with one behaviour: log mode. With no provider configured it reports success
   so the queue drains, and it logs the envelope. Applicants are therefore
   **not** notified — they must check the dashboard. Blocked on choosing a
   provider and holding an API key.
2. **No admin bootstrap.** See §6. Blocked on a founder decision; the seeding
   insert is documented, not automated.
3. **Revocation window of up to one hour** for a CLI token, up to a day plus
   grace for a key. See §3.
4. **`start` is rate-capped globally, not per IP.** See §8.
5. **Sessions live 90 days with no rotation** and no absolute cap beyond that.
   Rotation on privilege change is not implemented.
6. **No account unlinking.** A person who signs in with both Google and GitHub
   is linked by verified subject on first sight and there is no UI to undo it.
7. **The membership-key model cannot be fixed from here.** Keys are shared,
   all-or-nothing, and not per-user. Rewriting that model would break every
   existing member and every published install script, which the work brief
   forbids. The beta layer sits beside it; the difference is documented rather
   than hidden.
8. **The CLI's browser launch is untested.** `--no-browser` and the printed
   path are covered by tests; `webbrowser.open()` returning `False` on a
   headless box is handled in code and exercised only by hand.
9. **Purple Team tool execution has never run in this environment.** It is
   gated behind the Linux/Docker/gVisor check and this work did not touch it.
   Nothing here loosens it: beta access grants permission to use the product,
   not authorisation to attack any target, and every existing human-approval,
   target-authorisation and tool-allowlist control is unchanged.

---

## 11. Reporting

Security issues go to the address on kryonsec.in. Please do not open a public
issue for anything involving access to another account.
