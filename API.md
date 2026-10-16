# API contract

Every route this site serves, what authorises it, and what it answers. The
handlers carry the long-form reasoning; this is the index.

Reading the table: **auth** is what the request must present. *page* means it
renders HTML. *none* means deliberately unauthenticated — and where, the
comment in the handler says why.

---

## The shape of it

Three credentials, three ways in. They converge on one function.

```
   browser cookie ─┐
   CLI token ──────┼──>  accessFor(db, userId)  ──>  {entitled, status, reason}
   download token ─┘
```

`accessFor` in `functions/_store.js` is the only thing that decides. The
download gate, the license endpoint, the dashboard and the review desk all ask
it, so they cannot drift.

`status` is one of: `anonymous`, `unknown`, `programme_ended`, `none`,
`active`, `expired`, `revoked`, `suspended`. Only `active` is `entitled: true`.
`reason` is a complete sentence meant to be shown verbatim to the person.

---

## Authentication

| route | method | auth | answers |
|---|---|---|---|
| `/api/auth/[provider]/start` | GET | none | 302 to the provider (`google`, `github`), sets a signed state cookie |
| `/api/auth/[provider]/callback` | GET | state cookie | 302 to `next`. Creates or finds the user, links the identity, creates a session |

`next` is run through `safeNext()` before it is stored, which is the
open-redirect guard: the callback URL is one an attacker can hand a victim, and
`?next=` is exactly where a phishing flow wants to land them. Anything that is
not a plain same-site path — `//host`, `/\host`, `javascript:`, an embedded
control character — falls back to the default.

Identity is keyed on **(provider, subject)**. An email match never merges two
accounts. Scopes are `openid email` and `read:user user:email`; nothing that
reads a private repository is requested.

## Pages

| route | method | auth | notes |
|---|---|---|---|
| `/signin` | GET | none | redirects to the dashboard if already signed in |
| `/apply` | GET | session | the form; the route is not hidden, the POST is what authorises |
| `/dashboard` | GET | session | one page, one state, chosen by `accessFor` |
| `/admin` | GET | session + `admins` row | the review desk |
| `/beta/device` | GET | session | where a `kryonsec login` code is approved |
| `/logout` | POST | session + CSRF | POST only: a GET that signs out is revocable by an `<img>` tag |

## Applications and review

| route | method | auth | body → answer |
|---|---|---|---|
| `/api/apply` | POST | session + CSRF | the form → 303 to `/dashboard`. One active application per identity, enforced by a partial unique index |
| `/api/admin/action` | POST | session + `admins` + CSRF | `intent` + `back` → 303 to `/admin?status=…&msg=…` |

Both are guarded `UPDATE … WHERE`, and the affected row count is the answer:
1 means you did it, 0 means someone else already had.

`/api/admin/action` is three intents on one route rather than four routes,
because the guard they all need — session, then `admins`, then CSRF — is a
single decision that four routes would be four chances to get wrong:

```
intent=decide     decision=approve|reject|waitlist   application=<id>   reason
intent=access     action=grant|revoke|suspend        user=<id>          reason
intent=programme  status=active|ended
```

The redirect target is built by the route from a bare status word (`backTo`),
never taken from the form: a `next` param read out of a form is an open
redirect waiting for a reason to happen.

## Entitlement

There is no direct "grant" endpoint. Access is granted by approving an
application (`intent=decide&decision=approve`), and changed from the review
desk (`intent=access&action=…`). The programme itself is switched with
`intent=programme&status=ended`, which ends access for every beta account at
once — membership keys do not consult it.

## Downloads

| route | method | auth | answers |
|---|---|---|---|
| `/api/beta/download?t=<token>` | GET | `dl_` + 64 hex | 302 to the release asset. 15 minutes, single use, scoped to one user |
| `/api/download?key=<key>` | GET | membership key | 302 to the release asset. Unchanged legacy path |

The beta token is minted per dashboard page view. `pip` derives the wheel
filename from the URL path, not `Content-Disposition`, so the redirect target
matters.

## The command line

| route | method | auth | body → answer |
|---|---|---|---|
| `/api/beta/device/start` | POST | **none** | `{device_id, os, arch, version}` → `{code, device_code, url, expires_in_min}` |
| `/api/beta/device/poll` | POST | **none** | `{device_code}` → `{status, …}` |
| `/api/beta/device/approve` | POST | session + CSRF + entitled | `{code, decision}` → 303 back to `/beta/device` |
| `/api/beta/machines` | POST | session + CSRF | `{id, intent=revoke}` → 303 to `/dashboard#machines` |
| `/api/beta/cli/logout` | POST | `Authorization: Bearer s_…` | `{ok, revoked}` |

**`start` and `poll` are unauthenticated on purpose.** What `start` hands out
is inert: the code authorises nothing until a signed-in, entitled person
approves it, and `poll` refuses a code nobody approved. The alternative —
authenticating the request for a code — would mean the CLI already holds a
credential, which is the thing the flow exists to give it.

`poll` statuses:

```
{status: "pending"}                                   keep waiting
{status: "approved", token: "s_…", email, label, prefix}   store it
{status: "denied"}                                    the person said no
{status: "denied", reason: "…"}                       their access went away
{status: "expired"} | {status: "unknown"}             start over
```

`unknown` is the answer for a malformed code, a code that never existed, and a
code already collected — one value, so the endpoint cannot be asked which
codes were once real. The token is minted and the code claimed in the same
request, so two racing polls cannot produce two sessions, and an approval that
is never collected leaves no credential behind.

`logout` takes no id. The token is the credential and the subject at once, so
there is no id to aim at somebody else's machine. A dead token and a live one
get the same body, so a second logout is not an error.

## The license endpoint

| route | method | auth | answers |
|---|---|---|---|
| `/api/license/verify` | GET | `X-Kryonsec-Key` **or** `Authorization: Bearer s_…` | `{"valid": true\|false, "expires"?, "reason"?}` |

`?device=&os=&arch=&version=` are optional and are how a machine shows up as
alive. Nothing about the work being done is sent or stored.

**It answers 200 even when refusing.** The client reads any non-200 as "the
network is down" and falls back to a seven-day grace period, so serving a
revocation as a 4xx is what would keep a revoked key running. The verdict is
in the body.

A key is checked first, then a token. Both end at `accessFor`. The reason
string for a dead token is one sentence covering revoked, expired and
never-real, because the lookup makes those one thing.

## Legacy: the membership-key model

Unchanged, and still the path every existing install takes.

| route | method | auth |
|---|---|---|
| `/api/device/start` | POST | membership key |
| `/api/device/poll` | POST | membership key |
| `/api/device/claim` | POST | membership key |
| `/api/feedback` | POST | none (KV-backed, same-origin) |

## CLI environment overrides

The client reads these, so the whole journey can be pointed at a local server:

```
KRYONSEC_LOGIN_START_URL   KRYONSEC_LOGIN_POLL_URL   KRYONSEC_LOGOUT_URL
KRYONSEC_LICENSE_URL       KRYONSEC_CONNECT_START_URL   KRYONSEC_CONNECT_POLL_URL
```
