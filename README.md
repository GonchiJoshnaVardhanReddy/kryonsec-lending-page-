# KryonSec beta portal

Fresh Cloudflare Pages account and application system on https://kryonsec.in.
The sculptural product homepage is retained. The old membership, CLI login,
installer, admin-token, feedback, and account APIs are retired (HTTP 410).

## Routes
- `/account` — GitHub/Google sign-in
- `/apply` — four-step professional beta application
- `/dashboard` — applicant status, submitted answers, and review feedback
- `/admin` — founder-only queue, full applications, private notes, decisions, history

The founder is the verified GitHub subject `170815623`. Email and client-supplied
roles never grant administrator access. Use GitHub to enter the review desk.
Google identities with the same email are not administrators.

## Deployment
Pages deploys `main`, project `kryonsec-landing`, with no build command and `/` output.
`functions/[[path]].js` routes requests to `server/portal.mjs`.
Apply `migrations/0003_portal.sql` to existing D1 binding `KRYONSEC_DB` before release.
New portal tables use the `portal_` prefix. The database itself is preserved.
Old user data is cleared separately, in dependency order, once the new code is live.
Never automatically rerun a user-data reset during normal releases.

## OAuth
Keep these production environment settings in Cloudflare, never git:
- KRYONSEC_GITHUB_CLIENT_ID / KRYONSEC_GITHUB_CLIENT_SECRET
- KRYONSEC_GOOGLE_CLIENT_ID / KRYONSEC_GOOGLE_CLIENT_SECRET
Exact callbacks: `https://kryonsec.in/api/auth/github/callback` and
`https://kryonsec.in/api/auth/google/callback`.
Unconfigured providers are disabled. Google needs an externally configured Web
application OAuth client; adding code cannot provision that credential.

## Security and behavior
Server-stored, one-use OAuth state, PKCE, verified provider emails, hashed 24-hour
sessions, CSRF and origin checks, bounded JSON bodies, rate limits, server-side
validation, escaped DOM rendering, owner-only reviews, optimistic concurrency,
and transactional audit triggers. No automatic merge by email or OAuth token storage.
Private review notes never appear in applicant responses.
Approval does not distribute a binary or grant a target-testing authorization.
No decision emails are sent; users check the dashboard.

Run `node --test tests/*.test.mjs`.

## Feedback and First 50 edition
Apply `migrations/0004_feedback_cards.sql` before deploying this version. It only
adds tables, an approval trigger, and cards for existing approved accounts; it
never resets account data. Existing approvals are ordered by first approval time.
Cards #001–#050 are issued atomically on approval. Numbers remain reserved after
revocation or account deletion. Accounts using different providers remain separate.

`/feedback` requires sign-in and stores bug reports, ideas, experience ratings and
messages privately. The review desk has a **Read tester feedback** action.
Approved cardholders can choose a display name and download a 2400×1260 PNG from
their dashboard. Cards are private by default. Opting into sharing enables an
unguessable `/beta/card/<id>` page with only display name and edition number.
Disabling sharing or revoking approval disables the public page and SVG.
Previously downloaded images or third-party copies cannot be recalled.
Social posts should attach the downloaded PNG; automatic image unfurling is not
provided. No posts are sent automatically.

Google setup: create a Web application client in Google Auth Platform; configure
an External audience and the `openid`, `email`, `profile` scopes. The exact
redirect is `https://kryonsec.in/api/auth/google/callback`. Set
`KRYONSEC_GOOGLE_CLIENT_ID` and `KRYONSEC_GOOGLE_CLIENT_SECRET` as production
Cloudflare Pages secrets, then redeploy. No JavaScript origin is required by this
server-side redirect flow. Keep the secret out of the repository and chat.
