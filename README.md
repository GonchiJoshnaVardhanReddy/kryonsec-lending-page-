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
