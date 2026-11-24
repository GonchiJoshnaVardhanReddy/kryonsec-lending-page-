# KryonSec by RahaSec — separate beta accounts

The static Sites preview is independent of this Cloudflare Worker. Do not deploy custom OAuth into the Sites Worker runtime. This bundle is specifically for the user's Cloudflare account.

## Prepared
- Sculptural entrance and scroll animations; reduced-motion support and pause control.
- GitHub OAuth authorization-code flow with state, PKCE, verified primary email.
- Secure/HttpOnly/SameSite cookies; 24-hour sessions, hashed database tokens.
- D1-backed application records with versioned acknowledgements.
- Founder authorization by stable GitHub ID, never user-submitted roles or email.
- Guarded review decisions and transactional audit insertion.
- Same-origin + session-CSRF checks, bounded request bodies, input validation, rate limits, CSP.
- Pending, approved, declined and revoked states. Account logout.
- Security regression tests using Node SQLite: `node --test tests/accounts.test.mjs`.

## Deployment blocked pending founder approval
Automatic approval review rejected creation of `kryonsec-sculptural-accounts` in Cloudflare account `c9762363964f9c580e58ab52ade82546`, citing billing/production boundaries. No database was created and no Cloudflare Worker was uploaded in this task.

Proposed isolated Worker: `kryonsec-beta`. Keep existing rahasec.com and kryonsec.in deployments unchanged until the founder explicitly chooses domain cutover.

1. Obtain approval for the new D1 database and Worker, staying on the existing plan without upgrades.
2. Create the D1 database and apply cloudflare/schema.sql to that new database only.
3. Build with `node cloudflare/build.mjs`. The bundle embeds static assets; the API upload is an ES module named worker.mjs.
4. Bind DB as d1 with the returned database ID.
5. Bind APP_ORIGIN to the selected HTTPS origin. If choosing the unused worker name above, confirm the returned workers.dev URL before registering OAuth.
6. Bind ADMIN_GITHUB_ID to `170815623`, verified from the founder's connected GitHub profile, GonchiJoshnaVardhanReddy.
7. Create a new GitHub OAuth app using the final homepage and `<APP_ORIGIN>/auth/callback`. Keep its secret in Cloudflare encrypted secrets, never source control or chat. Configure GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.
8. Keep POLICIES_READY=false until founder review of beta-guide.html and privacy.html, especially the legal operator identity and retention schedule. Set true only after that review.
9. Configure the scheduled handler daily (cron `17 3 * * *`) to clean expired sessions, state records and rate limits.
10. Verify with real GitHub accounts: founder and unrelated tester; pending applicant cannot access onboarding; founder can approve; non-founder cannot see the review desk; revoked account loses membership; logout and replayed OAuth state fail.

## Explicit limits
- Tests run against real SQLite through a D1-shaped test adapter, not live D1 or live GitHub OAuth.
- This is a beta membership/application portal. The CLI currently needs a separately verified access integration. No installer/download links are exposed, even for approved accounts. Approval does not license or technically unlock an existing local binary.
- No automatic decision emails or marketing messages are sent. Applicants check their dashboard.
- Rate limits are basic ten-minute D1 counters. Platform WAF/Turnstile and abuse monitoring should be reviewed before broad public launch; do not advertise this as a complete security audit.
- Applicant account information is not logged. Rate-limit keys are hashes, not anonymization guarantees. Database backups/provider logs need to be included in final retention handling.
- Acknowledgements and beta-use guidelines are not a substitute for jurisdiction-specific legal review.
