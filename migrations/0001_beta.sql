-- Kryonsec landing page — D1 schema, part 1: beta onboarding, review, and
-- entitlement.
--
-- Apply 0000_existing.sql first. That file is a no-op on production; this one
-- is not.
--
--   wrangler d1 execute KRYONSEC_DB --local  --file migrations/0000_existing.sql
--   wrangler d1 execute KRYONSEC_DB --local  --file migrations/0001_beta.sql
--
--   # production, when you are ready — see DEPLOYING-BETA.md
--   wrangler d1 execute KRYONSEC_DB --remote --file migrations/0001_beta.sql
--
-- Nothing here drops or rewrites an existing table, so a member who is on a
-- membership key today keeps working exactly as before. The beta path is
-- additive on purpose: there is no migration of live customers in this file,
-- and that is what makes it safe to apply to production with people on it.
--
-- ---------------------------------------------------------------------------
-- Why there are two access models in one database
-- ---------------------------------------------------------------------------
--
-- `members` is the 2026-09 model: a membership key is the credential, a
-- person is a row created when a machine connects. `users` is the beta model:
-- a person is an OAuth identity, and access is an entitlement they hold.
--
-- Both are live. The download gate and the license endpoint accept either
-- (see the "entitlement layer" branch in api/download.js and
-- api/license/verify.js). Rewriting the key model in place would break every
-- existing member and every install script already published, and the brief
-- for this work says explicitly not to. So the key model stays, and the beta
-- model is layered beside it, sharing nothing but the database.
--
-- The one thing that does NOT carry over is revocation granularity: a key in
-- KRYONSEC_KEYS is all-or-nothing and shared by whoever holds it. The beta
-- path revokes per user. That difference is real and is documented rather
-- than papered over — see SECURITY-NOTES.md.

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

-- One person. Created on first successful OAuth sign-in; it carries no
-- credential of its own.
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,          -- 'u_' + 32 hex
    email           TEXT NOT NULL,             -- most recent verified address
    email_verified  INTEGER NOT NULL DEFAULT 0,-- 1/0, as the provider stated it
    name            TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- A provider login. The key is (provider, subject) and never the email:
-- the brief is explicit that two providers returning the same email string
-- must not be treated as the same person, because email is not a stable
-- identifier at either provider — it can be changed, and it can be recycled
-- onto a different account.
--
-- There is deliberately no unique index on (provider, email) and none on
-- email alone. Adding one would silently prevent a legitimate second person
-- from signing in with a recycled address, and would turn "same email" into
-- an account-merge trigger. Linking two identities to one user is an
-- explicit, signed-in action or it does not happen.
CREATE TABLE IF NOT EXISTS identities (
    provider        TEXT NOT NULL,             -- 'google' | 'github'
    subject         TEXT NOT NULL,             -- the provider's stable user id
    user_id         TEXT NOT NULL REFERENCES users(id),
    email           TEXT,                      -- as this provider reported it
    email_verified  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT,
    PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_identities_user ON identities (user_id);

-- ---------------------------------------------------------------------------
-- Website sessions
-- ---------------------------------------------------------------------------

-- The primary key is the SHA-256 of the cookie value, not the cookie value.
-- A session cookie is a bearer credential, and this table is the one an
-- attacker reads first if they get a dump — storing the hash means a dump
-- yields no usable session. Verification is a single indexed lookup on the
-- hash, so there is no cost to it.
--
-- There is no `user_id`-only uniqueness: a person may be signed in on a
-- phone and a laptop at once.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash      TEXT PRIMARY KEY,          -- sha256 hex of the cookie value
    user_id         TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    last_seen_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Application and review
-- ---------------------------------------------------------------------------

-- An application is a request for access. It is NOT access — the entitlement
-- table below is access, and the download gate reads that, not this. Keeping
-- them apart is what makes "approved but later suspended" expressible.
CREATE TABLE IF NOT EXISTS applications (
    id                  TEXT PRIMARY KEY,      -- 'a_' + 32 hex
    user_id             TEXT NOT NULL REFERENCES users(id),
    status              TEXT NOT NULL
                        CHECK (status IN ('pending','approved','rejected','waitlisted')),

    -- What the applicant told us. All optional except the acknowledgement —
    -- a short form is one people finish, and every field here is one more
    -- reason to abandon it.
    full_name           TEXT,
    contact_email       TEXT,
    github_username     TEXT,
    portfolio_url       TEXT,
    role                TEXT,
    primary_os          TEXT,
    intended_use        TEXT,
    experience          TEXT,
    feedback_willing    INTEGER,               -- 1/0
    comments            TEXT,

    -- The acknowledgement, with the version of the document that was shown
    -- and when. Storing only a boolean would prove consent to a text that
    -- may since have changed; the version is what makes it evidence.
    terms_version       TEXT NOT NULL,
    terms_accepted_at   TEXT NOT NULL,

    submitted_at        TEXT NOT NULL,
    decided_at          TEXT,
    decided_by          TEXT,                  -- admin label, never a secret
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- One ACTIVE application per person, enforced by the database rather than by
-- a check-then-insert in the handler. Two submissions racing — a double
-- click, two tabs, a retry after a slow response — both pass a SELECT and
-- both INSERT; only the index stops the second. `rejected` is deliberately
-- outside the predicate so a rejected applicant can apply again; `approved`
-- and `waitlisted` are inside it so an approved person cannot quietly file a
-- second application and land back in the review queue.
CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_active
    ON applications (user_id)
    WHERE status IN ('pending', 'approved', 'waitlisted');

-- The admin list is filtered by status and read newest-first.
CREATE INDEX IF NOT EXISTS idx_applications_status
    ON applications (status, submitted_at DESC);

-- Every status change, with who and when. Append-only: nothing in this file
-- or the code updates or deletes a row here. `actor` is 'applicant' for
-- self-service transitions and the admin's label otherwise — never a token.
CREATE TABLE IF NOT EXISTS application_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id  TEXT NOT NULL REFERENCES applications(id),
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    actor           TEXT NOT NULL,
    note            TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_application_events_app
    ON application_events (application_id, created_at);

-- A decision is made once, and the database is what makes that true.
--
-- Two admins clicking approve at the same moment — or one admin double-
-- clicking — both read `pending`, both pass their own check, and both write.
-- The partial index above cannot help here: neither statement changes
-- user_id. Without this trigger the second write succeeds and the review log
-- records a decision that nobody made twice, with the entitlement re-granted
-- underneath it.
--
-- With it, the loser's UPDATE aborts, and because D1 runs a batch as one
-- transaction the whole second decision — event row, audit row, queued email
-- — rolls back with it. The handler catches the abort and tells the admin the
-- application was already decided, which is the truth.
CREATE TRIGGER IF NOT EXISTS trg_applications_decided_once
BEFORE UPDATE ON applications
WHEN OLD.status <> 'pending' AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'application has already been decided');
END;

-- ---------------------------------------------------------------------------
-- Entitlement — the thing the runtime actually checks
-- ---------------------------------------------------------------------------

-- One row per user. `expires_at` NULL means what the brief says it means for
-- this beta: valid until an administrator revokes it or the programme ends.
-- A dated row is supported for the day an individual expiry is wanted, but
-- nothing sets one today.
CREATE TABLE IF NOT EXISTS entitlements (
    user_id         TEXT PRIMARY KEY REFERENCES users(id),
    status          TEXT NOT NULL
                    CHECK (status IN ('active','suspended','revoked','expired')),
    granted_at      TEXT,
    expires_at      TEXT,                      -- NULL = no individual expiry
    changed_at      TEXT NOT NULL,
    changed_by      TEXT,
    reason          TEXT
);

-- Entitlement history, same append-only rule as application_events. This is
-- what answers "when did access stop, and who stopped it" after the fact.
CREATE TABLE IF NOT EXISTS entitlement_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    actor           TEXT NOT NULL,
    reason          TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entitlement_events_user
    ON entitlement_events (user_id, created_at);

-- Same shape of guard as trg_applications_decided_once, for the same reason:
-- revoke and re-grant are driven by guarded UPDATEs (`... WHERE status =
-- 'active'`), and a second click that matches no row must roll back its
-- history row rather than leaving an entitlement_event describing a change
-- that did not happen.
--
-- A write that does not change the status is refused outright. Every
-- legitimate transition in this model changes it — grant, suspend, revoke,
-- expire — so an update that leaves it alone is either a bug or a duplicate.
CREATE TRIGGER IF NOT EXISTS trg_entitlements_status_change
BEFORE UPDATE ON entitlements
WHEN OLD.status = NEW.status
BEGIN
    SELECT RAISE(ABORT, 'entitlement status unchanged');
END;

-- ---------------------------------------------------------------------------
-- CLI authorization (the `kryonsec login` handshake)
-- ---------------------------------------------------------------------------

-- The same shape as `device_codes` above, with one deliberate difference:
-- the secret is stored hashed. device_codes keeps its device_code in clear
-- because it was written before this table and is consumed within 15 minutes;
-- a login grant can mint a long-lived CLI session, so a leaked database row
-- must not be redeemable for one.
--
-- `status` is explicit rather than inferred from timestamps so that "denied
-- by the user" is distinguishable from "expired" — they need different
-- messages and only one of them is worth an audit entry.
CREATE TABLE IF NOT EXISTS cli_auth (
    device_code_hash TEXT PRIMARY KEY,         -- sha256 hex; the raw never lands here
    user_code        TEXT NOT NULL,            -- 'XXXX-XXXX', what the human types
    status           TEXT NOT NULL
                     CHECK (status IN ('pending','approved','denied','consumed')),
    user_id          TEXT REFERENCES users(id),
    device_id        TEXT,
    os               TEXT,
    arch             TEXT,
    version          TEXT,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    approved_at      TEXT,
    consumed_at      TEXT
);

-- The user code is what a person reads off one screen and types into another,
-- so it must resolve to exactly one row. A collision is a correctness bug,
-- not a nuisance: two pending rows with one code means approving one could
-- grant the other.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cli_auth_user_code ON cli_auth (user_code);
CREATE INDEX IF NOT EXISTS idx_cli_auth_expires ON cli_auth (expires_at);

-- ---------------------------------------------------------------------------
-- CLI sessions
-- ---------------------------------------------------------------------------

-- What `kryonsec login` leaves on the machine. Hashed for the same reason as
-- `sessions`, and revocable individually so one machine can be cut off
-- without touching the others.
--
-- `token_prefix` exists so the dashboard can show and revoke a session
-- without ever rendering the credential — an admin should not be able to
-- read a working token off the screen, and a shared window is exactly where
-- that goes wrong.
CREATE TABLE IF NOT EXISTS cli_sessions (
    id              TEXT PRIMARY KEY,          -- 's_' + 32 hex
    token_hash      TEXT NOT NULL,             -- sha256 hex of the CLI's token
    user_id         TEXT NOT NULL REFERENCES users(id),
    token_prefix    TEXT NOT NULL,             -- display only, e.g. 's_3f9a…'
    label           TEXT,                      -- OS/arch the CLI reported
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    last_used_at    TEXT,
    revoked_at      TEXT,
    revoked_reason  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cli_sessions_token ON cli_sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_cli_sessions_user ON cli_sessions (user_id);

-- ---------------------------------------------------------------------------
-- Short-lived download credentials
-- ---------------------------------------------------------------------------

-- install.sh already works by calling /api/download with a key. Rather than
-- change the installer, a signed-in CLI mints a token here and hands THAT to
-- the installer, so the credential in the shell history and the process list
-- expires in minutes and is single-use.
--
-- Single-use is enforced by `used_at` plus a guarded UPDATE ... WHERE
-- used_at IS NULL, the same race-proof shape as the device claim.
CREATE TABLE IF NOT EXISTS download_tokens (
    token_hash      TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    used_at         TEXT
);

-- ---------------------------------------------------------------------------
-- Administrators
-- ---------------------------------------------------------------------------

-- Who may act. A user_id, not an email: the email on a users row can change
-- at the provider, and an admin grant that follows an email is a grant that
-- can be inherited by whoever picks that address up next.
CREATE TABLE IF NOT EXISTS admins (
    user_id         TEXT PRIMARY KEY REFERENCES users(id),
    email           TEXT NOT NULL,             -- for display only
    granted_at      TEXT NOT NULL,
    granted_by      TEXT NOT NULL              -- 'bootstrap' or an existing admin
);

-- Every privileged action. Append-only.
--
-- `before`/`after` hold the changed fields only — a status, a note, a
-- decision. Never a token, never a session cookie, never a raw OAuth
-- response: an audit log is read by more people than the thing it audits,
-- and it is the last place a credential should be copied to.
CREATE TABLE IF NOT EXISTS admin_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor           TEXT NOT NULL,             -- admin user id or label
    action          TEXT NOT NULL,             -- 'application.approve', …
    target          TEXT,                      -- application id / user id
    before          TEXT,                      -- JSON, changed fields only
    after           TEXT,                      -- JSON, changed fields only
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit (target, created_at);

-- ---------------------------------------------------------------------------
-- Email
-- ---------------------------------------------------------------------------

-- An outbox, not a send log. The send happens after the decision is already
-- committed, so a mail provider outage can never roll back an approval — and
-- a failed send is retryable without re-deciding anything.
--
-- The body is deliberately NOT stored. Once a decision is recorded, the mail
-- is a rendering of it: keeping a copy of every message would duplicate
-- applicant text into a second table with a different retention story, for
-- no gain. `kind` plus `payload` (non-sensitive values only) is enough to
-- render the same message again.
--
-- `dedupe_key` is what makes a retry idempotent. Retrying a failed send must
-- not queue a second copy, and an admin clicking retry twice must not either;
-- UNIQUE(kind, dedupe_key) makes the second INSERT a no-op rather than a
-- duplicate. For a decision mail the key is the decision, not the timestamp.
CREATE TABLE IF NOT EXISTS email_outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,             -- 'application.received', …
    dedupe_key      TEXT NOT NULL,
    to_email        TEXT NOT NULL,
    user_id         TEXT,
    payload         TEXT,                      -- JSON, non-sensitive fields only
    status          TEXT NOT NULL
                    CHECK (status IN ('queued','sent','failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TEXT NOT NULL,
    sent_at         TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_outbox_dedupe
    ON email_outbox (kind, dedupe_key);
CREATE INDEX IF NOT EXISTS idx_email_outbox_status
    ON email_outbox (status, created_at);

-- ---------------------------------------------------------------------------
-- Programme state
-- ---------------------------------------------------------------------------

-- One row, enforced by the CHECK. Ending the beta is a single update here,
-- and the download gate and the license endpoint both read it — so ending
-- the programme does not depend on the website being redeployed, which is
-- the property the brief asks for.
--
-- The row is seeded 'active' by this migration, so the gate has an answer
-- before anyone has visited /admin.
CREATE TABLE IF NOT EXISTS beta_program (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    status          TEXT NOT NULL CHECK (status IN ('active','ended')),
    ended_at        TEXT,
    changed_at      TEXT NOT NULL,
    changed_by      TEXT
);

INSERT OR IGNORE INTO beta_program (id, status, changed_at, changed_by)
    VALUES (1, 'active', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'migration');
