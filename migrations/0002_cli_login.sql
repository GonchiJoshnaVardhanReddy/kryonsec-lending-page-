-- Kryonsec landing page — D1 schema, part 2: the CLI login handshake.
--
-- Apply after 0001_beta.sql.
--
--   wrangler d1 execute KRYONSEC_DB --local  --file migrations/0002_cli_login.sql
--   wrangler d1 execute KRYONSEC_DB --remote --file migrations/0002_cli_login.sql
--
-- Additive: one new table, nothing altered, nothing dropped. Applying it to a
-- database with live members changes nothing for them.
--
-- ---------------------------------------------------------------------------
-- Why this is a second table and not a reuse of `device_codes`
-- ---------------------------------------------------------------------------
--
-- `device_codes` is the membership-key connect flow. A row there is authorised
-- by the key the CLI already holds, and claiming it writes a `members` row —
-- a key is the credential, so there is nothing to approve.
--
-- The beta has no key and the opposite shape: the CLI holds nothing, asks for
-- a code, and the code does nothing until a *signed-in person* approves it.
-- Different credential, different approval step, different columns. Sharing
-- one table would mean a nullable `key` and a nullable `approved_by` and a
-- pair of queries that have to remember which nulls mean which flow — which
-- is how a cross-flow mix-up gets shipped.
--
-- ---------------------------------------------------------------------------
-- What is deliberately not stored
-- ---------------------------------------------------------------------------
--
-- No provider token, no provider subject, no session cookie, no password. The
-- only thing this table learns about the person is the user id of whoever
-- clicked approve, and the address to print back in the terminal.
--
-- `device_code` is the secret the CLI keeps and polls with; `code` is the
-- short one a human reads off the screen. They are separate columns for the
-- same reason the connect flow separates them: somebody who glimpses the URL
-- over a shoulder, or reads a screenshot, still cannot collect the answer.

CREATE TABLE IF NOT EXISTS cli_login_codes (
    -- What the terminal displays. Human-typed, so it is short and
    -- unambiguous (Crockford base32, no O/0 or I/1).
    code            TEXT PRIMARY KEY,
    -- What the CLI polls with, and never prints. 256 random bits.
    device_code     TEXT NOT NULL UNIQUE,
    device_id       TEXT,
    os              TEXT,
    arch            TEXT,
    version         TEXT,
    created_at      TEXT NOT NULL,
    -- Set by the browser, not by the CLI. `approved_by` is a users row — the
    -- account that said yes — and it is what the minted token is issued for.
    approved_at     TEXT,
    approved_by     TEXT REFERENCES users(id),
    denied_at       TEXT,
    -- The address to print in the terminal once it is approved.
    email           TEXT
);

-- The CLI polls by its secret; the browser looks up by the short code. Both
-- are columns of a small table, but the poll runs every two seconds and the
-- index on `device_code` is what keeps that from being a scan. (`code` is
-- already the primary key.)
CREATE INDEX IF NOT EXISTS idx_cli_login_codes_device_code
    ON cli_login_codes (device_code);

-- Sweeping is by age, on every start.
CREATE INDEX IF NOT EXISTS idx_cli_login_codes_created
    ON cli_login_codes (created_at);
