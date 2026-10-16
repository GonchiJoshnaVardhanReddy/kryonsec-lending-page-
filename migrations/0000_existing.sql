-- Kryonsec landing page — D1 schema, part 0: the tables that already exist.
--
-- There was no schema file in this repository. The production database was
-- built by hand with `wrangler d1 execute`, so the only record of its shape
-- was the SQL in the Functions that read it. That is a bad place for the
-- source of truth to live: a column rename has no diff, and a fresh local
-- database could not be built at all.
--
-- This file reconstructs the existing tables exactly as the code queries
-- them, so that:
--
--   1. `wrangler d1 execute --local` can build a database to test against,
--   2. the next migration has something to ALTER,
--   3. a reader can see the baseline without reverse-engineering five
--      Functions.
--
-- Every statement is IF NOT EXISTS, and this file must be applied to
-- production BEFORE 0001. On the live database every one of these is a no-op;
-- on a fresh one it creates the baseline. That is deliberate — it means the
-- same command sequence works for both, with no manual "skip on prod" step.
--
-- Timestamps are ISO-8601 UTC TEXT throughout. That is not incidental: they
-- are compared with plain `<` in SQL (see device/start.js sweeping expired
-- codes), which only sorts correctly because the format is fixed-width and
-- lexicographic. Do not switch a column here to a numeric epoch.

-- A member is one membership key. The row exists so the dashboard can answer
-- "who is this key, and how many machines are on it" — before it was added,
-- a key was just a string in an environment variable.
CREATE TABLE IF NOT EXISTS members (
    key         TEXT PRIMARY KEY,
    email       TEXT,
    name        TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- One machine that has connected. Reconnecting the same device updates the
-- row rather than adding another, so a member who reinstalls still looks like
-- one machine. `id` is opaque hex the CLI generated — see cleanDeviceId.
CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    key         TEXT NOT NULL,
    os          TEXT,
    arch        TEXT,
    version     TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

-- One in-flight `kryonsec connect`. `code` is what the member reads off the
-- terminal; `device_code` is the secret the CLI polls with. They are separate
-- so that someone who glimpses the URL over a shoulder cannot collect the
-- answer. A row is deleted as it is collected (device/poll.js), so this table
-- only ever holds unclaimed or just-claimed codes — plus whatever the
-- per-start sweep has not reached yet.
CREATE TABLE IF NOT EXISTS device_codes (
    code        TEXT PRIMARY KEY,
    device_code TEXT NOT NULL,
    key         TEXT,
    device_id   TEXT,
    os          TEXT,
    arch        TEXT,
    version     TEXT,
    created_at  TEXT NOT NULL,
    claimed_at  TEXT,
    email       TEXT,
    name        TEXT
);

-- The poll looks a code up by its secret, not its primary key.
CREATE INDEX IF NOT EXISTS idx_device_codes_device_code
    ON device_codes (device_code);

-- The admin view lists machines per member.
CREATE INDEX IF NOT EXISTS idx_devices_key ON devices (key);
