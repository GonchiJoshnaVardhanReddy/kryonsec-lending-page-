// node --test "tests/*.test.mjs"
//
// The migrations had no test because there was no migration file — production
// was built by hand and only the Functions knew its shape.
//
// What is worth guarding here is not "the SQL parses". It is the handful of
// constraints that are cheap to declare and expensive to notice missing:
// a duplicate active application, an entitlement in a state nothing
// understands, a second row in beta_program. Each of those is silent in
// production — the insert succeeds, and the bug surfaces weeks later as two
// review rows for one person or a gate that reads the wrong programme status.
//
// node:sqlite is built into Node 22+, so this costs no dependency. The
// database is in-memory and the files are read from disk, so this tests the
// exact bytes that get applied to production.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS = ["migrations/0000_existing.sql", "migrations/0001_beta.sql"];

/** A fresh database with every migration applied, in order. */
function migrated() {
  const db = new DatabaseSync(":memory:");
  for (const file of MIGRATIONS) db.exec(readFileSync(file, "utf8"));
  return db;
}

const NOW = "2026-10-16T12:00:00.000Z";

function insertUser(db, id = "u_1") {
  db.prepare(
    `INSERT INTO users (id, email, email_verified, created_at, updated_at)
     VALUES (?, ?, 1, ?, ?)`,
  ).run(id, `${id}@example.com`, NOW, NOW);
  return id;
}

function insertApplication(db, { id, userId = "u_1", status = "pending" }) {
  db.prepare(
    `INSERT INTO applications
       (id, user_id, status, terms_version, terms_accepted_at,
        submitted_at, created_at, updated_at)
     VALUES (?, ?, ?, 'beta-2026-10', ?, ?, ?, ?)`,
  ).run(id, userId, status, NOW, NOW, NOW, NOW);
}

test("every migration applies to an empty database", () => {
  const db = migrated();
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all()
    .map((r) => r.name);
  for (const name of [
    "members", "devices", "device_codes", // the pre-existing baseline
    "users", "identities", "sessions",
    "applications", "application_events",
    "entitlements", "entitlement_events",
    "cli_auth", "cli_sessions", "download_tokens",
    "admins", "admin_audit", "email_outbox", "beta_program",
  ]) {
    assert.ok(tables.includes(name), `${name} was not created`);
  }
});

test("applying the migrations twice is a no-op", () => {
  // Both files have to be safe to re-run: an operator who is unsure whether
  // the migration took will run it again, and on production the first file is
  // ALWAYS a re-run because those tables already exist.
  const db = migrated();
  for (const file of MIGRATIONS) db.exec(readFileSync(file, "utf8"));

  const programmes = db.prepare("SELECT COUNT(*) AS n FROM beta_program").get();
  assert.equal(programmes.n, 1, "the seeded programme row was duplicated");
});

test("the beta programme starts active, with exactly one row", () => {
  const db = migrated();
  const row = db.prepare("SELECT id, status FROM beta_program").get();
  assert.equal(row.id, 1);
  assert.equal(row.status, "active");

  // The CHECK (id = 1) is what makes "the programme status" a single value
  // rather than a table someone later has to pick a row out of.
  assert.throws(
    () => db.prepare("INSERT INTO beta_program (id, status, changed_at) VALUES (2, 'active', ?)").run(NOW),
    /CHECK|UNIQUE|constraint/i,
  );
});

test("a status outside the model is refused by the database", () => {
  // These four states are read by the gate. A typo or a future rename that
  // reaches the database unchecked turns into an entitlement the runtime
  // cannot interpret, which is worse than a rejected write.
  const db = migrated();
  insertUser(db);
  assert.throws(
    () => db.prepare(
      `INSERT INTO entitlements (user_id, status, changed_at) VALUES ('u_1', 'aproved', ?)`,
    ).run(NOW),
    /CHECK|constraint/i,
  );

  assert.throws(
    () => insertApplication(db, { id: "a_1", status: "accepted" }),
    /CHECK|constraint/i,
  );
});

test("one active application per person, enforced by the index", () => {
  const db = migrated();
  insertUser(db);
  insertApplication(db, { id: "a_1", status: "pending" });

  // The double-click case: both requests pass their own SELECT, so only the
  // unique index stops the second row landing.
  for (const status of ["pending", "approved", "waitlisted"]) {
    assert.throws(
      () => insertApplication(db, { id: `a_${status}`, status }),
      /UNIQUE|constraint/i,
      `a second ${status} application was allowed`,
    );
  }
});

test("a rejected applicant may apply again", () => {
  // 'rejected' is deliberately outside the index predicate. Without this,
  // a person rejected once could never reapply, which is not the policy.
  const db = migrated();
  insertUser(db);
  insertApplication(db, { id: "a_1", status: "rejected" });
  insertApplication(db, { id: "a_2", status: "pending" });

  const n = db.prepare("SELECT COUNT(*) AS n FROM applications WHERE user_id = 'u_1'").get();
  assert.equal(n.n, 2);
});

test("two people may each hold an active application", () => {
  // The index is per user. A predicate written on status alone would let
  // exactly one application exist site-wide, which would be a strange beta.
  const db = migrated();
  insertUser(db, "u_1");
  insertUser(db, "u_2");
  insertApplication(db, { id: "a_1", userId: "u_1" });
  insertApplication(db, { id: "a_2", userId: "u_2" });
});

test("the same (provider, subject) cannot resolve to two users", () => {
  const db = migrated();
  insertUser(db, "u_1");
  insertUser(db, "u_2");
  const link = (userId) =>
    db.prepare(
      `INSERT INTO identities (provider, subject, user_id, created_at)
       VALUES ('github', '12345', ?, ?)`,
    ).run(userId, NOW);

  link("u_1");
  assert.throws(() => link("u_2"), /UNIQUE|constraint/i);
});

test("matching emails on two providers stay two accounts", () => {
  // The account-takeover path the brief names: someone signs up at GitHub
  // with an address that already exists at Google. If email were the key, or
  // if anything merged on it, that person would inherit the other account.
  const db = migrated();
  db.prepare(
    `INSERT INTO users (id, email, email_verified, created_at, updated_at)
     VALUES ('u_1', 'same@example.com', 1, ?, ?), ('u_2', 'same@example.com', 1, ?, ?)`,
  ).run(NOW, NOW, NOW, NOW);

  db.prepare(
    `INSERT INTO identities (provider, subject, user_id, email, created_at)
     VALUES ('google', 'g-1', 'u_1', 'same@example.com', ?),
            ('github', 'gh-1', 'u_2', 'same@example.com', ?)`,
  ).run(NOW, NOW);

  const n = db.prepare("SELECT COUNT(*) AS n FROM users").get();
  assert.equal(n.n, 2, "identities sharing an email were merged");
});

test("an email address is never the identity key", () => {
  // A regression guard on the schema itself rather than on behaviour: if a
  // future migration adds UNIQUE(email) to users or identities, this fails
  // and the reviewer sees why before it ships.
  const db = migrated();
  const indexes = db
    .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL")
    .all();
  for (const idx of indexes) {
    const onUsers = /ON\s+(users|identities)\s*\(\s*email/i.test(idx.sql);
    assert.ok(!onUsers, `${idx.name} makes email a key: ${idx.sql}`);
  }
});

test("a retried notification does not queue a second copy", () => {
  // Retrying a failed send is an admin action, and admins click twice. The
  // dedupe key is the decision, so the second attempt is a no-op rather than
  // a second email to the same person.
  const db = migrated();
  const queue = () =>
    db.prepare(
      `INSERT INTO email_outbox (kind, dedupe_key, to_email, status, created_at)
       VALUES ('application.approved', 'a_1:approved', 'a@example.com', 'queued', ?)`,
    ).run(NOW);

  queue();
  assert.throws(queue, /UNIQUE|constraint/i);
});

test("CLI user codes are unique, and the secret is not stored in clear", () => {
  const db = migrated();
  const grant = (hash, code) =>
    db.prepare(
      `INSERT INTO cli_auth (device_code_hash, user_code, status, created_at, expires_at)
       VALUES (?, ?, 'pending', ?, ?)`,
    ).run(hash, code, NOW, NOW);

  grant("a".repeat(64), "AB12-CD34");
  assert.throws(() => grant("b".repeat(64), "AB12-CD34"), /UNIQUE|constraint/i);

  // The column is named _hash so that a reader of the schema cannot mistake
  // it for the value the CLI actually sends.
  const cols = db.prepare("PRAGMA table_info(cli_auth)").all().map((c) => c.name);
  assert.ok(cols.includes("device_code_hash"));
  assert.ok(!cols.includes("device_code"));
});

test("the pre-existing tables are created exactly as the Functions query them", () => {
  // device/start.js INSERTs eight columns by name and device/claim.js UPDATEs
  // three more. If this reconstruction drifts from production, the migration
  // still applies — it is IF NOT EXISTS — and the drift only shows up as a
  // runtime error on the live database. So the column lists are asserted.
  const db = migrated();
  const cols = (t) => db.prepare(`PRAGMA table_info(${t})`).all().map((c) => c.name);

  assert.deepEqual(cols("device_codes"), [
    "code", "device_code", "key", "device_id", "os", "arch",
    "version", "created_at", "claimed_at", "email", "name",
  ]);
  assert.deepEqual(cols("members"), ["key", "email", "name", "created_at", "updated_at"]);
  assert.deepEqual(cols("devices"), [
    "id", "key", "os", "arch", "version", "first_seen", "last_seen",
  ]);
});
