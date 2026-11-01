// A real database, not a mock.
//
// `node:sqlite` is built into Node 22+, and its API is close enough to D1's
// that a ~40-line adapter is all it takes to run the actual SQL these
// Functions issue against the actual schema. That is worth the file: a
// hand-written D1 stub would pass happily while the real query was missing a
// column, and the whole point of testing the storage layer is to find that
// before a member does.
//
// Deliberately not a test file — the glob is `tests/*.test.mjs`, so this
// directory is never picked up as a suite.

import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS = [
  new URL("../../migrations/0000_existing.sql", import.meta.url),
  new URL("../../migrations/0001_beta.sql", import.meta.url),
  new URL("../../migrations/0002_cli_login.sql", import.meta.url),
];

/** Strip `undefined`, which node:sqlite rejects and D1 tolerates as null. */
const params = (values) => values.map((v) => (v === undefined ? null : v));

/**
 * The subset of the D1 binding these Functions use:
 *
 *   db.prepare(sql).bind(...p).first()  -> row | null
 *   db.prepare(sql).bind(...p).run()    -> { meta: { changes } }
 *   db.prepare(sql).bind(...p).all()    -> { results: [...] }
 *   db.batch([...])                     -> [...]
 *
 * `batch` is D1's transaction primitive and the addressee code depends on it
 * for the decision-plus-entitlement writes, so the fake runs the statements
 * inside a real SQLite transaction and rolls back if any of them throws —
 * otherwise a test would pass on a partial write that production would never
 * produce, or vice versa.
 */
export function testD1() {
  const db = new DatabaseSync(":memory:");
  for (const file of MIGRATIONS) db.exec(readFileSync(file, "utf8"));

  const wrap = (sql) => {
    // A SELECT in a batch returns rows, not a change count. Real D1 does this
    // too, so `batch` below has to know which it is holding — otherwise a
    // read-only batch would look like it succeeded while returning nothing,
    // and a test would pass on a query that never ran.
    const isRead = /^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql);
    const bound = (values) => ({
      _sql: sql,
      _values: values,
      _isRead: isRead,
      first: async () => db.prepare(sql).get(...params(values)) ?? null,
      run: async () => ({ meta: { changes: db.prepare(sql).run(...params(values)).changes } }),
      all: async () => ({ results: db.prepare(sql).all(...params(values)) }),
    });
    return {
      // The unbound statement carries the same markers, because a batch is
      // handed whatever `prepare()` returned — bound or not — and has to know
      // whether it is holding a read.
      _sql: sql,
      _values: [],
      _isRead: isRead,
      bind: (...values) => bound(params(values)),
      first: async () => db.prepare(sql).get() ?? null,
      run: async () => ({ meta: { changes: db.prepare(sql).run().changes } }),
      all: async () => ({ results: db.prepare(sql).all() }),
    };
  };

  // Batches are serialised, which is what one SQLite database does. Without
  // this, two overlapping batches would both issue BEGIN and the fake would
  // fail with "cannot start a transaction within a transaction" — a fake
  // artifact, not a finding. Real D1 queues them and the loser meets the
  // constraint, which is the behaviour the race tests are asserting.
  let tail = Promise.resolve();
  const serial = (fn) => {
    const run = tail.then(fn, fn);
    tail = run.then(
      () => {},
      () => {},
    );
    return run;
  };

  return {
    prepare: wrap,
    batch: (statements) =>
      serial(async () => {
        db.exec("BEGIN");
        try {
          const out = [];
          for (const s of statements) {
            out.push(
              s._isRead
                ? { results: db.prepare(s._sql).all(...(s._values || [])), meta: { changes: 0 } }
                : await s.run(),
            );
          }
          db.exec("COMMIT");
          return out;
        } catch (e) {
          db.exec("ROLLBACK");
          throw e;
        }
      }),
    /** Escape hatch for assertions — not part of the D1 surface. */
    _raw: db,
  };
}

/** A signed-in user, with a verified email. */
export async function makeUser(db, { id = "u_1", email = "a@example.com", admin = false } = {}) {
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
       VALUES (?, ?, 1, 'Test', ?, ?)`,
    )
    .bind(id, email, now, now)
    .run();
  if (admin) {
    await db
      .prepare("INSERT INTO admins (user_id, email, granted_at, granted_by) VALUES (?, ?, ?, 'test')")
      .bind(id, email, now)
      .run();
  }
  return id;
}

/** A request object with the headers the auth helpers read. */
export function req(url, { method = "GET", headers = {}, cookie, body } = {}) {
  const h = { ...headers };
  if (cookie) h.Cookie = cookie;
  return new Request(url, { method, headers: h, body });
}
