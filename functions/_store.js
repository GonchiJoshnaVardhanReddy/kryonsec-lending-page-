/**
 * Reading and writing the beta's own tables.
 *
 * Import-only: never served.
 *
 * Everything that decides *access* lives here, and nothing else decides it.
 * The website dashboard, the download endpoint, the license endpoint and the
 * CLI all ask the same `accessFor()` question and get the same answer from the
 * same rows — which is the property that makes revocation actually mean
 * something. A second implementation of "is this person allowed in" is how a
 * revoked account keeps working on the one screen nobody re-checked.
 *
 * ---------------------------------------------------------------------------
 * Two shapes worth knowing before you read the SQL
 * ---------------------------------------------------------------------------
 *
 * **Guarded writes.** A decision is an `UPDATE ... WHERE status = 'pending'`,
 * not a read-then-write. The row count is the answer: 1 means this caller made
 * the change, 0 means someone else already did. Two admins clicking approve at
 * the same moment both pass their own SELECT, so a SELECT is not a lock —
 * `migrations/0001_beta.sql` carries the triggers that make the database
 * referee it.
 *
 * **One transaction per decision.** The application row, its history row, the
 * audit row, the entitlement and the queued notification all go into a single
 * `db.batch()`. A partial decision is worse than no decision: an approved
 * applicant with no entitlement is a person who was told yes and then found
 * the download refused.
 */

import { newId } from "./_auth.js";
import { KINDS, outboxStatement } from "./_email.js";
import { nowIso } from "./_shared.js";

/** The version of the acknowledgement shown on the form. Bumping it means a
 *  new row records the new text; old rows keep the version they agreed to. */
export const TERMS_VERSION = "beta-2026-10";

/** Caps applied before anything is written. Free text is the only place an
 *  applicant can put a lot of bytes, so it is the only place that needs one. */
export const LIMITS = {
  full_name: 120,
  contact_email: 254,
  github_username: 60,
  portfolio_url: 300,
  role: 80,
  primary_os: 80,
  intended_use: 2000,
  experience: 2000,
  comments: 2000,
  reason: 500,
};

const DECISIONS = { approve: "approved", reject: "rejected", waitlist: "waitlisted" };

/** Statuses that mean "this application is still in play" — the index
 *  predicate in 0001_beta.sql is this exact list, and the two must agree. */
const ACTIVE_STATUSES = "('pending','approved','waitlisted')";

// --- reads ------------------------------------------------------------------

export async function getUser(db, userId) {
  if (!userId) return null;
  return db
    .prepare("SELECT id, email, email_verified, name, created_at FROM users WHERE id = ?")
    .bind(userId)
    .first();
}

export async function getEntitlement(db, userId) {
  if (!userId) return null;
  return db.prepare("SELECT * FROM entitlements WHERE user_id = ?").bind(userId).first();
}

/** The providers this account signs in with. Shown, never merged — an identity
 *  is linked by a signed-in action, not by two providers agreeing on an email. */
export async function listIdentities(db, userId) {
  if (!userId) return [];
  const { results } = await db
    .prepare(
      `SELECT provider, email, email_verified, created_at, last_login_at
         FROM identities WHERE user_id = ? ORDER BY created_at`,
    )
    .bind(userId)
    .all();
  return results || [];
}

export async function activeApplication(db, userId) {
  if (!userId) return null;
  // At most one row can match: idx_applications_active is a unique index over
  // exactly these three statuses, so LIMIT 1 is exact rather than a guess.
  return db
    .prepare(
      `SELECT * FROM applications
        WHERE user_id = ? AND status IN ${ACTIVE_STATUSES}
        ORDER BY submitted_at DESC LIMIT 1`,
    )
    .bind(userId)
    .first();
}

/**
 * Everything a page or a gate needs about one account, in one call.
 *
 * The decision table, and the only one:
 *
 *   programme ended   -> refused, whatever the entitlement says
 *   no entitlement    -> refused
 *   status != active  -> refused (suspended, revoked, expired)
 *   expires_at passed -> refused
 *   otherwise         -> allowed
 *
 * The programme check runs FIRST on purpose. Ending the beta has to stop
 * access for everybody, including people whose entitlement row still says
 * active — otherwise "end the programme" would be a flag that changes a
 * banner and nothing else.
 */
export async function accessFor(db, userId) {
  if (!userId) {
    return { entitled: false, status: "anonymous", reason: "Not signed in.", user: null };
  }

  const [u, a, e, p, r] = await db.batch([
    db.prepare("SELECT id, email, email_verified, name, created_at FROM users WHERE id = ?").bind(userId),
    db.prepare(
      `SELECT * FROM applications
        WHERE user_id = ? AND status IN ${ACTIVE_STATUSES}
        ORDER BY submitted_at DESC LIMIT 1`,
    ).bind(userId),
    db.prepare("SELECT * FROM entitlements WHERE user_id = ?").bind(userId),
    db.prepare("SELECT status, ended_at FROM beta_program WHERE id = 1"),
    // The most recent refusal, so a rejected applicant is told they may apply
    // again rather than left staring at an empty form wondering.
    db.prepare(
      `SELECT id, status, decided_at FROM applications
        WHERE user_id = ? AND status = 'rejected'
        ORDER BY submitted_at DESC LIMIT 1`,
    ).bind(userId),
  ]);

  const user = u.results?.[0] || null;
  const application = a.results?.[0] || null;
  const entitlement = e.results?.[0] || null;
  const programme = p.results?.[0] || null;
  const lastRejected = r.results?.[0] || null;

  const base = { user, application, entitlement, lastRejected };

  if (!user) return { ...base, entitled: false, status: "unknown", reason: "That account no longer exists." };

  if (!programme || programme.status !== "active") {
    return { ...base, entitled: false, status: "programme_ended", reason: "The beta programme has ended." };
  }

  if (!entitlement) {
    return { ...base, entitled: false, status: "none", reason: "No access has been granted to this account yet." };
  }

  if (entitlement.status !== "active") {
    return {
      ...base,
      entitled: false,
      status: entitlement.status,
      reason:
        entitlement.status === "revoked"
          ? "Access to this account has been revoked."
          : `Access to this account is ${entitlement.status}.`,
    };
  }

  // ISO-8601 UTC compares correctly as a string, which is why every timestamp
  // in this schema is stored that way and none of them are epoch numbers.
  if (entitlement.expires_at && entitlement.expires_at <= nowIso()) {
    return { ...base, entitled: false, status: "expired", reason: "Access to this account has expired." };
  }

  return { ...base, entitled: true, status: "active", reason: "", expiresAt: entitlement.expires_at || null };
}

/** A search box value: one line, capped, and still just a value. */
export function cleanSearch(value, max = 80) {
  return String(value ?? "").replace(/\s+/g, " ").trim().slice(0, max);
}

/** Escape LIKE's own wildcards so "50%" searches for those characters rather
 *  than for everything. The SQL below declares ESCAPE '\'. */
const like = (q) => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

const clampInt = (value, fallback, min, max) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
};

const applicationSearch = (q) => ({
  clause:
    "(u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR a.full_name LIKE ? ESCAPE '\\' OR a.contact_email LIKE ? ESCAPE '\\' OR a.github_username LIKE ? ESCAPE '\\')",
  params: Array(5).fill(like(q)),
});

/** The admin queue. Newest first, because that is the order they are worked. */
export async function listApplications(db, { status = "pending", limit = 100, offset = 0, q = "" } = {}) {
  const capped = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const skip = clampInt(offset, 0, 0, 100_000);
  const needle = cleanSearch(q);
  const where = [];
  const params = [];
  if (status !== "all") {
    where.push("a.status = ?");
    params.push(status);
  }
  if (needle) {
    const search = applicationSearch(needle);
    where.push(search.clause);
    params.push(...search.params);
  }
  const { results } = await db
    .prepare(
      `SELECT a.*, u.email AS account_email, u.name AS account_name
         FROM applications a JOIN users u ON u.id = a.user_id
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY a.submitted_at DESC LIMIT ? OFFSET ?`,
    )
    .bind(...params, capped, skip)
    .all();
  return results || [];
}

/** The count behind the same filters, for an honest page count. */
export async function countApplications(db, { status = "pending", q = "" } = {}) {
  const needle = cleanSearch(q);
  const where = [];
  const params = [];
  if (status !== "all") {
    where.push("a.status = ?");
    params.push(status);
  }
  if (needle) {
    const search = applicationSearch(needle);
    where.push(search.clause);
    params.push(...search.params);
  }
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM applications a JOIN users u ON u.id = a.user_id
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`,
    )
    .bind(...params)
    .first();
  return Number(row?.n || 0);
}

/** Accounts holding an entitlement, with the application that got them in. */
export async function listAccess(db, { limit = 200 } = {}) {
  const capped = Math.min(Math.max(Number(limit) || 200, 1), 500);
  const { results } = await db
    .prepare(
      `SELECT u.id AS user_id, u.email, u.name,
              e.status, e.granted_at, e.expires_at, e.changed_at, e.changed_by, e.reason,
              (SELECT COUNT(*) FROM cli_sessions c
                WHERE c.user_id = u.id AND c.revoked_at IS NULL AND c.expires_at > ?) AS live_cli_sessions
         FROM entitlements e JOIN users u ON u.id = e.user_id
        ORDER BY e.changed_at DESC LIMIT ?`,
    )
    .bind(nowIso(), capped)
    .all();
  return results || [];
}

/** Counts for the admin header. One query rather than four. */
export async function queueCounts(db) {
  const { results } = await db
    .prepare("SELECT status, COUNT(*) AS n FROM applications GROUP BY status")
    .all();
  const counts = { pending: 0, approved: 0, rejected: 0, waitlisted: 0 };
  for (const row of results || []) counts[row.status] = row.n;
  return counts;
}

export async function programmeStatus(db) {
  const row = await db.prepare("SELECT status, ended_at, changed_at FROM beta_program WHERE id = 1").first();
  return row || { status: "active" };
}

/** Outbox rows for the admin view. Bodies are not stored, so there is none. */
export async function listOutbox(db, { limit = 50 } = {}) {
  const { results } = await db
    .prepare(
      `SELECT id, kind, to_email, user_id, status, attempts, last_error, created_at, sent_at
         FROM email_outbox ORDER BY created_at DESC LIMIT ?`,
    )
    .bind(Math.min(Math.max(Number(limit) || 50, 1), 200))
    .all();
  return results || [];
}

const RECENT_LIMIT = 50;

/** Action families the audit view can filter by. A whitelist, not a prefix
 *  taken from the query string — the value reaches SQL. */
export const AUDIT_PREFIXES = ["application", "entitlement", "programme", "session", "cli_session", "admin"];

const auditWhere = (prefix) => {
  const p = String(prefix || "").toLowerCase();
  return AUDIT_PREFIXES.includes(p) ? { clause: "WHERE action LIKE ? ESCAPE '\\'", params: [`${p}.%`] } : { clause: "", params: [] };
};

export async function listAudit(db, { limit = RECENT_LIMIT, offset = 0, prefix = "" } = {}) {
  const where = auditWhere(prefix);
  const { results } = await db
    .prepare(
      `SELECT id, actor, action, target, before, after, created_at
         FROM admin_audit ${where.clause} ORDER BY id DESC LIMIT ? OFFSET ?`,
    )
    .bind(...where.params, Math.min(Math.max(Number(limit) || RECENT_LIMIT, 1), 200), clampInt(offset, 0, 0, 100_000))
    .all();
  return results || [];
}

export async function countAudit(db, { prefix = "" } = {}) {
  const where = auditWhere(prefix);
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM admin_audit ${where.clause}`)
    .bind(...where.params)
    .first();
  return Number(row?.n || 0);
}

// --- dashboard: people, sessions, machines, health --------------------------

/**
 * Accounts, with the two facts an admin most often needs beside them: whether
 * access is active and how many live credentials exist. Search is parameterised
 * and wildcard-escaped, so a typed `%` is a character, not a match-all.
 */
export async function listUsers(db, { limit = 50, offset = 0, q = "" } = {}) {
  const capped = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const skip = clampInt(offset, 0, 0, 100_000);
  const needle = cleanSearch(q);
  const after = needle
    ? { clause: "WHERE (u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR u.id LIKE ? ESCAPE '\\')", params: [like(needle), like(needle), like(needle)] }
    : { clause: "", params: [] };
  const now = nowIso();
  const { results } = await db
    .prepare(
      `SELECT u.id, u.email, u.email_verified, u.name, u.created_at,
              (SELECT e.status FROM entitlements e WHERE e.user_id = u.id) AS entitlement_status,
              (SELECT COUNT(*) FROM sessions s
                WHERE s.user_id = u.id AND s.expires_at > ?) AS live_sessions,
              (SELECT COUNT(*) FROM cli_sessions c
                WHERE c.user_id = u.id AND c.revoked_at IS NULL AND c.expires_at > ?) AS live_cli
         FROM users u ${after.clause}
        ORDER BY u.created_at DESC LIMIT ? OFFSET ?`,
    )
    .bind(now, now, ...after.params, capped, skip)
    .all();
  return results || [];
}

export async function countUsers(db, { q = "" } = {}) {
  const needle = cleanSearch(q);
  const row = needle
    ? await db
        .prepare(
          `SELECT COUNT(*) AS n FROM users u
            WHERE (u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR u.id LIKE ? ESCAPE '\\')`,
        )
        .bind(like(needle), like(needle), like(needle))
        .first()
    : await db.prepare("SELECT COUNT(*) AS n FROM users").first();
  return Number(row?.n || 0);
}

export const USER_ID_RE = /^u_[0-9a-f]{32}$/;

/** One account, everything an admin may see about it. No credentials: session
 *  rows are read as hashes and rendered as a short prefix. */
export async function userAdminDetail(db, userId) {
  if (!USER_ID_RE.test(String(userId || ""))) return null;
  const [user, entitlement, identities, application, sessions, cli, entitlementEvents] = await Promise.all([
    getUser(db, userId),
    getEntitlement(db, userId),
    listIdentities(db, userId),
    activeApplication(db, userId),
    db
      .prepare(
        `SELECT token_hash, created_at, expires_at, last_seen_at
           FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
      )
      .bind(userId)
      .all(),
    db
      .prepare(
        `SELECT id, token_prefix, label, created_at, expires_at, last_used_at, revoked_at, revoked_reason
           FROM cli_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
      )
      .bind(userId)
      .all(),
    db
      .prepare(
        `SELECT from_status, to_status, actor, reason, created_at FROM entitlement_events
          WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`,
      )
      .bind(userId)
      .all(),
  ]);

  // Read after the group above, because it needs the application the group
  // just found. Binding `application.id` inside the same `Promise.all` would
  // read the binding while the destructuring that defines it was still in
  // flight.
  const appEvents = application
    ? await db
        .prepare(
          `SELECT from_status, to_status, actor, note, created_at FROM application_events
            WHERE application_id = ? ORDER BY created_at DESC LIMIT 20`,
        )
        .bind(application.id)
        .all()
    : { results: [] };

  if (!user) return null;
  return {
    user,
    entitlement,
    identities: identities || [],
    application,
    sessions: sessions.results || [],
    cli: cli.results || [],
    appEvents: appEvents.results || [],
    entitlementEvents: entitlementEvents.results || [],
  };
}

/** Every signed-in command-line machine, across accounts. */
export async function listAllCliSessions(db, { limit = 100, offset = 0, q = "" } = {}) {
  const capped = Math.min(Math.max(Number(limit) || 100, 1), 200);
  const skip = clampInt(offset, 0, 0, 100_000);
  const needle = cleanSearch(q);
  const after = needle
    ? {
        clause:
          "WHERE (u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR c.label LIKE ? ESCAPE '\\' OR c.token_prefix LIKE ? ESCAPE '\\')",
        params: Array(4).fill(like(needle)),
      }
    : { clause: "", params: [] };
  const { results } = await db
    .prepare(
      `SELECT c.id, c.token_prefix, c.label, c.created_at, c.expires_at, c.last_used_at,
              c.revoked_at, c.revoked_reason, u.id AS user_id, u.email
         FROM cli_sessions c JOIN users u ON u.id = c.user_id
        ${after.clause}
        ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
    )
    .bind(...after.params, capped, skip)
    .all();
  return results || [];
}

export async function countAllCliSessions(db, { q = "" } = {}) {
  const needle = cleanSearch(q);
  const row = needle
    ? await db
        .prepare(
          `SELECT COUNT(*) AS n FROM cli_sessions c JOIN users u ON u.id = c.user_id
            WHERE (u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR c.label LIKE ? ESCAPE '\\' OR c.token_prefix LIKE ? ESCAPE '\\')`,
        )
        .bind(...Array(4).fill(like(needle)))
        .first()
    : await db.prepare("SELECT COUNT(*) AS n FROM cli_sessions").first();
  return Number(row?.n || 0);
}

/** The legacy membership machines. Read-only: the key model has no per-machine
 *  revocation, and inventing one here would be a second answer to access. */
export async function listDevices(db, { limit = 100, q = "" } = {}) {
  const capped = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const needle = cleanSearch(q);
  const after = needle
    ? {
        clause: "WHERE (d.key LIKE ? ESCAPE '\\' OR d.os LIKE ? ESCAPE '\\' OR m.email LIKE ? ESCAPE '\\')",
        params: Array(3).fill(like(needle)),
      }
    : { clause: "", params: [] };
  const { results } = await db
    .prepare(
      `SELECT d.id, d.key, d.os, d.arch, d.version, d.last_seen, m.email
         FROM devices d LEFT JOIN members m ON m.key = d.key
        ${after.clause}
        ORDER BY d.last_seen DESC LIMIT ?`,
    )
    .bind(...after.params, capped)
    .all();
  return results || [];
}

/** Header numbers, one query rather than a dozen round trips. */
export async function overviewCounts(db) {
  const now = nowIso();
  const dayAgo = new Date(Date.now() - 86_400_000).toISOString();
  const row = await db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM users) AS users,
         (SELECT COUNT(*) FROM users WHERE email_verified = 0) AS unverified,
         (SELECT COUNT(*) FROM sessions WHERE expires_at > ?) AS live_sessions,
         (SELECT COUNT(*) FROM sessions WHERE expires_at <= ?) AS expired_sessions,
         (SELECT COUNT(*) FROM cli_sessions WHERE revoked_at IS NULL AND expires_at > ?) AS live_cli,
         (SELECT COUNT(*) FROM admins) AS admins,
         (SELECT COUNT(*) FROM entitlements WHERE status = 'active') AS active_access,
         (SELECT COUNT(*) FROM entitlements) AS entitlement_rows,
         (SELECT COUNT(*) FROM applications WHERE status = 'pending') AS pending,
         (SELECT COUNT(*) FROM applications) AS applications,
         (SELECT COUNT(*) FROM devices) AS devices,
         (SELECT COUNT(*) FROM members) AS members,
         (SELECT COUNT(*) FROM email_outbox WHERE status = 'queued') AS queued_mail,
         (SELECT COUNT(*) FROM email_outbox WHERE status = 'failed') AS failed_mail,
         (SELECT COUNT(*) FROM admin_audit WHERE created_at > ?) AS audit_day,
         (SELECT COUNT(*) FROM admin_audit
           WHERE created_at > ?
             AND action IN ('admin.denied','admin.csrf_refused','admin.invalid','admin.throttled')) AS refused_day`,
    )
    .bind(now, now, now, dayAgo, dayAgo)
    .first();
  return row || {};
}

/** Which tables the schema actually has. A missing one is a deployment fault,
 *  not a rendering problem, so the security page says so plainly. */
const REQUIRED_TABLES = [
  "users", "identities", "sessions", "applications", "application_events",
  "entitlements", "entitlement_events", "cli_auth", "cli_sessions",
  "download_tokens", "admins", "admin_audit", "email_outbox", "beta_program",
  "cli_login_codes", "members", "devices", "device_codes",
];

export async function schemaSnapshot(db) {
  const { results } = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
  const names = new Set((results || []).map((r) => r.name));
  const missing = REQUIRED_TABLES.filter((name) => !names.has(name));
  return { required: REQUIRED_TABLES.length, missing };
}

/** Delete one website session, scoped to its owner. The audit row is written
 *  whether or not a row moved, so a failed attempt is visible too. */
export async function revokeWebsiteSession(db, { tokenHash, userId, actor }) {
  if (!/^[0-9a-f]{64}$/.test(String(tokenHash || "")) || !USER_ID_RE.test(String(userId || ""))) {
    return { ok: false, error: "That session no longer exists." };
  }
  const claim = await db
    .prepare("DELETE FROM sessions WHERE token_hash = ? AND user_id = ?")
    .bind(tokenHash, userId)
    .run();
  const revoked = Boolean(claim.meta && claim.meta.changes === 1);
  await db
    .prepare(
      `INSERT INTO admin_audit (actor, action, target, before, after, created_at)
       VALUES (?, ?, ?, NULL, ?, ?)`,
    )
    .bind(actor, revoked ? "session.revoked" : "session.revoke_missed", userId, JSON.stringify({ revoked }), nowIso())
    .run();
  return revoked ? { ok: true, userId } : { ok: false, error: "That session no longer exists." };
}

// --- writes -----------------------------------------------------------------

/** Trim to one line and cap. Everything from the form goes through this. */
export function cleanField(value, key) {
  return String(value ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, LIMITS[key] ?? 200);
}

/**
 * File an application.
 *
 * The pre-check exists to produce a decent message, not to protect anything:
 * two submissions racing both pass it. `idx_applications_active` is what
 * actually holds the line, and the catch below reads the constraint violation
 * as the answer it is.
 */
export async function submitApplication(db, userId, fields) {
  const user = await getUser(db, userId);
  if (!user) return { ok: false, code: "no_user", error: "That account no longer exists." };

  const existing = await activeApplication(db, userId);
  if (existing) return { ok: false, code: "exists", application: existing };

  const id = newId("a");
  const now = nowIso();
  const value = (key) => cleanField(fields?.[key], key) || null;

  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO applications
             (id, user_id, status, full_name, contact_email, github_username, portfolio_url,
              role, primary_os, intended_use, experience, feedback_willing, comments,
              terms_version, terms_accepted_at, submitted_at, created_at, updated_at)
           VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          id, userId,
          value("full_name"),
          cleanField(fields?.contact_email, "contact_email").toLowerCase() || null,
          value("github_username"),
          value("portfolio_url"),
          value("role"),
          value("primary_os"),
          value("intended_use"),
          value("experience"),
          fields?.feedback_willing ? 1 : 0,
          value("comments"),
          TERMS_VERSION, now, now, now, now,
        ),
      db
        .prepare(
          `INSERT INTO application_events (application_id, from_status, to_status, actor, note, created_at)
           VALUES (?, NULL, 'pending', 'applicant', NULL, ?)`,
        )
        .bind(id, now),
      outboxStatement(db, {
        kind: KINDS.RECEIVED,
        dedupeKey: `${id}:received`,
        toEmail: user.email,
        userId,
        payload: { name: user.name || "" },
      }),
    ]);
  } catch (error) {
    if (/UNIQUE|constraint/i.test(String(error?.message))) {
      return { ok: false, code: "exists", application: await activeApplication(db, userId) };
    }
    throw error;
  }

  return { ok: true, id };
}

/**
 * Approve, reject, or waitlist. One transaction.
 *
 * Approving also writes the entitlement, because "approved" and "allowed to
 * download" must not be able to disagree. Rejecting and waitlisting do not
 * touch the entitlement at all — a rejected applicant has none to remove, and
 * a waitlisted one is not being admitted.
 */
export async function decideApplication(db, { applicationId, decision, actor, reason = null }) {
  const to = DECISIONS[decision];
  if (!to) return { ok: false, error: "Unknown decision." };

  const application = await db
    .prepare("SELECT * FROM applications WHERE id = ?")
    .bind(applicationId)
    .first();
  if (!application) return { ok: false, error: "That application no longer exists." };
  if (application.status !== "pending") {
    return { ok: false, error: `That application was already ${application.status}.` };
  }

  const user = await getUser(db, application.user_id);
  const previous = await getEntitlement(db, application.user_id);
  const now = nowIso();
  const note = cleanField(reason, "reason") || null;

  const statements = [
    db
      .prepare(
        `UPDATE applications
            SET status = ?, decided_at = ?, decided_by = ?, updated_at = ?
          WHERE id = ? AND status = 'pending'`,
      )
      .bind(to, now, actor, now, applicationId),
    db
      .prepare(
        `INSERT INTO application_events (application_id, from_status, to_status, actor, note, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(applicationId, application.status, to, actor, note, now),
  ];

  if (to === "approved") {
    statements.push(...grantStatements(db, { userId: application.user_id, actor, reason: note, previous, now }));
  }

  statements.push(
    db
      .prepare(
        `INSERT INTO admin_audit (actor, action, target, before, after, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        actor,
        `application.${decision}`,
        applicationId,
        JSON.stringify({ status: application.status }),
        JSON.stringify({ status: to }),
        now,
      ),
    outboxStatement(db, {
      kind: decisionKind(decision),
      dedupeKey: `${applicationId}:${to}`,
      toEmail: user?.email || "",
      userId: application.user_id,
      payload: { name: user?.name || "", reason: note || "" },
    }),
  );

  try {
    await db.batch(statements);
  } catch (error) {
    // trg_applications_decided_once. The other admin won; say so plainly.
    if (/already been decided/i.test(String(error?.message))) {
      return { ok: false, error: "That application was decided a moment ago by someone else." };
    }
    throw error;
  }

  return { ok: true, status: to, userId: application.user_id, email: user?.email || "" };
}

/**
 * Restore access to a revoked or suspended account.
 *
 * Separate from `decideApplication` because the person's application is
 * already approved and cannot be approved again — the decided-once trigger
 * sees to that. This is the repair path, and it is also the honest answer to
 * "we revoked by mistake".
 */
export async function grantEntitlement(db, { userId, actor, reason = null }) {
  const user = await getUser(db, userId);
  if (!user) return { ok: false, error: "That account no longer exists." };

  const previous = await getEntitlement(db, userId);
  if (previous?.status === "active") return { ok: false, error: "That account already has access." };

  const now = nowIso();
  const note = cleanField(reason, "reason") || null;

  await db.batch([
    ...grantStatements(db, { userId, actor, reason: note, previous, now }),
    db
      .prepare(
        `INSERT INTO admin_audit (actor, action, target, before, after, created_at)
         VALUES (?, 'entitlement.granted', ?, ?, ?, ?)`,
      )
      .bind(actor, userId, JSON.stringify({ status: previous?.status ?? null }), JSON.stringify({ status: "active" }), now),
    outboxStatement(db, {
      kind: KINDS.ACCESS_GRANTED,
      dedupeKey: `${userId}:granted:${now}`,
      toEmail: user.email,
      userId,
      payload: { name: user.name || "" },
    }),
  ]);

  return { ok: true, userId };
}

/**
 * Take access away.
 *
 * `suspended` is the same write with a different word: the brief keeps both
 * because "paused, probably temporary" and "removed" need different messages
 * and different follow-ups, even though the gate treats them identically.
 */
export async function revokeEntitlement(db, { userId, actor, reason = null, status = "revoked" }) {
  if (status !== "revoked" && status !== "suspended") {
    return { ok: false, error: "Unknown entitlement status." };
  }

  const user = await getUser(db, userId);
  if (!user) return { ok: false, error: "That account no longer exists." };

  const current = await getEntitlement(db, userId);
  if (!current) return { ok: false, error: "That account has no access to remove." };
  if (current.status !== "active") return { ok: false, error: `Access is already ${current.status}.` };

  const now = nowIso();
  const note = cleanField(reason, "reason") || null;

  try {
    await db.batch([
      db
        .prepare(
          `UPDATE entitlements
              SET status = ?, changed_at = ?, changed_by = ?, reason = ?
            WHERE user_id = ? AND status = 'active'`,
        )
        .bind(status, now, actor, note, userId),
      db
        .prepare(
          `INSERT INTO entitlement_events (user_id, from_status, to_status, actor, reason, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(userId, current.status, status, actor, note, now),
      db
        .prepare(
          `INSERT INTO admin_audit (actor, action, target, before, after, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(actor, `entitlement.${status}`, userId, JSON.stringify({ status: current.status }), JSON.stringify({ status }), now),
      outboxStatement(db, {
        kind: KINDS.REVOKED,
        dedupeKey: `${userId}:${status}:${now}`,
        toEmail: user.email,
        userId,
        payload: { name: user.name || "", reason: note || "" },
      }),
    ]);
  } catch (error) {
    // Either the guarded UPDATE matched nothing (someone revoked first) or
    // trg_entitlements_status_change refused a write that changed nothing.
    // Both mean the same thing to the admin: it is already done.
    if (/unchanged|constraint/i.test(String(error?.message))) {
      return { ok: false, error: "That access was already changed a moment ago." };
    }
    throw error;
  }

  return { ok: true, userId, status };
}

/**
 * The entitlement write, shared by approval and re-grant.
 *
 * `WHERE entitlements.status <> 'active'` on the conflict branch matters: if
 * the row is already active the update does not happen, and
 * trg_entitlements_status_change never fires. Without that clause the trigger
 * would abort a legitimate second grant and take the whole transaction with
 * it.
 */
function grantStatements(db, { userId, actor, reason, previous, now }) {
  return [
    db
      .prepare(
        `INSERT INTO entitlements (user_id, status, granted_at, expires_at, changed_at, changed_by, reason)
         VALUES (?, 'active', ?, NULL, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
             status = 'active',
             granted_at = excluded.granted_at,
             expires_at = NULL,
             changed_at = excluded.changed_at,
             changed_by = excluded.changed_by,
             reason = excluded.reason
           WHERE entitlements.status <> 'active'`,
      )
      .bind(userId, now, now, actor, reason),
    db
      .prepare(
        `INSERT INTO entitlement_events (user_id, from_status, to_status, actor, reason, created_at)
         VALUES (?, ?, 'active', ?, ?, ?)`,
      )
      .bind(userId, previous?.status ?? null, actor, reason, now),
  ];
}

/** End or restart the whole programme. One row, one write. */
export async function setProgrammeStatus(db, { status, actor }) {
  if (status !== "active" && status !== "ended") return { ok: false, error: "Unknown programme status." };

  const current = await programmeStatus(db);
  if (current.status === status) return { ok: false, error: `The programme is already ${status}.` };

  const now = nowIso();
  await db.batch([
    db
      .prepare("UPDATE beta_program SET status = ?, ended_at = ?, changed_at = ?, changed_by = ? WHERE id = 1")
      .bind(status, status === "ended" ? now : null, now, actor),
    db
      .prepare(
        `INSERT INTO admin_audit (actor, action, target, before, after, created_at)
         VALUES (?, ?, 'beta_program', ?, ?, ?)`,
      )
      .bind(actor, `programme.${status}`, JSON.stringify({ status: current.status }), JSON.stringify({ status }), now),
  ]);

  return { ok: true, status };
}

const decisionKind = (decision) =>
  ({ approve: KINDS.APPROVED, reject: KINDS.REJECTED, waitlist: KINDS.WAITLISTED })[decision];
