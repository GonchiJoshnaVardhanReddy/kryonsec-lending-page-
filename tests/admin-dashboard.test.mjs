// node --test "tests/*.test.mjs"
//
// The sectioned admin dashboard and the new credential-revocation actions.
//
// The properties this file is built around:
//
//   - every view is behind the same check — an anonymous visitor and a
//     signed-in non-admin both get the token prompt, never a table;
//   - search text is a value, not SQL, and `%` is a character;
//   - a session or CLI token can be revoked by an administrator, and only
//     for the account named; a tampered id matches nothing;
//   - a refusal is audited, and neither a credential nor a CSRF token ever
//     reaches the audit table or the page;
//   - page numbers past the end clamp to the last real page.

import test from "node:test";
import assert from "node:assert/strict";

import { createSession, csrfFor, currentSession, sha256Hex, SESSION_COOKIE } from "../functions/_auth.js";
import { createCliSession, cliSessionFromToken } from "../functions/_cli.js";
import { onRequestGet as admin } from "../functions/admin.js";
import { onRequestPost as action } from "../functions/api/admin/action.js";
import { decideApplication, submitApplication } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const VIEWS = ["overview", "applications", "activity", "users", "devices", "security"];
const ADMIN_ID = `u_${"a".repeat(32)}`;
const env = (db, extra = {}) => ({ KRYONSEC_DB: db, ...extra });

/** Opaque 32-hex ids, because the detail route validates the shape. */
const uid = (n) => `u_${n.toString(16).padStart(32, "0")}`;

async function signIn(db, options = {}) {
  const userId = await makeUser(db, options);
  const token = await createSession(db, userId);
  return { userId, token, cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
}

const signInAdmin = (db) => signIn(db, { id: ADMIN_ID, email: "admin@example.com", admin: true });

const page = (db, cookie, query = "", extra = {}) =>
  admin({ request: req(`${SITE}/admin${query}`, { cookie }), env: env(db, extra) });

const body = async (response) => response.text();

function post(cookie, fields, { csrf = "", origin = SITE } = {}) {
  return req(`${SITE}/api/admin/action`, {
    method: "POST",
    cookie,
    body: new URLSearchParams({ ...fields, csrf }),
    headers: { "Fetch-Site": "same-origin", "Sec-Fetch-Site": origin === SITE ? "same-origin" : "cross-site", Origin: origin },
  });
}

const row = (db, sql, ...params) => db._raw.prepare(sql).get(...params);
const all = (db, sql, ...params) => db._raw.prepare(sql).all(...params);

async function applicant(db, { id = uid(1), email = "ada@example.com" } = {}) {
  const who = await signIn(db, { id, email });
  const filed = await submitApplication(db, who.userId, {
    full_name: "Ada",
    contact_email: email,
    intended_use: "our own staging estate",
  });
  return { ...who, applicationId: filed.id };
}

// --- every view, same guard -------------------------------------------------

test("every view shows the token prompt to an anonymous visitor", async () => {
  const db = testD1();
  await applicant(db);
  for (const view of VIEWS) {
    const response = await page(db, "", `?view=${view}`);
    const html = await body(response);
    assert.equal(response.status, 200, view);
    assert.match(html, /ADMIN TOKEN/, view);
    assert.doesNotMatch(html, /class="admin-tabs"/, view);
    assert.doesNotMatch(html, /class="stat-grid"/, view);
  }
});

test("every view shows the token prompt to a signed-in non-admin", async () => {
  const db = testD1();
  const other = await signIn(db, { id: uid(2), email: "other@example.com" });
  await applicant(db);
  for (const view of VIEWS) {
    const html = await body(await page(db, other.cookie, `?view=${view}`));
    assert.match(html, /ADMIN TOKEN/, view);
    assert.doesNotMatch(html, /ada@example\.com/, view);
  }
});

test("the new revocation intents refuse an anonymous caller before touching a row", async () => {
  const db = testD1();
  const target = await applicant(db);
  const machine = await createCliSession(db, { userId: target.userId });
  const cliId = row(db, "SELECT id FROM cli_sessions").id;

  for (const fields of [
    { intent: "session", action: "revoke", user: target.userId, token: "0".repeat(64) },
    { intent: "cli", action: "revoke", id: cliId },
  ]) {
    const response = await action({ request: post("", fields), env: env(db) });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("Location"), "/signin?next=%2Fadmin");
  }

  assert.equal(row(db, "SELECT COUNT(*) AS n FROM sessions").n, 1);
  assert.ok(await cliSessionFromToken(db, machine));
  assert.equal(row(db, "SELECT COUNT(*) AS n FROM admin_audit").n, 0);
});

// --- the sections render ----------------------------------------------------

test("an admin gets each section with its own content and no error", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);
  await createCliSession(db, { userId: target.userId, label: "linux/x86_64" });

  const expectations = {
    overview: [/ACCOUNTS/, /PENDING APPLICATIONS/, /AUDIT — RECENT ACTIVITY/],
    applications: [/APPLICATIONS/, /APPROVE/, /Ada/],
    activity: [/Append-only/, /ACTIVITY/],
    users: [/ada@example\.com/, /USERS &amp; ACCESS/],
    devices: [/COMMAND-LINE SESSIONS/, /linux\/x86_64/, /LEGACY DEVICES/],
    security: [/CONFIGURATION/, /Presence only/, /All 18 required tables are present/],
  };

  for (const [view, patterns] of Object.entries(expectations)) {
    const html = await body(await page(db, admin_.cookie, `?view=${view}`));
    for (const pattern of patterns) assert.match(html, pattern, view);
  }

  const detail = await body(await page(db, admin_.cookie, `?view=user&id=${target.userId}`));
  assert.match(detail, /SIGN-IN IDENTITIES/);
  assert.match(detail, /WEBSITE SESSIONS/);
  assert.match(detail, /COMMAND-LINE MACHINES/);
});

test("an unknown view falls back to the overview rather than a blank page", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const html = await body(await page(db, admin_.cookie, "?view=nonsense"));
  assert.match(html, /class="stat-grid"/);
  assert.match(html, /OPERATIONS/);
});

test("a missing account says so and does not fall through to another account", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  for (const id of ["", "u_1", "not-an-id", uid(9)]) {
    const html = await body(await page(db, admin_.cookie, `?view=user&id=${encodeURIComponent(id)}`));
    assert.match(html, /That account does not exist\./);
  }
});

// --- search and pagination --------------------------------------------------

test("search is a value: wildcards and SQL fragments match nothing", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  await signIn(db, { id: uid(1), email: "alice@example.com" });
  await signIn(db, { id: uid(2), email: "bob@example.com" });

  const wildcard = await body(await page(db, admin_.cookie, "?view=users&q=%25"));
  assert.match(wildcard, /0 account\(s\)/);
  assert.doesNotMatch(wildcard, /alice@example\.com/);

  const injection = await body(await page(db, admin_.cookie, `?view=users&q=${encodeURIComponent("' OR 1=1 --")}`));
  assert.match(injection, /0 account\(s\)/);
  assert.doesNotMatch(injection, /alice@example\.com/);

  const normal = await body(await page(db, admin_.cookie, "?view=users&q=alice"));
  assert.match(normal, /1 account\(s\)/);
  assert.match(normal, /alice@example\.com/);
  assert.doesNotMatch(normal, /bob@example\.com/);
});

test("application search escapes its wildcard too", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  await applicant(db, { id: uid(1), email: "ada@example.com" });
  const html = await body(await page(db, admin_.cookie, `?view=applications&status=all&q=${encodeURIComponent("%")}`));
  assert.match(html, /Nothing matches that filter\./);
});

test("a page past the end clamps to the last real page", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  for (let i = 1; i <= 55; i += 1) await signIn(db, { id: uid(i), email: `u${i}@example.com` });

  const html = await body(await page(db, admin_.cookie, "?view=users&page=999"));
  // 56 accounts including the admin, 50 per page, so two pages.
  assert.match(html, /PAGE 2 \/ 2/);
  assert.match(html, /56 account\(s\)/);
});

test("an application's own text is escaped, never markup", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const who = await signIn(db, { id: uid(1), email: "ada@example.com" });
  await submitApplication(db, who.userId, { full_name: "<script>alert(1)</script>", intended_use: "x" });

  const html = await body(await page(db, admin_.cookie, "?view=applications&status=all"));
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

// --- website session revocation --------------------------------------------

test("an administrator can revoke a website session, and the cookie stops working", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);
  const hash = await sha256Hex(target.token);

  const detail = await body(await page(db, admin_.cookie, `?view=user&id=${target.userId}`));
  // The visible row is the short stored hash, never the session cookie. The
  // full SHA-256 rides in the revoke form's hidden field because it names the
  // row; it is a hash, not a reusable credential, and the cookie itself is
  // nowhere on the page.
  assert.match(detail, new RegExp(`<code>${hash.slice(0, 8)}…</code>`));
  assert.match(detail, new RegExp(`name="token" value="${hash}"`));
  assert.doesNotMatch(detail, new RegExp(target.token));

  const response = await action({
    request: post(admin_.cookie, { intent: "session", action: "revoke", user: target.userId, token: hash }, { csrf: admin_.csrf }),
    env: env(db),
  });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), `/admin?view=user&id=${target.userId}&msg=session_revoked`);
  assert.equal(row(db, "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", target.userId).n, 0);
  assert.equal(await currentSession(db, req(`${SITE}/dashboard`, { cookie: target.cookie })), null);

  const audit = row(db, "SELECT actor, action, target, before, after FROM admin_audit WHERE action = 'session.revoked'");
  assert.equal(audit.actor, "admin@example.com");
  assert.equal(audit.target, target.userId);
  assert.equal(audit.before, null);
});

test("a session id is scoped to its account, so a tampered owner matches nothing", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const victim = await applicant(db, { id: uid(1), email: "ada@example.com" });
  const hash = await sha256Hex(victim.token);

  const response = await action({
    // ADMIN_ID is a real account, so the shape passes; the DELETE is scoped to
    // it and the victim's row is out of reach.
    request: post(admin_.cookie, { intent: "session", action: "revoke", user: ADMIN_ID, token: hash }, { csrf: admin_.csrf }),
    env: env(db),
  });

  assert.match(response.headers.get("Location"), /msg=missing/);
  assert.equal(row(db, "SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?", hash).n, 1);
  assert.equal(row(db, "SELECT action FROM admin_audit ORDER BY id DESC LIMIT 1").action, "session.revoke_missed");
});

test("a refused CSRF token revokes nothing and is audited without the token", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);
  const hash = await sha256Hex(target.token);
  const sentinel = "s".repeat(64);

  const response = await action({
    request: post(admin_.cookie, { intent: "session", action: "revoke", user: target.userId, token: hash }, { csrf: sentinel }),
    env: env(db),
  });

  assert.equal(response.status, 403);
  assert.equal(row(db, "SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?", hash).n, 1);

  const audit = row(db, "SELECT actor, action, target, before, after FROM admin_audit WHERE action = 'admin.csrf_refused'");
  assert.equal(audit.actor, "admin@example.com");
  assert.equal(audit.target, "session");
  assert.equal(audit.before, null);
  assert.equal(audit.after, null);
  for (const value of Object.values(audit)) assert.ok(!String(value ?? "").includes(sentinel));
  for (const value of Object.values(audit)) assert.ok(!String(value ?? "").includes(hash));
});

// --- CLI session revocation -------------------------------------------------

test("an administrator can revoke a command-line session from the devices view", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);
  const raw = await createCliSession(db, { userId: target.userId, label: "linux/x86_64" });
  const id = row(db, "SELECT id FROM cli_sessions").id;

  const response = await action({
    request: post(admin_.cookie, { intent: "cli", action: "revoke", id }, { csrf: admin_.csrf }),
    env: env(db),
  });

  assert.equal(response.headers.get("Location"), "/admin?view=devices&msg=cli_revoked");
  assert.ok(row(db, "SELECT revoked_at FROM cli_sessions WHERE id = ?", id).revoked_at);
  assert.equal(await cliSessionFromToken(db, raw), null);
  assert.equal(row(db, "SELECT action FROM admin_audit ORDER BY id DESC LIMIT 1").action, "cli_session.revoked");
});

test("a CLI revocation from an account page is scoped to that account", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db, { id: uid(1), email: "ada@example.com" });
  const other = await signIn(db, { id: uid(2), email: "other@example.com" });
  const raw = await createCliSession(db, { userId: other.userId });
  const id = row(db, "SELECT id FROM cli_sessions").id;

  // Named account is the target, but the row belongs to someone else.
  const missed = await action({
    request: post(admin_.cookie, { intent: "cli", action: "revoke", id, user: target.userId }, { csrf: admin_.csrf }),
    env: env(db),
  });
  assert.match(missed.headers.get("Location"), /msg=missing/);
  assert.ok(await cliSessionFromToken(db, raw));

  const hit = await action({
    request: post(admin_.cookie, { intent: "cli", action: "revoke", id, user: other.userId }, { csrf: admin_.csrf }),
    env: env(db),
  });
  assert.match(hit.headers.get("Location"), /msg=cli_revoked/);
  assert.equal(await cliSessionFromToken(db, raw), null);
});

test("the raw CLI token never reaches a page", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);
  const raw = await createCliSession(db, { userId: target.userId, label: "linux/x86_64" });

  for (const query of ["?view=devices", `?view=user&id=${target.userId}`]) {
    const html = await body(await page(db, admin_.cookie, query));
    assert.doesNotMatch(html, new RegExp(raw), query);
    assert.match(html, /s_[0-9a-f]{8}…/, query);
  }
});

// --- invalid input ----------------------------------------------------------

test("malformed revocation parameters are refused and audited as invalid", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);

  const attempts = [
    { intent: "session", action: "revoke", user: target.userId, token: "not-a-hash" },
    { intent: "session", action: "delete", user: target.userId, token: "0".repeat(64) },
    { intent: "cli", action: "revoke", id: "../../etc/passwd" },
    { intent: "cli", action: "delete", id: "s_" + "0".repeat(32) },
  ];

  for (const fields of attempts) {
    const response = await action({ request: post(admin_.cookie, fields, { csrf: admin_.csrf }), env: env(db) });
    assert.match(response.headers.get("Location"), /msg=invalid/);
  }

  assert.equal(row(db, "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", target.userId).n, 1);
  assert.equal(row(db, "SELECT COUNT(*) AS n FROM admin_audit WHERE action = 'admin.invalid'").n, attempts.length);
});

test("repeated refusals are throttled instead of growing the audit table", async () => {
  const db = testD1();
  const outsider = await signIn(db, { id: uid(3), email: "outsider@example.com" });
  const now = new Date().toISOString();
  for (let i = 0; i < 25; i += 1) {
    db._raw
      .prepare("INSERT INTO admin_audit (actor, action, target, created_at) VALUES (?, 'admin.denied', 'decide', ?)")
      .run(outsider.cookie ? "outsider@example.com" : "outsider@example.com", now);
  }

  const response = await action({
    request: post(outsider.cookie, { intent: "decide", decision: "approve" }, { csrf: outsider.csrf }),
    env: env(db),
  });

  assert.equal(response.status, 429);
  assert.equal(row(db, "SELECT COUNT(*) AS n FROM admin_audit").n, 25);
});

// --- security view and redaction -------------------------------------------

test("the security view reports presence and never a value", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const secrets = {
    KRYONSEC_GITHUB_CLIENT_ID: "gh-id-SENTINEL",
    KRYONSEC_GITHUB_CLIENT_SECRET: "gh-secret-SENTINEL",
    KRYONSEC_GOOGLE_CLIENT_ID: "google-id-SENTINEL",
    KRYONSEC_GOOGLE_CLIENT_SECRET: "google-secret-SENTINEL",
    KRYONSEC_REPO: "owner/repo-SENTINEL",
    KRYONSEC_EMAIL_PROVIDER: "provider-SENTINEL",
  };

  const html = await body(await page(db, admin_.cookie, "?view=security", secrets));
  assert.match(html, /CONFIGURED/);
  assert.match(html, /Presence only/);
  for (const value of Object.values(secrets)) assert.doesNotMatch(html, new RegExp(value));
});

test("the security view names a missing mail provider rather than hiding it", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const html = await body(await page(db, admin_.cookie, "?view=security"));
  assert.match(html, /EMAIL PROVIDER/);
  assert.match(html, /log mode/);
});

// --- consistency and empty states ------------------------------------------

test("an approved application with no entitlement is shown as an inconsistency", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const target = await applicant(db);
  await decideApplication(db, { applicationId: target.applicationId, decision: "approve", actor: "admin@example.com" });
  db._raw.prepare("DELETE FROM entitlements WHERE user_id = ?").run(target.userId);

  const html = await body(await page(db, admin_.cookie, `?view=user&id=${target.userId}`));
  assert.match(html, /although its application says approved/);
  assert.match(html, /GRANT ACCESS/);
});

test("empty sections say so instead of rendering an empty table", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);

  assert.match(await body(await page(db, admin_.cookie, "?view=applications")), /Nothing matches that filter\./);
  assert.match(await body(await page(db, admin_.cookie, "?view=devices")), /0 command-line session\(s\)/);
  assert.match(await body(await page(db, admin_.cookie, "?view=users")), /1 account\(s\)/);
  assert.match(await body(await page(db, admin_.cookie, "?view=activity")), /0 entr/);
});
