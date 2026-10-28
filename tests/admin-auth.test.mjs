// node --test tests/admin-auth.test.mjs
//
// The account-based authorization boundary for the admin desk.
//
// The admin token used to be the only way in. This file pins the replacement:
// a session, an `admins` row keyed by the session's internal user id, and a
// CSRF token for every write. Each of the ten properties below is exercised
// against the real handlers and a real schema, and every refusal is paired
// with an assertion that nothing moved.

import test from "node:test";
import assert from "node:assert/strict";

import {
  createSession,
  csrfFor,
  currentSession,
  sha256Hex,
  SESSION_COOKIE,
} from "../functions/_auth.js";
import { onRequestGet as adminPage } from "../functions/admin.js";
import { onRequestPost as adminAction } from "../functions/api/admin/action.js";
import { onRequestGet as download } from "../functions/api/download.js";
import { onRequestGet as verify } from "../functions/api/license/verify.js";
import { onRequestPost as logout } from "../functions/logout.js";
import { accessFor, submitApplication } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const ENV = (db, extra = {}) => ({ KRYONSEC_DB: db, ...extra });

const ADMIN_ID = "u_admin";
const ADMIN_EMAIL = "admin@example.com";

async function signIn(db, { id = "u_1", email = "a@example.com", admin = false } = {}) {
  await makeUser(db, { id, email, admin });
  const token = await createSession(db, id);
  return { userId: id, token, cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
}

const getAdmin = (db, cookie = "", query = "") =>
  adminPage({ request: req(`${SITE}/admin${query}`, { cookie }), env: ENV(db) });

function actionPost(cookie, fields, { csrf = "", origin = SITE } = {}) {
  return req(`${SITE}/api/admin/action`, {
    method: "POST",
    cookie,
    body: new URLSearchParams({ ...fields, csrf }),
    headers: {
      "Sec-Fetch-Site": origin === SITE ? "same-origin" : "cross-site",
      Origin: origin,
    },
  });
}

async function applicant(db, { id = "u_applicant", email = "ada@example.com" } = {}) {
  await makeUser(db, { id, email });
  const filed = await submitApplication(db, id, {
    full_name: "Ada",
    contact_email: email,
    intended_use: "our own staging estate",
  });
  return { userId: id, applicationId: filed.id };
}

const appRow = (db, id) => db._raw.prepare("SELECT * FROM applications WHERE id = ?").get(id);
const count = (db, sql, ...params) => db._raw.prepare(sql).get(...params).n;
const auditActions = (db) =>
  db._raw
    .prepare("SELECT actor, action FROM admin_audit ORDER BY id")
    .all()
    .map((r) => ({ actor: r.actor, action: r.action }));

// 1 -------------------------------------------------------------------------
test("anonymous callers are redirected from the page and refused by the API", async () => {
  const db = testD1();
  const target = await applicant(db);

  const pageResponse = await getAdmin(db);
  assert.equal(pageResponse.status, 303);
  assert.equal(pageResponse.headers.get("Location"), "/signin?next=%2Fadmin");

  // Without a database there is no session store to consult, and the page
  // still fails closed rather than falling back to any legacy door.
  const unbound = await adminPage({ request: req(`${SITE}/admin`), env: {} });
  assert.equal(unbound.status, 303);
  assert.equal(unbound.headers.get("Location"), "/signin?next=%2Fadmin");

  const apiResponse = await adminAction({
    request: actionPost("", { intent: "decide", application: target.applicationId, decision: "approve" }),
    env: ENV(db),
  });
  assert.equal(apiResponse.status, 401);
  assert.equal(appRow(db, target.applicationId).status, "pending");
  assert.equal(count(db, "SELECT COUNT(*) AS n FROM admin_audit"), 0);
});

// 2 -------------------------------------------------------------------------
test("a signed-in non-admin gets 403 from the page and the API, and no data", async () => {
  const db = testD1();
  const outsider = await signIn(db, { id: "u_outsider", email: "outsider@example.com" });
  const target = await applicant(db);

  const pageResponse = await getAdmin(db, outsider.cookie, "?view=applications");
  const html = await pageResponse.text();
  assert.equal(pageResponse.status, 403);
  assert.match(html, /NOT AN/);
  assert.match(html, /outsider@example\.com/);
  assert.doesNotMatch(html, /ADMIN TOKEN/);
  assert.doesNotMatch(html, /class="admin-tabs"/);
  assert.doesNotMatch(html, /intent" value="decide"/);
  assert.doesNotMatch(html, /ada@example\.com/);

  const apiResponse = await adminAction({
    request: actionPost(
      outsider.cookie,
      { intent: "decide", application: target.applicationId, decision: "approve" },
      { csrf: outsider.csrf },
    ),
    env: ENV(db),
  });
  assert.equal(apiResponse.status, 403);
  assert.equal(appRow(db, target.applicationId).status, "pending");
  assert.deepEqual(auditActions(db), [{ actor: "outsider@example.com", action: "admin.denied" }]);
});

// 3 -------------------------------------------------------------------------
test("an authenticated administrator can open the desk and decide an application", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });
  const target = await applicant(db);

  const pageResponse = await getAdmin(db, boss.cookie, "?view=applications");
  const html = await pageResponse.text();
  assert.equal(pageResponse.status, 200);
  assert.match(html, /class="admin-tabs"/);
  assert.match(html, /intent" value="decide"/);
  assert.match(html, /SIGN OUT/);
  assert.match(html, new RegExp(ADMIN_EMAIL));

  const decision = await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: target.applicationId, decision: "approve" },
      { csrf: boss.csrf },
    ),
    env: ENV(db),
  });
  assert.equal(decision.status, 303);
  assert.match(decision.headers.get("Location"), /msg=decided/);
  assert.equal(appRow(db, target.applicationId).status, "approved");
});

// 4 -------------------------------------------------------------------------
test("tampered, expired, and revoked sessions are refused", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });

  const flipped = `${boss.token.slice(0, -1)}${boss.token.endsWith("0") ? "1" : "0"}`;
  const tamperedCookie = `${SESSION_COOKIE}=${flipped}`;
  const tamperedPage = await getAdmin(db, tamperedCookie);
  assert.equal(tamperedPage.status, 303);
  assert.equal(tamperedPage.headers.get("Location"), "/signin?next=%2Fadmin");
  const tamperedApi = await adminAction({
    request: actionPost(tamperedCookie, { intent: "programme", status: "ended" }, { csrf: boss.csrf }),
    env: ENV(db),
  });
  assert.equal(tamperedApi.status, 401);

  db._raw
    .prepare("UPDATE sessions SET expires_at = '2020-01-01T00:00:00.000Z' WHERE token_hash = ?")
    .run(await sha256Hex(boss.token));
  const expiredPage = await getAdmin(db, boss.cookie);
  assert.equal(expiredPage.status, 303);
  assert.equal(expiredPage.headers.get("Location"), "/signin?next=%2Fadmin");
  // An expired row is deleted the moment it is presented.
  assert.equal(
    count(db, "SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?", await sha256Hex(boss.token)),
    0,
  );
  const expiredApi = await adminAction({
    request: actionPost(boss.cookie, { intent: "programme", status: "ended" }, { csrf: boss.csrf }),
    env: ENV(db),
  });
  assert.equal(expiredApi.status, 401);

  const revoked = await createSession(db, ADMIN_ID);
  db._raw.prepare("DELETE FROM sessions WHERE token_hash = ?").run(await sha256Hex(revoked));
  const revokedCookie = `${SESSION_COOKIE}=${revoked}`;
  const revokedPage = await getAdmin(db, revokedCookie);
  assert.equal(revokedPage.status, 303);
  const revokedApi = await adminAction({
    request: actionPost(
      revokedCookie,
      { intent: "programme", status: "ended" },
      { csrf: await csrfFor(revoked) },
    ),
    env: ENV(db),
  });
  assert.equal(revokedApi.status, 401);

  assert.equal(db._raw.prepare("SELECT status FROM beta_program WHERE id = 1").get().status, "active");
});

// 5 -------------------------------------------------------------------------
test("a client cannot self-assign administrator privileges", async () => {
  const db = testD1();
  const outsider = await signIn(db, { id: "u_outsider", email: "outsider@example.com" });

  const pageResponse = await getAdmin(
    db,
    outsider.cookie,
    "?admin=1&role=admin&user_id=u_admin&email=admin%40example.com",
  );
  assert.equal(pageResponse.status, 403);
  assert.doesNotMatch(await pageResponse.text(), /class="admin-tabs"/);

  for (const fields of [
    { intent: "admin", action: "grant", user: outsider.userId },
    { intent: "decide", decision: "approve", admin: "1", role: "admin", is_admin: "true" },
  ]) {
    const response = await adminAction({
      request: actionPost(outsider.cookie, fields, { csrf: outsider.csrf }),
      env: ENV(db),
    });
    assert.equal(response.status, 403);
  }

  assert.equal(count(db, "SELECT COUNT(*) AS n FROM admins"), 0);
});

// 6 -------------------------------------------------------------------------
test("state-changing requests require the session CSRF token and same origin", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });
  const target = await applicant(db);

  const stale = await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: target.applicationId, decision: "approve" },
      { csrf: "0".repeat(64) },
    ),
    env: ENV(db),
  });
  assert.equal(stale.status, 403);
  assert.equal(appRow(db, target.applicationId).status, "pending");

  const crossSite = await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: target.applicationId, decision: "approve" },
      { csrf: boss.csrf, origin: "https://evil.example" },
    ),
    env: ENV(db),
  });
  assert.equal(crossSite.status, 403);
  assert.equal(appRow(db, target.applicationId).status, "pending");

  const audit = auditActions(db);
  assert.deepEqual(audit.map((r) => r.action), ["admin.csrf_refused", "admin.csrf_refused"]);
  for (const row of audit) assert.equal(row.actor, ADMIN_EMAIL);
});

// 7 -------------------------------------------------------------------------
test("approve and reject enforce administrator membership on the server", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });
  const outsider = await signIn(db, { id: "u_outsider", email: "outsider@example.com" });
  const first = await applicant(db, { id: "u_a1", email: "ada@example.com" });
  const second = await applicant(db, { id: "u_a2", email: "grace@example.com" });

  for (const [target, decision] of [
    [first, "approve"],
    [second, "reject"],
  ]) {
    const refused = await adminAction({
      request: actionPost(
        outsider.cookie,
        { intent: "decide", application: target.applicationId, decision },
        { csrf: outsider.csrf },
      ),
      env: ENV(db),
    });
    assert.equal(refused.status, 403);
    assert.equal(appRow(db, target.applicationId).status, "pending");
  }

  const approved = await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: first.applicationId, decision: "approve" },
      { csrf: boss.csrf },
    ),
    env: ENV(db),
  });
  assert.match(approved.headers.get("Location"), /msg=decided/);

  const rejected = await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: second.applicationId, decision: "reject" },
      { csrf: boss.csrf },
    ),
    env: ENV(db),
  });
  assert.match(rejected.headers.get("Location"), /msg=decided/);

  assert.equal(appRow(db, first.applicationId).status, "approved");
  assert.equal(appRow(db, second.applicationId).status, "rejected");
});

// 8 -------------------------------------------------------------------------
test("administrative actions are recorded in the audit log", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });
  const target = await applicant(db);

  await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: target.applicationId, decision: "approve", reason: "clear fit" },
      { csrf: boss.csrf },
    ),
    env: ENV(db),
  });
  await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "access", user: target.userId, action: "revoke", reason: "sharing the wheel" },
      { csrf: boss.csrf },
    ),
    env: ENV(db),
  });

  const audit = auditActions(db);
  assert.deepEqual(audit.map((r) => r.action), ["application.approve", "entitlement.revoked"]);
  for (const row of audit) assert.equal(row.actor, ADMIN_EMAIL);
});

// 9 -------------------------------------------------------------------------
test("signing out ends the session and closes the admin desk", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });

  assert.equal((await getAdmin(db, boss.cookie)).status, 200);

  const signedOut = await logout({
    request: req(`${SITE}/logout`, {
      method: "POST",
      cookie: boss.cookie,
      body: new URLSearchParams({ csrf: boss.csrf }),
      headers: { "Sec-Fetch-Site": "same-origin", Origin: SITE },
    }),
    env: ENV(db),
  });
  assert.equal(signedOut.status, 303);
  assert.equal(signedOut.headers.get("Location"), "/");
  assert.match(signedOut.headers.get("Set-Cookie"), /kr_session=;.*Max-Age=0/);
  assert.equal(await currentSession(db, req(`${SITE}/admin`, { cookie: boss.cookie })), null);

  const pageAfter = await getAdmin(db, boss.cookie);
  assert.equal(pageAfter.status, 303);
  assert.equal(pageAfter.headers.get("Location"), "/signin?next=%2Fadmin");

  const apiAfter = await adminAction({
    request: actionPost(boss.cookie, { intent: "programme", status: "ended" }, { csrf: boss.csrf }),
    env: ENV(db),
  });
  assert.equal(apiAfter.status, 401);
  assert.equal(db._raw.prepare("SELECT status FROM beta_program WHERE id = 1").get().status, "active");
});

// 10 ------------------------------------------------------------------------
test("the membership-key and download gates still answer as before", async () => {
  const db = testD1();
  const boss = await signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });
  const target = await applicant(db);

  await adminAction({
    request: actionPost(
      boss.cookie,
      { intent: "decide", application: target.applicationId, decision: "approve" },
      { csrf: boss.csrf },
    ),
    env: ENV(db),
  });
  assert.equal((await accessFor(db, target.userId)).entitled, true);

  const KEY = "KRYO-AB2C-DE3F-GH4J";
  const licensed = await verify({
    request: new Request(`${SITE}/api/license/verify?key=${KEY}`),
    env: { KRYONSEC_KEYS: KEY, KRYONSEC_DB: db },
  });
  assert.equal(licensed.status, 200);
  assert.equal((await licensed.json()).valid, true);

  // The download gate's own refusals are unchanged: no key, malformed key.
  const missing = await download({ request: new Request(`${SITE}/api/download`), env: {} });
  assert.equal(missing.status, 400);
  const malformed = await download({
    request: new Request(`${SITE}/api/download?key=KRYO-AB0C-DE3F-GH4J`),
    env: { KRYONSEC_KEYS: KEY },
  });
  assert.equal(malformed.status, 403);
});
