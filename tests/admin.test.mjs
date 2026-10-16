// node --test "tests/*.test.mjs"
//
// The review desk, and the guard in front of every write on it.
//
// The guard is the point of this file. Session, then an `admins` row, then a
// CSRF token — three conditions that have to hold together, and the cheapest
// way to get one of them wrong is to write the test as an assertion on a
// boolean and have `checkCsrf` return a *message*. So each condition is
// exercised on its own, and each refusal is paired with an assertion that
// nothing in the database moved.

import test from "node:test";
import assert from "node:assert/strict";

import { csrfFor, createSession, SESSION_COOKIE } from "../functions/_auth.js";
import { onRequestGet as admin } from "../functions/admin.js";
import { onRequestPost as action } from "../functions/api/admin/action.js";
import { grantEntitlement, submitApplication } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const ENV = (db) => ({ KRYONSEC_DB: db });

/** A signed-in account. `admin: true` also writes the `admins` row. */
async function signIn(db, options = {}) {
  const userId = await makeUser(db, options);
  const token = await createSession(db, userId);
  return { userId, token, cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
}

/** The reviewer. A separate id from the applicant, or the two collide. */
const ADMIN_ID = "u_admin";
const ADMIN_EMAIL = "admin@example.com";
const signInAdmin = (db) => signIn(db, { id: ADMIN_ID, email: ADMIN_EMAIL, admin: true });

/** A browser form post — same-origin, with or without a valid CSRF token. */
function post(cookie, fields, { csrf = "", origin = SITE } = {}) {
  return req(`${SITE}/api/admin/action`, {
    method: "POST",
    cookie,
    body: new URLSearchParams({ ...fields, csrf }),
    headers: { "Sec-Fetch-Site": origin === SITE ? "same-origin" : "cross-site", Origin: origin },
  });
}

const getAdmin = (cookie) => admin({ request: req(`${SITE}/admin`, { cookie }), env: ENV(null) });

/** An application waiting to be decided. */
async function pending(db, options = {}) {
  const who = await signIn(db, options);
  const filed = await submitApplication(db, who.userId, {
    full_name: "Ada",
    contact_email: "ada@example.com",
    intended_use: "our own staging estate",
  });
  return { ...who, applicationId: filed.id };
}

const applicationRow = (db, id) => db._raw.prepare("SELECT * FROM applications WHERE id = ?").get(id);
const entitlementRow = (db, userId) => db._raw.prepare("SELECT * FROM entitlements WHERE user_id = ?").get(userId);

// --- the two doors ----------------------------------------------------------

test("a signed-in account that is not an admin gets the token prompt", async () => {
  const db = testD1();
  const { cookie } = await signIn(db);

  const response = await admin({ request: req(`${SITE}/admin`, { cookie }), env: ENV(db) });
  const body = await response.text();

  assert.equal(response.status, 200);
  // The prompt is the tell, and the absence of the queue is the substance:
  // a non-admin must not be one missing `<a>` away from the review desk.
  assert.match(body, /ADMIN TOKEN/);
  assert.doesNotMatch(body, /intent" value="decide"/);
});

test("an admin sees the queue, the programme switch and the audit log", async () => {
  const db = testD1();
  const { cookie } = await signInAdmin(db);
  await pending(db);

  const response = await admin({ request: req(`${SITE}/admin`, { cookie }), env: ENV(db) });
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /AUDIT/);
  assert.match(body, /intent" value="decide"/);
  assert.match(body, /intent" value="programme"/);
  // The admin's own email is the audit actor, so it has to reach the page.
  assert.match(body, new RegExp(ADMIN_EMAIL));
});

test("no session at all is sent to sign in, not shown the desk", async () => {
  const db = testD1();
  const response = await getAdmin("");
  assert.equal(response.status, 200);
  assert.match(await response.text(), /ADMIN TOKEN/);
});

// --- the guard on writes ----------------------------------------------------

test("a POST with no session goes to sign-in rather than being honoured", async () => {
  const db = testD1();
  const { applicationId } = await pending(db);

  const response = await action({
    request: post("", { intent: "decide", application: applicationId, decision: "approve" }),
    env: ENV(db),
  });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/signin?next=%2Fadmin");
  assert.equal(applicationRow(db, applicationId).status, "pending");
});

test("a non-admin cannot decide anything, and cannot tell the endpoint exists", async () => {
  const db = testD1();
  const applicant = await pending(db);
  const { cookie, csrf } = await signIn(db, { id: "u_other", email: "other@example.com" });

  const response = await action({
    request: post(cookie, { intent: "decide", application: applicant.applicationId, decision: "approve" }, { csrf }),
    env: ENV(db),
  });

  // 404 rather than 403: a 403 confirms the endpoint is real and that this
  // account was the one turned away.
  assert.equal(response.status, 404);
  assert.equal(applicationRow(db, applicant.applicationId).status, "pending");
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM admin_audit").get().n, 0);
});

test("an admin with a stale CSRF token is refused and changes nothing", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const applicant = await pending(db);

  const response = await action({
    request: post(admin_.cookie, { intent: "decide", application: applicant.applicationId, decision: "approve" }, { csrf: "0".repeat(64) }),
    env: ENV(db),
  });

  assert.equal(response.status, 403);
  assert.equal(applicationRow(db, applicant.applicationId).status, "pending");
  assert.equal(entitlementRow(db, applicant.userId), undefined);
});

test("a cross-site POST is refused even with a correct token", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const applicant = await pending(db);

  // A SameSite=Lax cookie still rides a top-level cross-site form POST, so
  // the CSRF token is the only thing standing here.
  const response = await action({
    request: post(
      admin_.cookie,
      { intent: "decide", application: applicant.applicationId, decision: "approve" },
      { csrf: admin_.csrf, origin: "https://evil.example" },
    ),
    env: ENV(db),
  });

  assert.equal(response.status, 403);
  assert.equal(applicationRow(db, applicant.applicationId).status, "pending");
});

// --- the writes themselves --------------------------------------------------

test("approving grants access, records who did it, and queues one email", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const applicant = await pending(db);

  const response = await action({
    request: post(admin_.cookie, {
      intent: "decide",
      application: applicant.applicationId,
      decision: "approve",
      reason: "clear fit",
    }, { csrf: admin_.csrf }),
    env: ENV(db),
  });

  assert.equal(response.status, 303);
  assert.match(response.headers.get("Location"), /^\/admin\?status=pending&msg=decided/);

  const application = applicationRow(db, applicant.applicationId);
  assert.equal(application.status, "approved");
  assert.equal(application.decided_by, ADMIN_EMAIL);

  const entitlement = entitlementRow(db, applicant.userId);
  assert.equal(entitlement.status, "active");
  assert.equal(entitlement.reason, "clear fit");

  const audit = db._raw.prepare("SELECT actor, action FROM admin_audit ORDER BY created_at DESC").get();
  assert.equal(audit.actor, ADMIN_EMAIL);

  // Two emails, and they are the two this account should have: the
  // acknowledgement the submission queued, and the approval. Kinds rather than
  // a count, because a count of 2 would also pass if the approval were
  // duplicated and the acknowledgement lost.
  const queued = db._raw.prepare("SELECT kind FROM email_outbox").all().map((r) => r.kind).sort();
  assert.deepEqual(queued, ["application.approved", "application.received"]);
});

test("a second decision on the same application says so and changes nothing", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const applicant = await pending(db);
  const first = await action({
    request: post(admin_.cookie, { intent: "decide", application: applicant.applicationId, decision: "approve" }, { csrf: admin_.csrf }),
    env: ENV(db),
  });
  assert.equal(first.status, 303);

  const second = await action({
    request: post(admin_.cookie, { intent: "decide", application: applicant.applicationId, decision: "reject" }, { csrf: admin_.csrf }),
    env: ENV(db),
  });

  // Not an error — the guarded UPDATE did its job, and the admin is told the
  // honest thing rather than the page silently re-rendering as if it worked.
  assert.match(second.headers.get("Location"), /msg=already/);
  assert.equal(applicationRow(db, applicant.applicationId).status, "approved");
  assert.equal(entitlementRow(db, applicant.userId).status, "active");
  // One decision event, not two — the submission's own "pending" event is a
  // different row and is not what this is counting.
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM application_events WHERE to_status = 'approved'").get().n, 1);
});

test("revoking through the desk takes access away and keeps the reason", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const applicant = await pending(db);
  await action({
    request: post(admin_.cookie, { intent: "decide", application: applicant.applicationId, decision: "approve" }, { csrf: admin_.csrf }),
    env: ENV(db),
  });

  const response = await action({
    request: post(admin_.cookie, { intent: "access", user: applicant.userId, action: "revoke", reason: "sharing the wheel" }, { csrf: admin_.csrf }),
    env: ENV(db),
  });

  assert.match(response.headers.get("Location"), /msg=revoked/);
  const entitlement = entitlementRow(db, applicant.userId);
  assert.equal(entitlement.status, "revoked");
  assert.equal(entitlement.reason, "sharing the wheel");
});

test("an unrecognised intent or decision is refused, not defaulted", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const applicant = await pending(db);

  for (const fields of [
    { intent: "decide", application: applicant.applicationId, decision: "let-them-in" },
    { intent: "access", user: applicant.userId, action: "delete" },
    { intent: "nonsense" },
  ]) {
    const response = await action({ request: post(admin_.cookie, fields, { csrf: admin_.csrf }), env: ENV(db) });
    assert.match(response.headers.get("Location"), /msg=invalid/);
  }

  assert.equal(applicationRow(db, applicant.applicationId).status, "pending");
  assert.equal(entitlementRow(db, applicant.userId), undefined);
});

test("ending the programme closes it for everyone and is recorded", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);

  const response = await action({
    request: post(admin_.cookie, { intent: "programme", status: "ended" }, { csrf: admin_.csrf }),
    env: ENV(db),
  });

  assert.match(response.headers.get("Location"), /msg=programme/);
  assert.equal(db._raw.prepare("SELECT status FROM beta_program WHERE id = 1").get().status, "ended");

  // And the gate agrees — closing it is not just a label on a page.
  const holder = await signIn(db, { id: "u_holder", email: "holder@example.com" });
  await grantEntitlement(db, { userId: holder.userId, actor: "admin" });
  const { accessFor } = await import("../functions/_store.js");
  assert.equal((await accessFor(db, holder.userId)).entitled, false);
});

test("an admin cannot make themselves an admin through the desk", async () => {
  const db = testD1();
  const admin_ = await signInAdmin(db);
  const other = await signIn(db, { id: "u_other", email: "other@example.com" });

  // There is no intent for this, and that is deliberate: privilege escalation
  // would need a new code path, not a crafted form field.
  const response = await action({
    request: post(admin_.cookie, { intent: "admin", user: other.userId, action: "grant" }, { csrf: admin_.csrf }),
    env: ENV(db),
  });

  assert.match(response.headers.get("Location"), /msg=invalid/);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM admins").get().n, 1);
});
