// node --test "tests/*.test.mjs"
//
// The access model. This is the layer the brief calls a critical security
// boundary, so the tests here are behavioural: they ask the same question the
// download endpoint and the CLI will ask, and check that revocation actually
// revokes.
//
// Where a guarantee belongs to the database rather than to JavaScript — one
// active application per person, one decision per application — the test
// attacks the database directly. A handler-only test would pass with the
// constraint dropped.

import test from "node:test";
import assert from "node:assert/strict";

import {
  accessFor,
  cleanField,
  decideApplication,
  getEntitlement,
  grantEntitlement,
  programmeStatus,
  queueCounts,
  revokeEntitlement,
  setProgrammeStatus,
  submitApplication,
  TERMS_VERSION,
} from "../functions/_store.js";
import { makeUser, testD1 } from "./helpers/d1.mjs";

const FORM = {
  full_name: "Ann Example",
  contact_email: "Ann@Example.COM",
  github_username: "ann",
  role: "Security engineer",
  primary_os: "Linux",
  intended_use: "Testing my own lab.",
  experience: "Five years.",
  feedback_willing: "on",
  comments: "Hello.",
};

const apply = (db, userId, fields = FORM) => submitApplication(db, userId, fields);
const rows = (db, sql) => db._raw.prepare(sql).get().n;

/** A user with a pending application. Returns both ids. */
async function applied(db, userId = "u_1") {
  await makeUser(db, { id: userId, email: `${userId}@example.com` });
  const filed = await apply(db, userId);
  assert.equal(filed.ok, true, "the fixture failed to file an application");
  return { userId, applicationId: filed.id };
}

// --- the gate ---------------------------------------------------------------

test("nobody signed in gets nothing", async () => {
  const db = testD1();
  for (const nobody of [null, undefined, ""]) {
    const access = await accessFor(db, nobody);
    assert.equal(access.entitled, false);
  }
});

test("a signed-in account with no entitlement is refused", async () => {
  const db = testD1();
  await makeUser(db);
  const access = await accessFor(db, "u_1");
  assert.equal(access.entitled, false);
  assert.equal(access.status, "none");
});

test("an active entitlement is allowed, and an unknown id is not", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });

  assert.equal((await accessFor(db, userId)).entitled, true);
  assert.equal((await accessFor(db, "u_deleted")).entitled, false);
});

test("revoked and suspended are both refused, and say which they are", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });

  await revokeEntitlement(db, { userId, actor: "founder", reason: "Abuse.", status: "suspended" });
  const suspended = await accessFor(db, userId);
  assert.equal(suspended.entitled, false);
  assert.equal(suspended.status, "suspended");

  await grantEntitlement(db, { userId, actor: "founder" });
  await revokeEntitlement(db, { userId, actor: "founder", reason: "Abuse.", status: "revoked" });
  const revoked = await accessFor(db, userId);
  assert.equal(revoked.entitled, false);
  assert.equal(revoked.status, "revoked");
  // The reason reaches the person, not just the audit log.
  assert.match(revoked.reason, /revoked/i);
});

test("an entitlement whose date has passed is refused, whatever its status says", async () => {
  // Nothing sets a date today, so this row is written by hand — which is the
  // point: the day someone does set one, the gate has to already honour it.
  const db = testD1();
  const { userId } = await applied(db);
  db._raw
    .prepare(
      `INSERT INTO entitlements (user_id, status, granted_at, expires_at, changed_at, changed_by)
       VALUES (?, 'active', ?, '2020-01-01T00:00:00.000Z', ?, 'test')`,
    )
    .run(userId, "2019-01-01T00:00:00.000Z", "2019-01-01T00:00:00.000Z");

  const access = await accessFor(db, userId);
  assert.equal(access.entitled, false);
  assert.equal(access.status, "expired");
});

test("ending the programme stops everyone, including an active entitlement", async () => {
  // The property that makes "end the beta" a real switch rather than a banner:
  // it is checked before the entitlement, so nobody's row can outvote it.
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });
  assert.equal((await accessFor(db, userId)).entitled, true);

  await setProgrammeStatus(db, { status: "ended", actor: "founder" });

  const access = await accessFor(db, userId);
  assert.equal(access.entitled, false);
  assert.equal(access.status, "programme_ended");
  assert.equal((await getEntitlement(db, userId)).status, "active", "the row itself should be untouched");

  await setProgrammeStatus(db, { status: "active", actor: "founder" });
  assert.equal((await accessFor(db, userId)).entitled, true, "restarting the programme should restore access");
});

// --- applying ---------------------------------------------------------------

test("an application is filed with its history and one notification", async () => {
  const db = testD1();
  await makeUser(db, { id: "u_1", email: "a@example.com" });
  const filed = await apply(db, "u_1");
  assert.equal(filed.ok, true);

  const app = db._raw.prepare("SELECT * FROM applications").get();
  assert.equal(app.status, "pending");
  assert.equal(app.terms_version, TERMS_VERSION);
  assert.ok(app.terms_accepted_at, "the acknowledgement was not timestamped");
  assert.equal(app.contact_email, "ann@example.com", "the address was not normalised");
  assert.equal(app.feedback_willing, 1);

  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM application_events"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM email_outbox"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM entitlements"), 0, "applying must not grant anything");
  assert.equal((await accessFor(db, "u_1")).entitled, false);
});

test("a second application is refused and leaves the first alone", async () => {
  const db = testD1();
  await makeUser(db, { id: "u_1" });
  assert.equal((await apply(db, "u_1")).ok, true);

  const again = await apply(db, "u_1");
  assert.equal(again.ok, false);
  assert.equal(again.code, "exists");
  assert.equal(again.application.status, "pending");

  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM applications"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM application_events"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM email_outbox"), 1);
});

test("two simultaneous submissions produce exactly one application", async () => {
  // A double click. Both handlers pass the pre-check, because a pre-check is
  // a read and a read is not a lock. The unique index is what decides.
  const db = testD1();
  await makeUser(db, { id: "u_1" });

  const both = await Promise.all([apply(db, "u_1"), apply(db, "u_1")]);
  assert.equal(both.filter((r) => r.ok).length, 1, "both submissions were accepted");
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM applications"), 1);
  assert.equal(both.filter((r) => r.code === "exists").length, 1);
});

test("a rejected applicant may apply again, and the old decision is kept", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "reject", actor: "founder" });

  const second = await apply(db, userId);
  assert.equal(second.ok, true);
  assert.notEqual(second.id, applicationId);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM applications"), 2);

  // Both refusals stay on the record — a reapplication must not erase the
  // history that explains why it is being looked at twice.
  const access = await accessFor(db, userId);
  assert.equal(access.application.status, "pending");
});

// --- deciding ---------------------------------------------------------------

test("approving writes the entitlement, the history, the audit row and the mail together", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);

  const result = await decideApplication(db, {
    applicationId, decision: "approve", actor: "founder", reason: "Looks good.",
  });
  assert.equal(result.ok, true);

  const app = db._raw.prepare("SELECT * FROM applications WHERE id = ?").get(applicationId);
  assert.equal(app.status, "approved");
  assert.equal(app.decided_by, "founder");
  assert.ok(app.decided_at);

  assert.equal((await getEntitlement(db, userId)).status, "active");
  assert.equal((await accessFor(db, userId)).entitled, true);

  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM application_events"), 2);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM entitlement_events"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM admin_audit"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM email_outbox"), 2);

  // The audit row carries the change, and nothing else.
  const audit = db._raw.prepare("SELECT * FROM admin_audit").get();
  assert.equal(audit.action, "application.approve");
  assert.deepEqual(JSON.parse(audit.before), { status: "pending" });
  assert.deepEqual(JSON.parse(audit.after), { status: "approved" });
});

test("a second approval is refused and adds no second trace", async () => {
  const db = testD1();
  const { applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });

  const again = await decideApplication(db, { applicationId, decision: "reject", actor: "other" });
  assert.equal(again.ok, false);

  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM application_events"), 2);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM admin_audit"), 1);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM email_outbox"), 2);
  assert.equal(
    db._raw.prepare("SELECT status FROM applications WHERE id = ?").get(applicationId).status,
    "approved",
  );
});

test("the database refuses a re-decision, and rolls the whole batch back when it does", async () => {
  // Attacking through the database rather than the handler, because the
  // handler's pre-check is a read and the guarantee has to survive two
  // requests that both got past it.
  const db = testD1();
  const { applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });

  const events = rows(db, "SELECT COUNT(*) AS n FROM application_events");
  const audit = rows(db, "SELECT COUNT(*) AS n FROM admin_audit");

  await assert.rejects(
    db.batch([
      db
        .prepare("UPDATE applications SET status = 'rejected', decided_by = 'attacker' WHERE id = ?")
        .bind(applicationId),
      db
        .prepare(
          `INSERT INTO application_events (application_id, from_status, to_status, actor, created_at)
           VALUES (?, 'approved', 'rejected', 'attacker', '2026-10-16T00:00:00.000Z')`,
        )
        .bind(applicationId),
    ]),
    /already been decided/i,
  );

  // The stray history row the second decision tried to write is gone with it.
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM application_events"), events);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM admin_audit"), audit);
  assert.equal(
    db._raw.prepare("SELECT status FROM applications WHERE id = ?").get(applicationId).status,
    "approved",
  );
});

test("rejecting admits nobody and waitlisting keeps the application in play", async () => {
  const db = testD1();
  const rejected = await applied(db, "u_1");
  await decideApplication(db, { applicationId: rejected.applicationId, decision: "reject", actor: "founder" });
  assert.equal((await accessFor(db, "u_1")).entitled, false);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM entitlements"), 0);

  const waitlisted = await applied(db, "u_2");
  await decideApplication(db, { applicationId: waitlisted.applicationId, decision: "waitlist", actor: "founder" });
  assert.equal((await accessFor(db, "u_2")).entitled, false);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM entitlements"), 0);

  // Still occupying the index predicate, so they cannot file a second one.
  const second = await apply(db, "u_2");
  assert.equal(second.ok, false);
  assert.equal(second.code, "exists");
});

test("an unknown decision changes nothing", async () => {
  const db = testD1();
  const { applicationId } = await applied(db);
  const result = await decideApplication(db, { applicationId, decision: "promote", actor: "founder" });

  assert.equal(result.ok, false);
  assert.equal(db._raw.prepare("SELECT status FROM applications").get().status, "pending");
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM application_events"), 1);
});

// --- revoking and restoring -------------------------------------------------

test("revoking flips the gate, is recorded once, and survives a second attempt", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });

  const first = await revokeEntitlement(db, { userId, actor: "founder", reason: "Shared the key." });
  assert.equal(first.ok, true);
  assert.equal((await accessFor(db, userId)).entitled, false);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM entitlement_events"), 2);

  const second = await revokeEntitlement(db, { userId, actor: "founder" });
  assert.equal(second.ok, false);
  // The guarded UPDATE matched no row, so its history row rolled back with it.
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM entitlement_events"), 2);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM admin_audit"), 2);
  assert.equal(
    db._raw.prepare("SELECT status FROM entitlements WHERE user_id = ?").get(userId).status,
    "revoked",
  );
});

test("a revoked account can be restored, and the history shows both moves", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });
  await revokeEntitlement(db, { userId, actor: "founder" });
  assert.equal((await accessFor(db, userId)).entitled, false);

  const restored = await grantEntitlement(db, { userId, actor: "founder", reason: "Mistake." });
  assert.equal(restored.ok, true);
  assert.equal((await accessFor(db, userId)).entitled, true);

  const history = db._raw
    .prepare("SELECT from_status, to_status FROM entitlement_events WHERE user_id = ? ORDER BY id")
    .all(userId);
  assert.deepEqual(
    history.map((h) => `${h.from_status}->${h.to_status}`),
    ["null->active", "active->revoked", "revoked->active"],
  );

  // Already active — the second grant is refused rather than stacked.
  assert.equal((await grantEntitlement(db, { userId, actor: "founder" })).ok, false);
});

test("access cannot be removed from an account that never had it", async () => {
  const db = testD1();
  await makeUser(db);
  const result = await revokeEntitlement(db, { userId: "u_1", actor: "founder" });
  assert.equal(result.ok, false);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM admin_audit"), 0);
});

test("an unrecognised entitlement status is refused before it is written", async () => {
  const db = testD1();
  const { userId, applicationId } = await applied(db);
  await decideApplication(db, { applicationId, decision: "approve", actor: "founder" });

  const result = await revokeEntitlement(db, { userId, actor: "founder", status: "banned" });
  assert.equal(result.ok, false);
  assert.equal((await accessFor(db, userId)).entitled, true);
});

// --- the programme switch ---------------------------------------------------

test("the programme state is one row and only one", async () => {
  const db = testD1();
  assert.equal((await programmeStatus(db)).status, "active");

  await setProgrammeStatus(db, { status: "ended", actor: "founder" });
  assert.equal((await programmeStatus(db)).status, "ended");
  assert.ok((await programmeStatus(db)).ended_at);

  // Ending it twice is refused rather than recorded twice.
  assert.equal((await setProgrammeStatus(db, { status: "ended", actor: "founder" })).ok, false);
  assert.equal(rows(db, "SELECT COUNT(*) AS n FROM admin_audit"), 1);
});

// --- the queue view ---------------------------------------------------------

test("the queue counts add up across decisions", async () => {
  const db = testD1();
  const a = await applied(db, "u_1");
  const b = await applied(db, "u_2");
  await applied(db, "u_3");
  await decideApplication(db, { applicationId: a.applicationId, decision: "approve", actor: "f" });
  await decideApplication(db, { applicationId: b.applicationId, decision: "reject", actor: "f" });

  assert.deepEqual(await queueCounts(db), { pending: 1, approved: 1, rejected: 1, waitlisted: 0 });
});

// --- input ------------------------------------------------------------------

test("free text is collapsed and capped before it is stored", async () => {
  const db = testD1();
  await makeUser(db);
  await apply(db, "u_1", {
    full_name: "  Ann\n\n  Example  ",
    intended_use: "x".repeat(9000),
    comments: "a".repeat(9000),
  });

  const app = db._raw.prepare("SELECT * FROM applications").get();
  assert.equal(app.full_name, "Ann Example");
  assert.equal(app.intended_use.length, 2000);
  assert.equal(app.comments.length, 2000);
});

test("cleanField never returns undefined, whatever it is handed", () => {
  for (const junk of [null, undefined, 0, false, {}, []]) {
    assert.equal(typeof cleanField(junk, "full_name"), "string");
  }
  assert.equal(cleanField("<script>", "comments"), "<script>", "escaping is the renderer's job, not storage's");
});
