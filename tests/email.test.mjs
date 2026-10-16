// node --test "tests/*.test.mjs"
//
// Notifications. The assertions that matter here are not about wording — they
// are about the two things the brief says an email must never do: carry a
// reusable credential, and duplicate itself when something is retried.

import test from "node:test";
import assert from "node:assert/strict";

import { KINDS, drain, outboxStatement, render, subjectOf } from "../functions/_email.js";
import { decideApplication, submitApplication } from "../functions/_store.js";
import { makeUser, testD1 } from "./helpers/d1.mjs";

const ALL_KINDS = Object.values(KINDS);

test("every declared kind has a template", () => {
  // Guards the failure mode where a kind is added to the outbox by a caller
  // and silently renders to nothing at send time.
  for (const kind of ALL_KINDS) {
    const rendered = render({ kind, payload: JSON.stringify({ name: "Ann", reason: "Because." }) });
    assert.ok(rendered, `${kind} has no template`);
    assert.ok(rendered.subject.length > 0);
    assert.ok(rendered.text.length > 0);
  }
  assert.equal(render({ kind: "application.made-up" }), null);
});

test("no message carries anything that could be replayed", () => {
  // The brief is explicit: no permanent reusable authorization credential in
  // email. Membership keys, device codes, session cookies and CLI tokens are
  // all out — and this is the test that notices if one is ever added.
  const credentialish = /[?&](key|token|code|device_code|session)=|KRYO-[A-Z0-9]{4}-|Bearer |KRYONSEC_/i;

  for (const kind of ALL_KINDS) {
    const rendered = render({ kind, payload: JSON.stringify({ name: "Ann", reason: "Shared the key." }) });
    assert.doesNotMatch(rendered.text, credentialish, `${kind} leaked a credential`);
    assert.doesNotMatch(rendered.subject, credentialish);
  }
});

test("a subject is a header, and rendering survives a broken payload", () => {
  const rendered = render({ kind: KINDS.RECEIVED, payload: null });
  assert.equal(subjectOf(rendered), rendered.subject);

  const oneLine = render({ kind: KINDS.RECEIVED, payload: "{not json" });
  assert.ok(oneLine.text.startsWith("Hi,"), "a malformed payload should degrade, not throw");

  const named = render({ kind: KINDS.RECEIVED, payload: JSON.stringify({ name: "  Ann\n" }) });
  assert.ok(named.text.startsWith("Hi Ann,"));
});

test("only the revocation message repeats the reason it was given", () => {
  const payload = JSON.stringify({ name: "Ann", reason: "Chargeback." });
  assert.match(render({ kind: KINDS.REVOKED, payload }).text, /Chargeback\./);
  // An applicant must never see an internal review note, even if one was
  // passed in alongside the decision.
  assert.doesNotMatch(render({ kind: KINDS.REJECTED, payload }).text, /Chargeback\./);
});

test("queueing the same notification twice writes one row", async () => {
  const db = testD1();
  const queue = () =>
    db.batch([
      outboxStatement(db, {
        kind: KINDS.RECEIVED, dedupeKey: "a_1:received", toEmail: "a@example.com", userId: "u_1",
      }),
    ]);
  await queue();
  await queue();
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM email_outbox").get().n, 1);
});

test("with no provider configured, a drain records the send and logs no body", async (t) => {
  const db = testD1();
  const logged = [];
  t.mock.method(console, "log", (...args) => logged.push(args.join(" ")));

  await db.batch([
    outboxStatement(db, {
      kind: KINDS.RECEIVED, dedupeKey: "a_1:received", toEmail: "a@example.com", userId: "u_1",
    }),
  ]);

  const result = await drain(db, {});
  assert.deepEqual(result, { sent: 1, failed: 0, queued: 1 });

  const row = db._raw.prepare("SELECT * FROM email_outbox").get();
  assert.equal(row.status, "sent");
  assert.equal(row.attempts, 1);
  assert.ok(row.sent_at);

  // The envelope is logged; the message is not. An applicant's own words
  // should not be sitting in a Worker log for the next person who reads one.
  assert.equal(logged.length, 1);
  assert.match(logged[0], /application\.received/);
  assert.doesNotMatch(logged[0], /Kryonsec beta/);
  assert.doesNotMatch(logged[0], /Your request for/);
});

test("a named provider with no adapter fails the row instead of losing it", async () => {
  const db = testD1();
  await db.batch([
    outboxStatement(db, {
      kind: KINDS.APPROVED, dedupeKey: "a_1:approved", toEmail: "a@example.com", userId: "u_1",
    }),
  ]);

  const result = await drain(db, { KRYONSEC_EMAIL_PROVIDER: "resend", KRYONSEC_EMAIL_FROM: "beta@kryonsec.in" });
  assert.equal(result.failed, 1);

  const row = db._raw.prepare("SELECT * FROM email_outbox").get();
  assert.equal(row.status, "failed");
  assert.match(row.last_error, /no adapter/i);
  // Still there, so wiring the adapter later sends it.
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM email_outbox").get().n, 1);
});

test("a provider with no from-address fails rather than sending as nobody", async () => {
  const db = testD1();
  await db.batch([
    outboxStatement(db, { kind: KINDS.APPROVED, dedupeKey: "a_1:approved", toEmail: "a@example.com" }),
  ]);

  await drain(db, { KRYONSEC_EMAIL_PROVIDER: "resend" });
  assert.match(db._raw.prepare("SELECT last_error FROM email_outbox").get().last_error, /FROM/i);
});

test("an unknown kind is marked failed with a reason, not silently dropped", async () => {
  const db = testD1();
  db._raw
    .prepare(
      `INSERT INTO email_outbox (kind, dedupe_key, to_email, status, created_at)
       VALUES ('application.invented', 'x', 'a@example.com', 'queued', '2026-10-16T00:00:00.000Z')`,
    )
    .run();

  const result = await drain(db, {});
  assert.equal(result.failed, 1);
  assert.match(db._raw.prepare("SELECT last_error FROM email_outbox").get().last_error, /template/i);
});

test("a decision queues exactly one message for the decision that was made", async () => {
  const db = testD1();
  await makeUser(db, { id: "u_1", email: "a@example.com" });
  const filed = await submitApplication(db, "u_1", { full_name: "Ann" });

  await decideApplication(db, { applicationId: filed.id, decision: "approve", actor: "founder" });

  const kinds = db._raw
    .prepare("SELECT kind FROM email_outbox ORDER BY id")
    .all()
    .map((r) => r.kind);
  assert.deepEqual(kinds, [KINDS.RECEIVED, KINDS.APPROVED]);
});
