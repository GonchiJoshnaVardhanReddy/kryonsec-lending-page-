// node --test "tests/*.test.mjs"
//
// The application form, end to end: the GET that renders it, the POST that
// validates it, and the sign-out beside it. These drive the real handlers
// against the real schema through tests/helpers/d1.mjs, because the things
// worth catching here are exactly the ones a hand-written expectation would
// miss — a column the migration does not have, a constraint that fires on a
// legitimate retry, a validation that refuses in the message and writes anyway.

import test from "node:test";
import assert from "node:assert/strict";

import { csrfFor, createSession, SESSION_COOKIE, sha256Hex } from "../functions/_auth.js";
import { onRequestGet as getApply } from "../functions/apply.js";
import { onRequestPost as postApply } from "../functions/api/apply.js";
import { onRequestPost as postLogout } from "../functions/logout.js";
import { TERMS_VERSION } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";

/** Everything a valid submission needs, so each test changes one thing. */
const GOOD = {
  full_name: "Ada Lovelace",
  contact_email: "ada@example.com",
  github_username: "@ada",
  portfolio_url: "https://example.com/work",
  role: "Security engineer",
  primary_os: "Linux",
  intended_use: "I want to test our own staging estate before it ships.",
  experience: "Burp, semgrep",
  comments: "",
  terms: "1",
};

/** A signed-in applicant: the session row, its token, and the Cookie header. */
async function signIn(db, options = {}) {
  const userId = await makeUser(db, options);
  const token = await createSession(db, userId);
  const cookie = `${SESSION_COOKIE}=${token}`;
  const csrf = await csrfFor(token);
  return { userId, token, cookie, csrf };
}

/** An HTML form post, as a browser sends it — same-origin, CSRF included. */
function post(cookie, csrf, fields, { origin = SITE, url = `${SITE}/api/apply` } = {}) {
  const body = new URLSearchParams({ ...fields, csrf });
  return req(url, {
    method: "POST",
    cookie,
    body,
    headers: {
      "Sec-Fetch-Site": origin === SITE ? "same-origin" : "cross-site",
      Origin: origin,
    },
  });
}

const textOf = async (response) => await response.text();

// --- the form ---------------------------------------------------------------

test("the form is behind sign-in, and says where to come back to", async () => {
  const db = testD1();
  const response = await getApply({ request: req(`${SITE}/apply`), env: { KRYONSEC_DB: db } });

  assert.equal(response.status, 303);
  // Encoded, because `next` is read back through a query string. A raw `/apply`
  // here would work by accident and break the day a path needs escaping.
  assert.equal(response.headers.get("Location"), "/signin?next=%2Fapply");
});

test("the rendered form carries the session's own CSRF token", async () => {
  const db = testD1();
  const { cookie, token } = await signIn(db);
  const response = await getApply({ request: req(`${SITE}/apply`, { cookie }), env: { KRYONSEC_DB: db } });

  assert.equal(response.status, 200);
  const body = await textOf(response);

  // The token in the markup must be the derived one, or every submission on
  // the site fails the check that exists to make submissions fail.
  assert.match(body, new RegExp(`name="csrf" value="${await csrfFor(token)}"`));
  // The account's address, pre-filled but editable — the decision is emailed
  // here, and an applicant may want it somewhere else.
  assert.match(body, /value="a@example\.com"/);
});

test("an applicant who already applied gets the dashboard, not a second form", async () => {
  const db = testD1();
  const { cookie, csrf } = await signIn(db);
  await postApply({
    request: post(cookie, csrf, GOOD),
    env: { KRYONSEC_DB: db },
  });

  const response = await getApply({ request: req(`${SITE}/apply`, { cookie }), env: { KRYONSEC_DB: db } });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/dashboard");
});

// --- submission -------------------------------------------------------------

test("a complete application is filed, versioned, and acknowledged", async () => {
  const db = testD1();
  const { cookie, csrf, userId } = await signIn(db);
  const response = await postApply({ request: post(cookie, csrf, GOOD), env: { KRYONSEC_DB: db } });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/dashboard");

  const row = db._raw.prepare("SELECT * FROM applications WHERE user_id = ?").get(userId);
  assert.equal(row.status, "pending");
  assert.equal(row.full_name, "Ada Lovelace");
  assert.equal(row.intended_use, GOOD.intended_use);
  assert.equal(row.feedback_willing, 0);
  // Consent is only worth recording if it is recorded with the text it agreed
  // to. A bare boolean cannot answer "what did they accept".
  assert.equal(row.terms_version, TERMS_VERSION);
  assert.ok(row.terms_accepted_at, "the acknowledgement must be timestamped");

  // The opening history row, so the admin view has an origin as well as a
  // current state.
  const events = db._raw.prepare("SELECT * FROM application_events WHERE application_id = ?").all(row.id);
  assert.equal(events.length, 1);
  assert.equal(events[0].from_status, null);
  assert.equal(events[0].to_status, "pending");

  const queued = db._raw.prepare("SELECT * FROM email_outbox").all();
  assert.equal(queued.length, 1);
  assert.equal(queued[0].kind, "application.received");
  assert.equal(queued[0].status, "sent", "the drain should have sent the queued message");
});

test("a handle is normalised to the handle, however it was pasted", async () => {
  const db = testD1();
  const { cookie, csrf, userId } = await signIn(db);
  // People paste the profile URL at least as often as the name.
  await postApply({
    request: post(cookie, csrf, { ...GOOD, github_username: "https://github.com/ada/" }),
    env: { KRYONSEC_DB: db },
  });

  const row = db._raw.prepare("SELECT github_username FROM applications WHERE user_id = ?").get(userId);
  assert.equal(row.github_username, "ada");
});

test("a second submission is not an error and does not create a second row", async () => {
  const db = testD1();
  const { cookie, csrf, userId } = await signIn(db);

  const first = await postApply({ request: post(cookie, csrf, GOOD), env: { KRYONSEC_DB: db } });
  const second = await postApply({ request: post(cookie, csrf, GOOD), env: { KRYONSEC_DB: db } });

  // A double click, or two tabs. The database refuses the duplicate and the
  // handler treats that refusal as the answer rather than as a failure — so a
  // person who submitted twice sees the dashboard, not an error page.
  assert.equal(first.status, 303);
  assert.equal(second.status, 303);
  assert.equal(second.headers.get("Location"), "/dashboard");

  const count = db._raw.prepare("SELECT COUNT(*) AS n FROM applications WHERE user_id = ?").get(userId).n;
  assert.equal(count, 1);
});

// --- refusal ----------------------------------------------------------------

test("a missing acknowledgement is refused, and is not re-ticked for them", async () => {
  const db = testD1();
  const { cookie, csrf, userId } = await signIn(db);
  const { terms, ...withoutTerms } = GOOD;

  const response = await postApply({ request: post(cookie, csrf, withoutTerms), env: { KRYONSEC_DB: db } });

  assert.equal(response.status, 400);
  const body = await textOf(response);
  // The form comes back with their writing intact...
  assert.match(body, /Ada Lovelace/);
  // ...and the box comes back empty. Re-ticking it would make "I agree"
  // something the browser asserted rather than the applicant.
  assert.doesNotMatch(body, /name="terms"[^>]*checked/);
  assert.doesNotMatch(body, /name="feedback_willing"[^>]*checked/);

  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM applications").get().n, 0);
});

test("a javascript: website is refused rather than stored", async () => {
  const db = testD1();
  const { cookie, csrf } = await signIn(db);
  const response = await postApply({
    request: post(cookie, csrf, { ...GOOD, portfolio_url: "javascript:alert(document.cookie)" }),
    env: { KRYONSEC_DB: db },
  });

  // This value is rendered as a link on a page an admin reads. `new URL()`
  // parses it happily, so the check that matters is the scheme.
  assert.equal(response.status, 400);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM applications").get().n, 0);
});

test("a value outside the dropdown is stored as nothing, not as itself", async () => {
  const db = testD1();
  const { cookie, csrf, userId } = await signIn(db);
  await postApply({
    request: post(cookie, csrf, { ...GOOD, role: "<script>alert(1)</script>" }),
    env: { KRYONSEC_DB: db },
  });

  const row = db._raw.prepare("SELECT role FROM applications WHERE user_id = ?").get(userId);
  assert.equal(row.role, null);
});

test("a malformed address is refused before anything is written", async () => {
  const db = testD1();
  const { cookie, csrf } = await signIn(db);
  for (const contact_email of ["", "ada", "ada@", "ada@example", "a b@example.com"]) {
    const response = await postApply({
      request: post(cookie, csrf, { ...GOOD, contact_email }),
      env: { KRYONSEC_DB: db },
    });
    assert.equal(response.status, 400, `expected ${JSON.stringify(contact_email)} to be refused`);
  }
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM applications").get().n, 0);
});

test("a cross-site post is refused by the origin check, not just by SameSite", async () => {
  const db = testD1();
  const { cookie, csrf, userId } = await signIn(db);
  const response = await postApply({
    request: post(cookie, csrf, GOOD, { origin: "https://evil.example" }),
    env: { KRYONSEC_DB: db },
  });

  assert.equal(response.status, 400);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM applications WHERE user_id = ?").get(userId).n, 0);
});

test("a wrong CSRF token is refused even from our own origin", async () => {
  const db = testD1();
  const { cookie, userId } = await signIn(db);
  const response = await postApply({
    request: post(cookie, "0".repeat(64), GOOD),
    env: { KRYONSEC_DB: db },
  });

  assert.equal(response.status, 400);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM applications WHERE user_id = ?").get(userId).n, 0);
});

test("submitting while signed out redirects instead of writing", async () => {
  const db = testD1();
  const response = await postApply({
    request: post("", "", GOOD),
    env: { KRYONSEC_DB: db },
  });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/signin?next=%2Fapply");
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM applications").get().n, 0);
});

// --- sign-out ---------------------------------------------------------------

test("signing out deletes the session row and clears the cookie", async () => {
  const db = testD1();
  const { cookie, csrf, token } = await signIn(db);
  const body = new URLSearchParams({ csrf });

  const response = await postLogout({
    request: req(`${SITE}/logout`, {
      method: "POST",
      cookie,
      body,
      headers: { "Sec-Fetch-Site": "same-origin" },
    }),
    env: { KRYONSEC_DB: db },
  });

  assert.equal(response.status, 303);
  assert.match(response.headers.get("Set-Cookie"), /kr_session=;/);
  assert.match(response.headers.get("Set-Cookie"), /Max-Age=0/);

  // The row, not just the cookie. A session that only *looks* signed out is
  // still a usable token for anyone who kept a copy of it.
  const remaining = db._raw
    .prepare("SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?")
    .get(await sha256Hex(token)).n;
  assert.equal(remaining, 0);
});

test("a failed CSRF check signs nobody out", async () => {
  const db = testD1();
  const { cookie, token } = await signIn(db);
  const body = new URLSearchParams({ csrf: "0".repeat(64) });

  const response = await postLogout({
    request: req(`${SITE}/logout`, {
      method: "POST",
      cookie,
      body,
      headers: { "Sec-Fetch-Site": "same-origin" },
    }),
    env: { KRYONSEC_DB: db },
  });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/dashboard");
  const remaining = db._raw
    .prepare("SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?")
    .get(await sha256Hex(token)).n;
  assert.equal(remaining, 1, "a refused sign-out must leave the session alone");
});

test("signing out with a stale cookie still clears it", async () => {
  const db = testD1();
  const response = await postLogout({
    request: req(`${SITE}/logout`, {
      method: "POST",
      cookie: `${SESSION_COOKIE}=${"a".repeat(64)}`,
      body: new URLSearchParams({ csrf: "0".repeat(64) }),
      headers: { "Sec-Fetch-Site": "same-origin" },
    }),
    env: { KRYONSEC_DB: db },
  });

  // No row to delete, but the browser is still holding a cookie. Leaving it
  // there means "sign out" appears not to work on an already-stale session.
  assert.equal(response.status, 303);
  assert.match(response.headers.get("Set-Cookie"), /kr_session=;/);
});
