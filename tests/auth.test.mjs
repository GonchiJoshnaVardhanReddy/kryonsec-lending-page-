// node --test "tests/*.test.mjs"
//
// Sessions and CSRF. These run against the real schema through tests/helpers/d1.mjs,
// so a query that names a column the migration does not create fails here.

import test from "node:test";
import assert from "node:assert/strict";

import {
  checkCsrf,
  clearSessionCookie,
  createSession,
  csrfFor,
  currentSession,
  destroySession,
  isAdminUser,
  isSameOrigin,
  parseCookies,
  sessionCookie,
  sha256Hex,
  timingSafeEqual,
} from "../functions/_auth.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const LOCAL = "http://localhost:8788";

test("sha256Hex matches the published vector for 'abc'", async () => {
  // A hash helper that is subtly wrong still produces plausible-looking hex,
  // and every hash in the database would be wrong together — so pin one.
  assert.equal(
    await sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("cookies are HttpOnly, Lax, and Secure only where Secure works", () => {
  const secure = sessionCookie("deadbeef", SITE);
  assert.match(secure, /HttpOnly/);
  assert.match(secure, /SameSite=Lax/);
  assert.match(secure, /Secure/);
  assert.match(secure, /Path=\//);

  // On plain-http localhost a Secure cookie is dropped by the browser and the
  // session silently never sticks, which reads as "login is broken".
  const local = sessionCookie("deadbeef", LOCAL);
  assert.doesNotMatch(local, /Secure/);
  assert.match(local, /HttpOnly/);
});

test("clearing a session cookie expires it and keeps the flags", () => {
  const cleared = clearSessionCookie(SITE);
  assert.match(cleared, /kr_session=;/);
  assert.match(cleared, /Max-Age=0/);
  assert.match(cleared, /HttpOnly/);
});

test("parseCookies survives odd input", () => {
  assert.deepEqual(parseCookies(req(SITE, { cookie: "a=1; b=2" })), { a: "1", b: "2" });
  assert.deepEqual(parseCookies(req(SITE)), {});
  assert.deepEqual(parseCookies(req(SITE, { cookie: "junk" })), {});
  assert.deepEqual(parseCookies(req(SITE, { cookie: "=5" })), {});
  // A value containing '=' keeps everything after the first one.
  assert.deepEqual(parseCookies(req(SITE, { cookie: "t=a=b" })), { t: "a=b" });
});

test("a session round-trips, and the raw token is not in the database", async () => {
  const db = testD1();
  await makeUser(db);

  const token = await createSession(db, "u_1");
  assert.match(token, /^[0-9a-f]{64}$/);

  const found = await currentSession(db, req(SITE, { cookie: `kr_session=${token}` }));
  assert.equal(found.user.user_id, "u_1");
  assert.equal(found.user.email, "a@example.com");

  // The whole reason the column is a hash: a dump of `sessions` must not hand
  // anyone a working cookie.
  const row = db._raw.prepare("SELECT token_hash FROM sessions").get();
  assert.notEqual(row.token_hash, token);
  assert.equal(row.token_hash, await sha256Hex(token));
});

test("an expired session is refused and swept", async () => {
  const db = testD1();
  await makeUser(db);
  const token = await createSession(db, "u_1");

  db._raw
    .prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
    .run("2020-01-01T00:00:00.000Z", await sha256Hex(token));

  const found = await currentSession(db, req(SITE, { cookie: `kr_session=${token}` }));
  assert.equal(found, null);

  const left = db._raw.prepare("SELECT COUNT(*) AS n FROM sessions").get();
  assert.equal(left.n, 0, "the dead row was left behind");
});

test("a forged or malformed cookie resolves to nobody", async () => {
  const db = testD1();
  await makeUser(db);

  const cases = [
    undefined, // no cookie at all
    "kr_session=nothex",
    `kr_session=${"f".repeat(64)}`, // well-formed, never issued
    "kr_session=",
  ];
  for (const cookie of cases) {
    const found = await currentSession(db, req(SITE, cookie ? { cookie } : {}));
    assert.equal(found, null, `cookie ${cookie} resolved to a session`);
  }
});

test("two sessions for one user are independent, and sign-out is per device", async () => {
  const db = testD1();
  await makeUser(db);

  const laptop = await createSession(db, "u_1");
  const phone = await createSession(db, "u_1");
  assert.notEqual(laptop, phone);

  await destroySession(db, req(SITE, { cookie: `kr_session=${laptop}` }));

  assert.equal(await currentSession(db, req(SITE, { cookie: `kr_session=${laptop}` })), null);
  assert.ok(await currentSession(db, req(SITE, { cookie: `kr_session=${phone}` })));
});

test("the csrf value is derived from the session and does not leak it", async () => {
  const token = "a".repeat(64);
  const csrf = await csrfFor(token);
  assert.match(csrf, /^[0-9a-f]{64}$/);
  assert.notEqual(csrf, token);
  // Deterministic — that is what lets it be checked without storing it.
  assert.equal(csrf, await csrfFor(token));
  assert.notEqual(csrf, await csrfFor("b".repeat(64)));
});

test("a same-origin post with the right csrf token passes", async () => {
  const db = testD1();
  await makeUser(db);
  const token = await createSession(db, "u_1");
  const session = await currentSession(db, req(SITE, { cookie: `kr_session=${token}` }));

  const form = new FormData();
  form.set("csrf", await csrfFor(token));

  const request = req(SITE, {
    method: "POST",
    headers: { "Sec-Fetch-Site": "same-origin" },
  });
  assert.equal(await checkCsrf(request, session, form), "");
});

test("a cross-site post is refused even with a valid csrf token", async () => {
  // Defence in depth, and the order matters: the origin check runs first, so
  // a leaked CSRF value from another site's context still does not work.
  const db = testD1();
  await makeUser(db);
  const token = await createSession(db, "u_1");
  const session = await currentSession(db, req(SITE, { cookie: `kr_session=${token}` }));

  const form = new FormData();
  form.set("csrf", await csrfFor(token));

  const crossSite = req(SITE, {
    method: "POST",
    headers: { "Sec-Fetch-Site": "cross-site" },
  });
  assert.notEqual(await checkCsrf(crossSite, session, form), "");
});

test("a wrong or missing csrf token is refused", async () => {
  const db = testD1();
  await makeUser(db);
  const token = await createSession(db, "u_1");
  const session = await currentSession(db, req(SITE, { cookie: `kr_session=${token}` }));

  const request = req(SITE, { method: "POST", headers: { "Sec-Fetch-Site": "same-origin" } });

  for (const value of [null, "", "x", "a".repeat(64)]) {
    const form = new FormData();
    if (value !== null) form.set("csrf", value);
    assert.notEqual(await checkCsrf(request, session, form), "", `csrf ${value} was accepted`);
  }
});

test("an absent origin header is not treated as same-origin", async () => {
  // A hand-rolled curl proves nothing about origin. Reading "no header" as
  // "fine" is how a CSRF gets in through the one client that always omits it.
  assert.equal(isSameOrigin(req(SITE, { method: "POST" })), false);

  assert.equal(
    isSameOrigin(req(SITE, { method: "POST", headers: { Origin: SITE } })),
    true,
  );
  assert.equal(
    isSameOrigin(req(SITE, { method: "POST", headers: { Origin: "https://evil.example" } })),
    false,
  );
  // Sec-Fetch-Site wins when present, and a page cannot forge it.
  assert.equal(
    isSameOrigin(req(SITE, {
      method: "POST",
      headers: { "Sec-Fetch-Site": "cross-site", Origin: SITE },
    })),
    false,
  );
});

test("admin is a table lookup, not a field on the request", async () => {
  const db = testD1();
  await makeUser(db, { id: "u_1", email: "plain@example.com" });
  await makeUser(db, { id: "u_2", email: "boss@example.com", admin: true });

  assert.equal(await isAdminUser(db, "u_2"), true);
  assert.equal(await isAdminUser(db, "u_1"), false);
  assert.equal(await isAdminUser(db, null), false);
  assert.equal(await isAdminUser(db, "u_nope"), false);
});

test("timingSafeEqual compares the whole string", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abd"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
  assert.equal(timingSafeEqual("", ""), true);
  assert.equal(timingSafeEqual(null, ""), true);
});
