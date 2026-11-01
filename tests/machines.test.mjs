// node --test "tests/*.test.mjs"
//
// Turning a machine off, from either end: the dashboard (session + CSRF) and
// the command line (the token itself).
//
// These are two doors into one guarded UPDATE, and the properties that matter
// are that neither door opens onto somebody else's session, and that a
// revocation takes effect on the very next request rather than at the next
// daily check-in.

import test from "node:test";
import assert from "node:assert/strict";

import { createSession, csrfFor, SESSION_COOKIE } from "../functions/_auth.js";
import { createCliSession, listCliSessions } from "../functions/_cli.js";
import { onRequestPost as logout } from "../functions/api/beta/cli/logout.js";
import { onRequestPost as machines } from "../functions/api/beta/machines.js";
import { onRequestGet as dashboard } from "../functions/dashboard.js";
import { grantEntitlement } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const ENV = (db) => ({ KRYONSEC_DB: db });

/** A signed-in, entitled account with one machine already signed in. */
async function account(db, options = {}) {
  const userId = await makeUser(db, options);
  await grantEntitlement(db, { userId, actor: "admin" });
  const token = await createSession(db, userId);
  const machine = await createCliSession(db, { userId, label: "Linux/x86_64" });
  return { userId, token, machine, cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
}

/** The form post as the route receives it. */
const revokeRequest = (who, id, { csrf = null, origin = SITE } = {}) =>
  req(`${SITE}/api/beta/machines`, {
    method: "POST",
    cookie: who.cookie,
    body: new URLSearchParams({ id, intent: "revoke", csrf: csrf ?? who.csrf }),
    headers: { ...(origin === SITE ? { "Sec-Fetch-Site": "same-origin" } : { "Sec-Fetch-Site": "cross-site" }), Origin: origin },
  });

/** ...and what the route answers. */
const revoke = (db, who, id, options) =>
  machines({ request: revokeRequest(who, id, options), env: ENV(db) });

const cliLogout = (token) =>
  req(`${SITE}/api/beta/cli/logout`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

const liveSessions = (db) =>
  db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions WHERE revoked_at IS NULL").get().n;

// --- the dashboard door -----------------------------------------------------

test("the dashboard revokes one of its own machines", async () => {
  const db = testD1();
  const who = await account(db);
  const row = (await listCliSessions(db, who.userId))[0];

  const response = await revoke(db, who, row.id);
  assert.equal(response.status, 303);
  assert.equal(liveSessions(db), 0);

  // And the reason is recorded, so the table can say why rather than just that.
  const after = (await listCliSessions(db, who.userId))[0];
  assert.match(after.revoked_reason, /dashboard/);
});

test("a tampered session id revokes nothing", async () => {
  const db = testD1();
  const who = await account(db);
  const other = await account(db, { id: "u_2", email: "b@example.com" });
  const theirs = (await listCliSessions(db, other.userId))[0];

  // The id is a real id, belonging to somebody else. Scoping the UPDATE to the
  // session's own user is what makes this a no-op rather than a cut-off.
  await revoke(db, who, theirs.id);

  // Neither machine moved: the caller's own was not named, and the one that
  // was named is not theirs.
  assert.equal(liveSessions(db), 2, "nothing should have been revoked");
  assert.equal((await listCliSessions(db, other.userId))[0].revoked_at, null);
});

test("revoking without a session or without CSRF changes nothing", async () => {
  const db = testD1();
  const who = await account(db);
  const row = (await listCliSessions(db, who.userId))[0];

  const anon = await machines({
    request: req(`${SITE}/api/beta/machines`, {
      method: "POST",
      body: new URLSearchParams({ id: row.id, intent: "revoke", csrf: who.csrf }),
      headers: { "Sec-Fetch-Site": "same-origin", Origin: SITE },
    }),
    env: ENV(db),
  });
  assert.ok(anon instanceof Response);
  assert.equal(anon.status, 303);
  assert.match(anon.headers.get("Location"), /^\/signin/);

  const crossSite = await revoke(db, who, row.id, { origin: "https://evil.example" });
  assert.equal(crossSite.status, 403);

  const stale = await revoke(db, who, row.id, { csrf: "0".repeat(64) });
  assert.equal(stale.status, 403);

  assert.equal(liveSessions(db), 1);
});

test("an account whose access was revoked can still turn its own machine off", async () => {
  const db = testD1();
  const who = await account(db);
  const row = (await listCliSessions(db, who.userId))[0];
  db._raw.prepare("UPDATE entitlements SET status = 'revoked' WHERE user_id = ?").run(who.userId);

  // Revoking never grants anything, so it must not need an entitlement. Being
  // unable to cut off a machine you no longer control is the worse failure.
  await revoke(db, who, row.id);
  assert.equal(liveSessions(db), 0);
});

// --- the command-line door --------------------------------------------------

test("the CLI revokes exactly its own token and nothing else", async () => {
  const db = testD1();
  const who = await account(db);
  const other = await account(db, { id: "u_2", email: "b@example.com" });

  const response = await logout({ request: cliLogout(who.machine), env: ENV(db) });
  assert.deepEqual(await response.json(), { ok: true, revoked: true });

  // The other machine is untouched: the route takes no id, so there is no id
  // to aim at somebody else's session.
  assert.equal(liveSessions(db), 1);
  assert.equal((await listCliSessions(db, other.userId))[0].revoked_at, null);
});

test("an unknown, revoked, expired or malformed token revokes nothing, and says the same thing", async () => {
  const db = testD1();
  const who = await account(db);
  await logout({ request: cliLogout(who.machine), env: ENV(db) });

  const bodies = [];
  for (const token of [who.machine, "s_" + "0".repeat(64), "dl_" + "0".repeat(64), "", "nonsense"]) {
    const response = await logout({ request: cliLogout(token), env: ENV(db) });
    assert.equal(response.status, 200);
    bodies.push(JSON.stringify(await response.json()));
  }
  // Identical answers, so this endpoint cannot be asked whether a token was
  // ever real, and a second `kryonsec logout` is not an error.
  assert.equal(new Set(bodies).size, 1, bodies.join(" / "));
});

test("with no database bound, logout fails closed", async () => {
  const response = await logout({ request: cliLogout("s_" + "a".repeat(64)), env: {} });
  assert.equal(response.status, 503);
});

// --- a revocation takes effect now, not tomorrow ----------------------------

test("a revoked machine is refused at the license endpoint on its very next call", async () => {
  const { onRequestGet: verify } = await import("../functions/api/license/verify.js");
  const db = testD1();
  const who = await account(db);

  const check = async () =>
    (
      await verify({
        request: req(`${SITE}/api/license/verify?device=d1&os=Linux&arch=x86_64&version=1.3.7`, {
          headers: { Authorization: `Bearer ${who.machine}` },
        }),
        env: ENV(db),
      })
    ).json();

  assert.equal((await check()).valid, true);

  await logout({ request: cliLogout(who.machine), env: ENV(db) });

  const after = await check();
  assert.equal(after.valid, false);
  assert.match(after.reason, /not signed in/i);
});

// --- the dashboard card -----------------------------------------------------

test("the dashboard offers the login command and lists the machines", async () => {
  const db = testD1();
  const who = await account(db);

  const body = await (
    await dashboard({
      request: req(`${SITE}/dashboard`, { cookie: who.cookie }),
      env: ENV(db),
    })
  ).text();

  assert.match(body, /kryonsec login/);
  assert.match(body, /02 \/ THE COMMAND LINE/);
  assert.match(body, /1 SIGNED IN/);
  assert.match(body, /value="revoke"/);
  // The raw token is never on the page — only the display prefix.
  assert.doesNotMatch(body, new RegExp(who.machine));
  assert.match(body, new RegExp(who.machine.slice(0, 10)));
});

test("a signed-out machine is still listed, so it can be told from one that never was", async () => {
  const db = testD1();
  const who = await account(db);
  const row = (await listCliSessions(db, who.userId))[0];
  await revoke(db, who, row.id);

  const body = await (
    await dashboard({
      request: req(`${SITE}/dashboard`, { cookie: who.cookie }),
      env: ENV(db),
    })
  ).text();

  assert.match(body, /0 SIGNED IN/);
  assert.match(body, /signed out/);
  assert.doesNotMatch(body, /value="revoke"/);
});

test("a machine is never offered to an account that cannot use one", async () => {
  const db = testD1();
  const userId = await makeUser(db);
  const token = await createSession(db, userId);

  const body = await (
    await dashboard({
      request: req(`${SITE}/dashboard`, { cookie: `${SESSION_COOKIE}=${token}` }),
      env: ENV(db),
    })
  ).text();

  assert.doesNotMatch(body, /THE COMMAND LINE/);
});
