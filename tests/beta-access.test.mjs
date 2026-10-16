// node --test "tests/*.test.mjs"
//
// The download gate and the dashboard. These are the two places an entitlement
// is turned into something a person can act on, so what they exercise is the
// ordering: credential, then access, then bytes.
//
// GitHub is stubbed at `globalThis.fetch` because that is the seam to the
// outside world. Everything on our side of it — the token tables, the access
// decision, the SQL — is real. `stubProvider(t, [])` asserts that nothing was
// fetched at all, which is how the "refused before the fetch" tests prove what
// they claim rather than merely observing a 403.

import test from "node:test";
import assert from "node:assert/strict";

import { SESSION_COOKIE, createSession, sha256Hex } from "../functions/_auth.js";
import { createCliSession, mintDownloadToken, revokeCliSession } from "../functions/_cli.js";
import { onRequestGet as download } from "../functions/api/beta/download.js";
import { onRequestGet as dashboard } from "../functions/dashboard.js";
import { grantEntitlement, revokeEntitlement, submitApplication } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";

const RELEASE = {
  assets: [{ name: "kryonsec-9.9.9-py3-none-any.whl", url: "https://api.github.com/assets/1" }],
};

/** Route requests to the stubbed GitHub by substring. Anything unmatched throws,
 *  so an unexpected call is a failure rather than a silent pass. */
const stubGithub = (t, routes = [["/releases/latest", () => jsonOk(RELEASE)], ["/assets/", () => wheelResponse()]]) =>
  t.mock.method(globalThis, "fetch", async (url) => {
    const target = String(url);
    for (const [needle, reply] of routes) {
      if (target.includes(needle)) return reply(target);
    }
    throw new Error(`the test hit an unexpected URL: ${target}`);
  });

const jsonOk = (body) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

const wheelResponse = () =>
  new Response(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), {
    status: 200,
    headers: { "Content-Type": "application/octet-stream" },
  });

const ENV = (db) => ({ KRYONSEC_DB: db, KRYONSEC_GITHUB_TOKEN: "gh-pat" });

/** A user who is signed in and holds an active entitlement. */
async function entitled(db, options = {}) {
  const userId = await makeUser(db, options);
  const sessionToken = await createSession(db, userId);
  await grantEntitlement(db, { userId, actor: "admin" });
  return { userId, sessionToken, cookie: `${SESSION_COOKIE}=${sessionToken}` };
}

const get = (url, headers = {}) => req(url, { headers });

// --- who may download -------------------------------------------------------

test("no credential at all is refused without touching GitHub", async (t) => {
  const db = testD1();
  stubGithub(t, []); // nothing should be fetched

  const response = await download({ request: get(`${SITE}/api/beta/download`), env: ENV(db) });
  assert.equal(response.status, 401);
  assert.match(await response.text(), /kryonsec login/);
});

test("a session cookie with an active entitlement downloads the wheel", async (t) => {
  const db = testD1();
  const { cookie } = await entitled(db);
  stubGithub(t);

  const response = await download({ request: get(`${SITE}/api/beta/download`, { Cookie: cookie }), env: ENV(db) });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Content-Type"), "application/octet-stream");
  // The filename has to survive to the client: pip derives the wheel name from
  // it, and a wheel pip cannot name is a wheel pip will not install.
  assert.match(response.headers.get("Content-Disposition"), /kryonsec-9\.9\.9-py3-none-any\.whl/);
  assert.match(response.headers.get("Cache-Control"), /no-store/);
  assert.ok((await response.arrayBuffer()).byteLength > 0);
});

test("a revoked account is refused before GitHub is called", async (t) => {
  const db = testD1();
  const { userId, cookie } = await entitled(db);
  await revokeEntitlement(db, { userId, actor: "admin", reason: "shared the build" });
  stubGithub(t, []); // the gate must decide without fetching

  const response = await download({ request: get(`${SITE}/api/beta/download`, { Cookie: cookie }), env: ENV(db) });
  assert.equal(response.status, 403);
  // The reason is true and specific — it tells the person what happened without
  // telling anyone probing anything.
  assert.match(await response.text(), /revoked/i);
});

test("ending the programme stops a still-active entitlement from downloading", async (t) => {
  const db = testD1();
  const { cookie } = await entitled(db);
  db._raw.prepare("UPDATE beta_program SET status = 'ended' WHERE id = 1").run();
  stubGithub(t, []);

  const response = await download({ request: get(`${SITE}/api/beta/download`, { Cookie: cookie }), env: ENV(db) });
  assert.equal(response.status, 403);
  assert.match(await response.text(), /programme has ended/i);
});

test("a browser gets a page it can read, a script gets a line", async (t) => {
  const db = testD1();
  stubGithub(t, []);

  const forScript = await download({
    request: get(`${SITE}/api/beta/download`, { Accept: "*/*" }),
    env: ENV(db),
  });
  assert.match(forScript.headers.get("Content-Type"), /text\/plain/);

  const forBrowser = await download({
    request: get(`${SITE}/api/beta/download`, { Accept: "text/html,application/xhtml+xml" }),
    env: ENV(db),
  });
  assert.match(forBrowser.headers.get("Content-Type"), /text\/html/);
  assert.match(await forBrowser.text(), /BACK TO THE DASHBOARD/);
});

test("a wrong CLI token is refused, not treated as anonymous", async (t) => {
  const db = testD1();
  await entitled(db);
  stubGithub(t, []);

  const response = await download({
    request: get(`${SITE}/api/beta/download`, { Authorization: `Bearer s_${"a".repeat(64)}` }),
    env: ENV(db),
  });
  assert.equal(response.status, 401);
});

// --- the CLI's own credential -----------------------------------------------

test("a CLI session token downloads, and re-presents as the same person", async (t) => {
  const db = testD1();
  const { userId } = await entitled(db);
  const cliToken = await createCliSession(db, { userId, label: "linux/x86_64" });
  stubGithub(t);

  const response = await download({
    request: get(`${SITE}/api/beta/download`, { Authorization: `Bearer ${cliToken}` }),
    env: ENV(db),
  });
  assert.equal(response.status, 200);

  // `last_used_at` is stamped, which is what the dashboard's machine list shows.
  const row = db._raw.prepare("SELECT last_used_at FROM cli_sessions WHERE user_id = ?").get(userId);
  assert.ok(row.last_used_at, "a used CLI session should record that it was used");
});

test("revoking one machine does not touch the other", async (t) => {
  const db = testD1();
  const { userId } = await entitled(db);
  const laptop = await createCliSession(db, { userId, label: "laptop" });
  const desktop = await createCliSession(db, { userId, label: "desktop" });
  stubGithub(t);

  const laptopRow = db._raw.prepare("SELECT id FROM cli_sessions WHERE label = 'laptop'").get();
  assert.equal(await revokeCliSession(db, { id: laptopRow.id, actor: "self" }), true);
  // A second revoke reports honestly rather than rewriting the reason.
  assert.equal(await revokeCliSession(db, { id: laptopRow.id, actor: "self" }), false);

  const refused = await download({
    request: get(`${SITE}/api/beta/download`, { Authorization: `Bearer ${laptop}` }),
    env: ENV(db),
  });
  assert.equal(refused.status, 401);

  const allowed = await download({
    request: get(`${SITE}/api/beta/download`, { Authorization: `Bearer ${desktop}` }),
    env: ENV(db),
  });
  assert.equal(allowed.status, 200);
});

test("a CLI session past its expiry is refused", async (t) => {
  const db = testD1();
  const { userId } = await entitled(db);
  const cliToken = await createCliSession(db, { userId });
  db._raw
    .prepare("UPDATE cli_sessions SET expires_at = ? WHERE token_hash = ?")
    .run("2020-01-01T00:00:00.000Z", await sha256Hex(cliToken));
  stubGithub(t, []);

  const response = await download({
    request: get(`${SITE}/api/beta/download`, { Authorization: `Bearer ${cliToken}` }),
    env: ENV(db),
  });
  assert.equal(response.status, 401);
});

// --- the single-use download token ------------------------------------------

test("a download token works exactly once", async (t) => {
  const db = testD1();
  const { userId } = await entitled(db);
  const token = await mintDownloadToken(db, userId);
  const github = stubGithub(t);

  const first = await download({ request: get(`${SITE}/api/beta/download?t=${token}`), env: ENV(db) });
  assert.equal(first.status, 200);
  await first.arrayBuffer();
  const callsAfterSuccess = github.mock.callCount();

  const second = await download({ request: get(`${SITE}/api/beta/download?t=${token}`), env: ENV(db) });
  assert.equal(second.status, 401);
  // Refused without a second round trip to GitHub. A replayed token that still
  // fetches the bytes and then discards them is a replay the CDN can see.
  assert.equal(github.mock.callCount(), callsAfterSuccess);
});

test("an expired download token is refused", async (t) => {
  const db = testD1();
  const { userId } = await entitled(db);
  const token = await mintDownloadToken(db, userId);
  db._raw
    .prepare("UPDATE download_tokens SET expires_at = ? WHERE token_hash = ?")
    .run("2020-01-01T00:00:00.000Z", await sha256Hex(token));
  stubGithub(t, []);

  const response = await download({ request: get(`${SITE}/api/beta/download?t=${token}`), env: ENV(db) });
  assert.equal(response.status, 401);
});

test("a token minted before a revocation does not survive it", async (t) => {
  const db = testD1();
  const { userId } = await entitled(db);
  const token = await mintDownloadToken(db, userId);
  await revokeEntitlement(db, { userId, actor: "admin", reason: "no longer eligible" });
  stubGithub(t, []);

  // The credential answers "who", never "whether". A token that carried the
  // entitlement with it would keep working after the revocation that was
  // supposed to end it, which is the failure the brief names explicitly.
  const response = await download({ request: get(`${SITE}/api/beta/download?t=${token}`), env: ENV(db) });
  assert.equal(response.status, 403);

  // And the token is spent anyway, because it is spent on presentation rather
  // than on success. That is the stricter of the two available orderings: a
  // token that survives a refused attempt survives for its whole window, and
  // the window is the only thing making it safe.
  assert.ok(
    db._raw.prepare("SELECT used_at FROM download_tokens WHERE token_hash = ?").get(await sha256Hex(token)).used_at,
    "presenting a token spends it, whatever the gate then decides",
  );
});

test("a token minted for one account cannot be used after another signs in", async (t) => {
  const db = testD1();
  const alice = await entitled(db, { id: "u_alice", email: "alice@example.com" });
  const bob = await entitled(db, { id: "u_bob", email: "bob@example.com" });
  const aliceToken = await mintDownloadToken(db, alice.userId);
  stubGithub(t);

  // Alice's token names Alice, so revoking Alice kills it — and bob's own
  // session is untouched, which is what makes the token a reference to a
  // person rather than a bearer pass.
  await revokeEntitlement(db, { userId: alice.userId, actor: "admin" });
  const spent = await download({ request: get(`${SITE}/api/beta/download?t=${aliceToken}`), env: ENV(db) });
  assert.equal(spent.status, 403);

  const bobStillFine = await download({
    request: get(`${SITE}/api/beta/download`, { Cookie: bob.cookie }),
    env: ENV(db),
  });
  assert.equal(bobStillFine.status, 200);
});

// --- the dashboard ----------------------------------------------------------

test("the dashboard is behind sign-in and remembers where to come back to", async () => {
  const db = testD1();
  const response = await dashboard({ request: get(`${SITE}/dashboard`), env: ENV(db) });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/signin?next=%2Fdashboard");
});

test("an entitled account is given a working install command", async (t) => {
  const db = testD1();
  const { userId, cookie } = await entitled(db);
  stubGithub(t);

  const response = await dashboard({ request: get(`${SITE}/dashboard`, { Cookie: cookie }), env: ENV(db) });
  assert.equal(response.status, 200);
  const body = await response.text();

  assert.match(body, /KRYONSEC_DOWNLOAD_URL=/);
  assert.match(body, /\/install\.sh/);

  // The token rendered into the page has to be one the gate will accept —
  // a dashboard that prints a plausible-looking dead link is worse than one
  // that prints nothing.
  const token = /t=(dl_[0-9a-f]{64})/.exec(body)?.[1];
  assert.ok(token, "the install command should carry a download token");
  assert.equal(db._raw.prepare("SELECT user_id FROM download_tokens WHERE token_hash = ?").get(await sha256Hex(token)).user_id, userId);
});

test("a pending applicant is told they are in review, and gets no install command", async () => {
  const db = testD1();
  const userId = await makeUser(db);
  const cookie = `${SESSION_COOKIE}=${await createSession(db, userId)}`;
  await submitApplication(db, userId, { full_name: "Ada", contact_email: "ada@example.com", intended_use: "testing" });

  const response = await dashboard({ request: get(`${SITE}/dashboard`, { Cookie: cookie }), env: ENV(db) });
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /IN REVIEW/);
  // The negative that matters: no credential is minted and nothing about
  // downloading appears on the page of someone who is not entitled.
  assert.doesNotMatch(body, /KRYONSEC_DOWNLOAD_URL=/);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM download_tokens").get().n, 0);
});

test("a revoked account is told so, and is given nothing to download", async () => {
  const db = testD1();
  const { userId, cookie } = await entitled(db);
  await revokeEntitlement(db, { userId, actor: "admin", reason: "sharing the wheel" });

  const response = await dashboard({ request: get(`${SITE}/dashboard`, { Cookie: cookie }), env: ENV(db) });
  const body = await response.text();

  assert.match(body, /REVOKED/);
  assert.match(body, /sharing the wheel/);
  assert.doesNotMatch(body, /KRYONSEC_DOWNLOAD_URL=/);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM download_tokens").get().n, 0);
});

test("an account that never applied is offered the form", async () => {
  const db = testD1();
  const userId = await makeUser(db);
  const cookie = `${SESSION_COOKIE}=${await createSession(db, userId)}`;

  const body = await (await dashboard({ request: get(`${SITE}/dashboard`, { Cookie: cookie }), env: ENV(db) })).text();
  assert.match(body, /NOT APPLIED/);
  assert.match(body, /href="\/apply"/);
});

test("a rejected applicant is invited to apply again", async () => {
  const db = testD1();
  const userId = await makeUser(db);
  const cookie = `${SESSION_COOKIE}=${await createSession(db, userId)}`;
  const filed = await submitApplication(db, userId, {
    full_name: "Ada",
    contact_email: "ada@example.com",
    intended_use: "testing",
  });
  // Rejection is the one decision a person can come back from, which is why
  // the active-application index leaves it out.
  db._raw.prepare("UPDATE applications SET status = 'rejected' WHERE id = ?").run(filed.id);

  const body = await (await dashboard({ request: get(`${SITE}/dashboard`, { Cookie: cookie }), env: ENV(db) })).text();
  assert.match(body, /NOT ACCEPTED/);
  assert.match(body, /href="\/apply"/);
});

test("the programme ending is said plainly on the dashboard too", async () => {
  const db = testD1();
  const { cookie } = await entitled(db);
  db._raw.prepare("UPDATE beta_program SET status = 'ended' WHERE id = 1").run();

  const body = await (await dashboard({ request: get(`${SITE}/dashboard`, { Cookie: cookie }), env: ENV(db) })).text();
  assert.match(body, /BETA HAS/);
  assert.doesNotMatch(body, /KRYONSEC_DOWNLOAD_URL=/);
});
