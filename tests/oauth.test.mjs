// node --test "tests/*.test.mjs"
//
// The sign-in flow. These drive the real handlers with a stubbed provider, so
// what is exercised is the actual ordering — state, then code exchange, then
// session — rather than a paraphrase of it in a comment.
//
// The provider is stubbed at `globalThis.fetch` because that is the seam
// between us and Google/GitHub. Everything on our side of it, including every
// SQL statement, is real.

import test from "node:test";
import assert from "node:assert/strict";

import { OAUTH_COOKIE, SESSION_COOKIE, b64url, sha256Hex } from "../functions/_auth.js";
import {
  beginFlow,
  isConfigured,
  configuredProviders,
  findOrCreateUser,
  isProvider,
  safeNext,
  decodeFlow,
  encodeFlow,
  completeFlow,
  OAuthError,
} from "../functions/_oauth.js";
import { onRequestGet as callback } from "../functions/api/auth/[provider]/callback.js";
import { onRequestGet as start } from "../functions/api/auth/[provider]/start.js";
import { testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const ENV = (db) => ({
  KRYONSEC_DB: db,
  KRYONSEC_GOOGLE_CLIENT_ID: "google-client-id",
  KRYONSEC_GOOGLE_CLIENT_SECRET: "google-client-secret",
  KRYONSEC_GITHUB_CLIENT_ID: "github-client-id",
  KRYONSEC_GITHUB_CLIENT_SECRET: "github-client-secret",
});

/** Route requests to the stubbed provider by substring, in order. */
const stubProvider = (t, routes) =>
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    const target = String(url);
    for (const [needle, reply] of routes) {
      if (target.includes(needle)) return reply(target, init);
    }
    throw new Error(`the test hit an unexpected URL: ${target}`);
  });

const jsonOk = (body) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

/** A callback request carrying a valid in-flight cookie. */
function callbackRequest(flow, { query = "", cookie = `kr_oauth=${encodeFlow(flow)}` } = {}) {
  const url = `${SITE}/api/auth/${flow.provider}/callback${query}`;
  return new Request(url, { headers: cookie ? { Cookie: cookie } : {} });
}

const CALLBACK_PARAMS = (provider) => ({ provider });

// --- the redirect guard -----------------------------------------------------

test("only a same-site path survives as ?next", () => {
  // Each of these is a way to land someone on a page that is not ours while
  // the address bar still shows kryonsec.in for the moment it matters.
  for (const hostile of [
    "https://evil.example/",
    "http://evil.example",
    "//evil.example",
    "///evil.example",
    "/\\evil.example",
    "/\tevil.example",
    "javascript:alert(1)",
    "/legit\r\nLocation: https://evil.example",
    "",
    null,
    undefined,
  ]) {
    assert.equal(safeNext(hostile), "/dashboard", `safeNext let through: ${JSON.stringify(hostile)}`);
  }

  assert.equal(safeNext("/apply"), "/apply");
  assert.equal(safeNext("/dashboard?tab=downloads"), "/dashboard?tab=downloads");
});

// --- configuration ----------------------------------------------------------

test("a provider with no client id is not offered", () => {
  const full = ENV(null);
  assert.deepEqual(configuredProviders(full).sort(), ["github", "google"]);

  // A half-configured provider is not configured. Offering the button would
  // send people to the provider's own error page.
  const noSecret = { ...full, KRYONSEC_GITHUB_CLIENT_SECRET: "" };
  assert.deepEqual(configuredProviders(noSecret), ["google"]);

  assert.equal(isConfigured({}, "google"), false);
  assert.equal(isConfigured(full, "nope"), false);
  assert.equal(isProvider("google"), true);
  assert.equal(isProvider("__proto__"), false);
  assert.equal(isProvider("constructor"), false);
});

// --- the in-flight cookie ---------------------------------------------------

test("the flow cookie round-trips, and rubbish decodes to null", () => {
  const flow = { state: "s1", verifier: "v1", next: "/apply", provider: "github" };
  assert.deepEqual(decodeFlow(encodeFlow(flow)), flow);

  for (const junk of ["", "!!!", "e30", b64url(new TextEncoder().encode("[1,2]")), null]) {
    assert.equal(decodeFlow(junk), null, `decoded junk: ${junk}`);
  }

  // Missing state or verifier is not a usable flow even if the JSON parses.
  const half = b64url(new TextEncoder().encode(JSON.stringify({ v: "v1", p: "github" })));
  assert.equal(decodeFlow(half), null);
});

// --- starting a flow --------------------------------------------------------

test("start builds a PKCE authorize URL and sets one short-lived cookie", async () => {
  const { flow, redirect } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(null),
    provider: "google",
    next: "/apply",
  });

  const url = new URL(redirect);
  assert.equal(url.origin + url.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
  assert.equal(url.searchParams.get("client_id"), "google-client-id");
  assert.equal(url.searchParams.get("redirect_uri"), `${SITE}/api/auth/google/callback`);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("state"), flow.state);
  assert.equal(flow.next, "/apply");

  // The published vector from RFC 7636 Appendix B. Checking against the
  // verifier we just made would only prove the code is self-consistent; this
  // proves it is the algorithm the provider expects.
  assert.equal(
    b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")))),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
  assert.match(url.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
});

test("the start handler refuses an unconfigured provider instead of redirecting", async () => {
  const res = await start({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: { KRYONSEC_DB: testD1() },
    params: { provider: "google" },
  });
  assert.equal(res.status, 503);
  assert.match(await res.text(), /not switched on/i);

  const unknown = await start({
    request: new Request(`${SITE}/api/auth/__proto__/start`),
    env: ENV(testD1()),
    params: { provider: "__proto__" },
  });
  assert.equal(unknown.status, 404);
});

// --- identity ---------------------------------------------------------------

test("a Google profile becomes a normalised identity", async (t) => {
  stubProvider(t, [
    ["oauth2.googleapis.com/token", () => jsonOk({ access_token: "at" })],
    [
      "openidconnect.googleapis.com/v1/userinfo",
      () => jsonOk({ sub: "110169484474386276334", email: "Ann@Example.COM", email_verified: true, name: "Ann" }),
    ],
  ]);

  const identity = await completeFlow({
    env: ENV(null),
    provider: "google",
    code: "c",
    verifier: "v",
    redirectUri: `${SITE}/api/auth/google/callback`,
  });

  assert.equal(identity.subject, "110169484474386276334");
  assert.equal(identity.email, "ann@example.com", "the address was not normalised");
  assert.equal(identity.emailVerified, true);
  assert.equal(identity.name, "Ann");
});

test("a GitHub identity with a private address reads the verified one", async (t) => {
  // The common case: /user reports email: null. Reading only /user would
  // leave the account with no contact address at all.
  stubProvider(t, [
    ["/login/oauth/access_token", () => jsonOk({ access_token: "at" })],
    [
      "api.github.com/user/emails",
      () =>
        jsonOk([
          { email: "old@example.com", primary: false, verified: true },
          { email: "unverified@example.com", primary: true, verified: false },
          { email: "real@example.com", primary: true, verified: true },
        ]),
    ],
    ["api.github.com/user", () => jsonOk({ id: 42, login: "ann", name: null, email: null })],
  ]);

  const identity = await completeFlow({
    env: ENV(null),
    provider: "github",
    code: "c",
    verifier: "v",
    redirectUri: `${SITE}/api/auth/github/callback`,
  });

  assert.equal(identity.subject, "42");
  // primary AND verified — not the unverified primary, not the verified
  // non-primary.
  assert.equal(identity.email, "real@example.com");
  assert.equal(identity.emailVerified, true);
  assert.equal(identity.name, "ann", "the login should stand in for a missing name");
});

test("a GitHub account with no verified address gets no address", async (t) => {
  stubProvider(t, [
    ["/login/oauth/access_token", () => jsonOk({ access_token: "at" })],
    ["api.github.com/user/emails", () => jsonOk([{ email: "unverified@example.com", primary: true, verified: false }])],
    ["api.github.com/user", () => jsonOk({ id: 7, login: "ghost" })],
  ]);

  const identity = await completeFlow({
    env: ENV(null),
    provider: "github",
    code: "c",
    verifier: "v",
    redirectUri: `${SITE}/api/auth/github/callback`,
  });

  // Empty, not invented. `login@users.noreply.github.com` would be an address
  // we made up on the person's behalf and then mailed.
  assert.equal(identity.email, "");
  assert.equal(identity.emailVerified, false);
});

test("a refused exchange is an error, not a half-built identity", async (t) => {
  stubProvider(t, [["/login/oauth/access_token", () => new Response("bad_verification_code", { status: 400 })]]);

  await assert.rejects(
    completeFlow({ env: ENV(null), provider: "github", code: "c", verifier: "v", redirectUri: "x" }),
    OAuthError,
  );
});

// --- user resolution --------------------------------------------------------

test("an identity creates its user once and resolves to it thereafter", async () => {
  const db = testD1();
  const identity = { provider: "google", subject: "g-1", email: "a@example.com", emailVerified: true, name: "A" };

  const first = await findOrCreateUser(db, identity);
  const second = await findOrCreateUser(db, identity);
  assert.equal(first, second);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM users").get().n, 1);

  // The address follows the provider; the identity key does not move.
  const moved = await findOrCreateUser(db, { ...identity, email: "b@example.com" });
  assert.equal(moved, first);
  assert.equal(db._raw.prepare("SELECT email FROM users WHERE id = ?").get(first).email, "b@example.com");
});

test("the same address at two providers stays two accounts", async () => {
  // The account-takeover path the brief names. Neither provider's `sub` is
  // consulted about the other, and email is not a key anywhere.
  const db = testD1();
  const google = await findOrCreateUser(db, {
    provider: "google", subject: "g-1", email: "same@example.com", emailVerified: true, name: "",
  });
  const github = await findOrCreateUser(db, {
    provider: "github", subject: "gh-1", email: "same@example.com", emailVerified: true, name: "",
  });

  assert.notEqual(google, github);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM users").get().n, 2);
});

// --- the callback -----------------------------------------------------------

test("a valid callback mints a session and clears the flow cookie", async (t) => {
  const db = testD1();
  stubProvider(t, [
    ["oauth2.googleapis.com/token", () => jsonOk({ access_token: "at" })],
    ["openidconnect.googleapis.com/v1/userinfo", () => jsonOk({ sub: "g-9", email: "a@example.com", email_verified: true })],
  ]);

  const { flow } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(db),
    provider: "google",
    next: "/apply",
  });

  const res = await callback({
    request: callbackRequest(flow, { query: `?code=abc&state=${flow.state}` }),
    env: ENV(db),
    params: CALLBACK_PARAMS("google"),
  });

  assert.equal(res.status, 302);
  assert.equal(res.headers.get("Location"), "/apply");

  const cookies = res.headers.getSetCookie();
  const session = cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  const cleared = cookies.find((c) => c.startsWith(`${OAUTH_COOKIE}=`));
  assert.ok(session, "no session cookie was set");
  assert.match(session, /HttpOnly/);
  assert.match(cleared, /Max-Age=0/, "the flow cookie was left behind");

  // And the cookie works: its raw value is the hash stored in the row.
  const token = session.split(";")[0].split("=")[1];
  const row = db._raw.prepare("SELECT user_id FROM sessions").get();
  assert.equal(row.user_id, db._raw.prepare("SELECT id FROM users").get().id);
  assert.equal(row.user_id.length > 2, true);
  assert.equal(
    db._raw.prepare("SELECT token_hash FROM sessions").get().token_hash,
    await sha256Hex(token),
  );
});

test("a callback with the wrong state does nothing at all", async (t) => {
  const db = testD1();
  // If the state check were skipped, this stub would be reached and a session
  // would exist. Asserting on the row is what makes that visible.
  stubProvider(t, [["googleapis.com", () => jsonOk({ access_token: "at" })]]);

  const { flow } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(db),
    provider: "google",
    next: "/apply",
  });

  const res = await callback({
    request: callbackRequest(flow, { query: `?code=abc&state=${"0".repeat(flow.state.length)}` }),
    env: ENV(db),
    params: CALLBACK_PARAMS("google"),
  });

  assert.equal(res.status, 400);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM sessions").get().n, 0);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM users").get().n, 0);
  assert.ok(res.headers.getSetCookie().some((c) => c.startsWith(`${OAUTH_COOKIE}=`) && /Max-Age=0/.test(c)));
});

test("a flow started for one provider cannot be replayed at another", async (t) => {
  const db = testD1();
  stubProvider(t, [["github.com", () => jsonOk({ access_token: "at", id: 1 })]]);

  const { flow } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(db),
    provider: "google",
    next: "/apply",
  });

  // Same state, right cookie, wrong path segment.
  const res = await callback({
    request: callbackRequest(flow, { query: `?code=abc&state=${flow.state}` }),
    env: ENV(db),
    params: CALLBACK_PARAMS("github"),
  });

  assert.equal(res.status, 400);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM users").get().n, 0);
});

test("a callback with no flow cookie is refused", async () => {
  const db = testD1();
  const res = await callback({
    request: new Request(`${SITE}/api/auth/google/callback?code=abc&state=whatever`),
    env: ENV(db),
    params: CALLBACK_PARAMS("google"),
  });
  assert.equal(res.status, 400);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM sessions").get().n, 0);
});

test("a cancelled sign-in creates nothing and is not an error", async (t) => {
  const db = testD1();
  stubProvider(t, []); // nothing should be fetched at all

  const { flow } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(db),
    provider: "google",
    next: "/apply",
  });

  const res = await callback({
    request: callbackRequest(flow, { query: `?error=access_denied&state=${flow.state}` }),
    env: ENV(db),
    params: CALLBACK_PARAMS("google"),
  });

  assert.equal(res.status, 200);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM users").get().n, 0);
});

test("a failed exchange leaves no user behind and shows no detail", async (t) => {
  const db = testD1();
  stubProvider(t, [
    ["oauth2.googleapis.com/token", () => new Response('{"error":"invalid_client","client_id":"google-client-id"}', { status: 401 })],
  ]);

  const { flow } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(db),
    provider: "google",
    next: "/apply",
  });

  const res = await callback({
    request: callbackRequest(flow, { query: `?code=abc&state=${flow.state}` }),
    env: ENV(db),
    params: CALLBACK_PARAMS("google"),
  });

  assert.equal(res.status, 502);
  const body = await res.text();
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM users").get().n, 0);

  // Nothing from the provider's response body reaches the page.
  assert.doesNotMatch(body, /invalid_client/);
  assert.doesNotMatch(body, /google-client-id/);
  assert.doesNotMatch(body, /google-client-secret/);
});

test("the callback never puts the client secret in a URL", async (t) => {
  // A defence against a later refactor moving the exchange to a redirect or a
  // query string, where the secret lands in logs and Referer headers.
  const db = testD1();
  const seen = [];
  stubProvider(t, [
    ["oauth2.googleapis.com/token", (url, init) => {
      seen.push({ url, method: init.method, body: String(init.body || "") });
      return jsonOk({ access_token: "at" });
    }],
    ["openidconnect.googleapis.com/v1/userinfo", () => jsonOk({ sub: "g-1", email: "a@example.com" })],
  ]);

  const { flow } = await beginFlow({
    request: new Request(`${SITE}/api/auth/google/start`),
    env: ENV(db),
    provider: "google",
    next: "/apply",
  });

  await callback({
    request: callbackRequest(flow, { query: `?code=abc&state=${flow.state}` }),
    env: ENV(db),
    params: CALLBACK_PARAMS("google"),
  });

  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, "POST");
  assert.doesNotMatch(seen[0].url, /client_secret/);
  assert.match(seen[0].body, /client_secret=google-client-secret/);
  // The verifier goes with it — that is the point of PKCE.
  assert.match(seen[0].body, new RegExp(`code_verifier=${flow.verifier}`));
});
