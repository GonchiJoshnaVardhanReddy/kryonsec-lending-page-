// node --test "tests/*.test.mjs"
//
// What /signin renders, and what the start and callback routes answer when
// provider configuration is present, half-present, and absent. The OAuth
// exchange itself is covered in oauth.test.mjs; this file is about the
// surfaces a person actually meets.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { onRequestGet as signin } from "../functions/signin.js";
import { onRequestGet as start } from "../functions/api/auth/[provider]/start.js";
import { onRequestGet as callback } from "../functions/api/auth/[provider]/callback.js";
import { SESSION_COOKIE } from "../functions/_auth.js";
import { testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";

const ENV = (db, overrides = {}) => ({
  KRYONSEC_DB: db,
  KRYONSEC_GOOGLE_CLIENT_ID: "google-client-id",
  KRYONSEC_GOOGLE_CLIENT_SECRET: "google-client-secret",
  KRYONSEC_GITHUB_CLIENT_ID: "github-client-id",
  KRYONSEC_GITHUB_CLIENT_SECRET: "github-client-secret",
  ...overrides,
});

const renderSignin = (env) => signin({ request: new Request(`${SITE}/signin`), env });

// --- the homepage navigation ------------------------------------------------

test("the homepage primary navigation links to /signin and keeps its other links", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const nav = html.match(/<nav class="site-nav"[^>]*>([\s\S]*?)<\/nav>/);
  assert.ok(nav, "the primary navigation was not found");

  const inner = nav[1];
  assert.match(inner, /href="\/signin"[^>]*>SIGN IN<\/a>/);
  for (const href of ["#platform", "#access", "feedback.html", "roadmap.html"]) {
    assert.match(inner, new RegExp(`href="${href.replace(/[.#]/g, "\\$&")}"`));
  }
});

// --- what the sign-in page offers ------------------------------------------

test("both configured providers get working start links", async () => {
  const res = await renderSignin(ENV(testD1()));
  assert.equal(res.status, 200);
  const body = await res.text();

  assert.match(body, /href="\/api\/auth\/google\/start\?next=%2Fdashboard"/);
  assert.match(body, /href="\/api\/auth\/github\/start\?next=%2Fdashboard"/);
  assert.doesNotMatch(body, /is-unavailable/);
  assert.doesNotMatch(body, /not available on this deployment/);
  // The privacy wording survives.
  assert.match(body, /We cannot read your repositories, your files, or your mail/);
});

test("one configured provider is offered, and the other is named as unavailable", async () => {
  const env = ENV(testD1(), {
    KRYONSEC_GOOGLE_CLIENT_ID: "",
    KRYONSEC_GOOGLE_CLIENT_SECRET: "",
  });
  const body = await (await renderSignin(env)).text();

  assert.match(body, /href="\/api\/auth\/github\/start/);
  assert.doesNotMatch(body, /href="\/api\/auth\/google\/start/);
  // The disabled control is still visible, so the missing option is explained.
  assert.match(body, /data-provider="google"[^>]*disabled/);
  assert.match(body, /Google sign-in is not available on this deployment yet\. Use GitHub instead\./);
  assert.doesNotMatch(body, /GitHub sign-in is not available/);
});

test("with nothing configured, both providers are named and none is linked", async () => {
  const body = await (await renderSignin({ KRYONSEC_DB: testD1() })).text();

  assert.doesNotMatch(body, /href="\/api\/auth\/(google|github)\/start/);
  assert.match(body, /data-provider="google"[^>]*disabled/);
  assert.match(body, /data-provider="github"[^>]*disabled/);
  assert.match(body, /neither Google nor GitHub sign-in has been configured/);
});

test("a half-configured provider is not offered", async () => {
  // An id with no secret cannot complete an exchange, so it must not look
  // usable. This is the state the live project is in for Google today.
  const env = ENV(testD1(), { KRYONSEC_GOOGLE_CLIENT_SECRET: "" });
  const body = await (await renderSignin(env)).text();

  assert.doesNotMatch(body, /href="\/api\/auth\/google\/start/);
  assert.match(body, /Google sign-in is not available on this deployment yet/);
  assert.match(body, /href="\/api\/auth\/github\/start/);
});

test("the loading script is loaded from the same origin", async () => {
  const body = await (await renderSignin(ENV(testD1()))).text();
  assert.match(body, /<script src="\/signin.js" defer><\/script>/);
});

// --- the OAuth routes -------------------------------------------------------

test("a configured GitHub start redirects to GitHub with PKCE and a flow cookie", async () => {
  const res = await start({
    request: new Request(`${SITE}/api/auth/github/start?next=/apply`),
    env: ENV(testD1()),
    params: { provider: "github" },
  });

  assert.equal(res.status, 302);
  const location = new URL(res.headers.get("Location"));
  assert.equal(location.origin + location.pathname, "https://github.com/login/oauth/authorize");
  assert.equal(location.searchParams.get("client_id"), "github-client-id");
  assert.equal(location.searchParams.get("redirect_uri"), `${SITE}/api/auth/github/callback`);
  assert.equal(location.searchParams.get("code_challenge_method"), "S256");
  assert.ok(location.searchParams.get("state"));
  assert.match(res.headers.get("Set-Cookie") || "", /kr_oauth=.+HttpOnly/);
  assert.match(res.headers.get("Set-Cookie") || "", /SameSite=Lax/);
  // The secret never leaves the server.
  assert.doesNotMatch(res.headers.get("Location"), /client_secret|github-client-secret/);
});

test("an unconfigured provider's start page names that provider", async () => {
  const res = await start({
    request: new Request(`${SITE}/api/auth/github/start`),
    env: { KRYONSEC_DB: testD1() },
    params: { provider: "github" },
  });
  assert.equal(res.status, 503);
  const body = await res.text();
  assert.match(body, /GitHub sign-in is not switched on yet/);
  assert.doesNotMatch(body, /github-client-secret/);
});

test("the callback rejects an unknown provider without touching the database", async () => {
  const res = await callback({
    request: new Request(`${SITE}/api/auth/__proto__/callback?code=x&state=y`),
    env: ENV(testD1()),
    params: { provider: "__proto__" },
  });
  assert.equal(res.status, 404);
  assert.match(await res.text(), /does not exist/);
});

test("the callback names an unconfigured provider and clears the flow cookie", async () => {
  const res = await callback({
    request: new Request(`${SITE}/api/auth/google/callback?code=x&state=y`),
    env: { KRYONSEC_DB: testD1() },
    params: { provider: "google" },
  });
  assert.equal(res.status, 503);
  assert.match(await res.text(), /Google sign-in is not switched on yet/);
  assert.ok(res.headers.getSetCookie().some((c) => /Max-Age=0/.test(c)));
});

test("a configured provider with no database fails clearly before the exchange", async () => {
  // The preview environment is in this state: providers can be set while the
  // D1 binding is not. A 500 with no message would read as a broken site.
  const res = await callback({
    request: new Request(`${SITE}/api/auth/google/callback?code=x&state=y`),
    env: {
      KRYONSEC_GOOGLE_CLIENT_ID: "google-client-id",
      KRYONSEC_GOOGLE_CLIENT_SECRET: "google-client-secret",
    },
    params: { provider: "google" },
  });
  assert.equal(res.status, 503);
  assert.match(await res.text(), /account store is not available/);
});

test("a signed-in visitor is sent on to ?next instead of seeing the page", async () => {
  const { createSession } = await import("../functions/_auth.js");
  const db = testD1();
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
       VALUES ('u_1', 'a@example.com', 1, 'A', ?, ?)`,
    )
    .bind(now, now)
    .run();
  const token = await createSession(db, "u_1");

  const res = await signin({
    request: new Request(`${SITE}/signin?next=/apply`, {
      headers: { Cookie: `${SESSION_COOKIE}=${token}` },
    }),
    env: ENV(db),
  });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("Location"), "/apply");
});
