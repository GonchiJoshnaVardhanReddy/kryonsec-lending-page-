// node --test tests/install-flow.test.mjs
//
// The Windows installer authorises itself the same way `kryonsec login` does:
// a person approves a code in a browser. What comes back is different — a
// single-use download URL instead of a ninety-day machine token — because an
// installer has no reason to hold a credential after the wheel is on disk.
//
// These tests pin that distinction: the approval must produce a download
// token, must not create a CLI session, and that token must behave exactly
// like every other download token at the gate.

import test from "node:test";
import assert from "node:assert/strict";

import { SESSION_COOKIE, createSession, csrfFor, sha256Hex } from "../functions/_auth.js";
import { onRequestPost as approve } from "../functions/api/beta/device/approve.js";
import { onRequestPost as poll } from "../functions/api/beta/device/poll.js";
import { onRequestPost as start } from "../functions/api/beta/device/start.js";
import { onRequestGet as download } from "../functions/api/beta/download.js";
import { grantEntitlement } from "../functions/_store.js";
import { makeUser, req, testD1 } from "./helpers/d1.mjs";

const SITE = "https://kryonsec.in";
const PREVIEW = "https://feat-beta-onboarding.kryonsec-landing.pages.dev";

const RELEASE = {
  assets: [{ name: "kryonsec-9.9.9-py3-none-any.whl", url: "https://api.github.com/assets/1" }],
};

const jsonOk = (body) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

const wheelResponse = () =>
  new Response(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), {
    status: 200,
    headers: { "Content-Type": "application/octet-stream" },
  });

/** GitHub is the only thing stubbed; every table and query above it is real. */
const stubGithub = (t) =>
  t.mock.method(globalThis, "fetch", async (url) => {
    const target = String(url);
    if (target.includes("/releases/latest")) return jsonOk(RELEASE);
    if (target.includes("/assets/")) return wheelResponse();
    throw new Error(`the test hit an unexpected URL: ${target}`);
  });

const ENV = (db) => ({ KRYONSEC_DB: db, KRYONSEC_GITHUB_TOKEN: "gh-pat" });

const startRequest = (origin = SITE) =>
  new Request(`${origin}/api/beta/device/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: "pc-1", os: "Windows", arch: "amd64", version: "installer" }),
  });

const pollRequest = (device_code, fields = {}, origin = SITE) =>
  new Request(`${origin}/api/beta/device/poll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_code, ...fields }),
  });

/** A signed-in, entitled account — the person approving the install. */
async function browser(db) {
  const userId = await makeUser(db);
  const token = await createSession(db, userId);
  await grantEntitlement(db, { userId, actor: "admin" });
  return { userId, token, cookie: `${SESSION_COOKIE}=${token}`, csrf: await csrfFor(token) };
}

async function approvedCode(db, who, origin = SITE) {
  const started = await (await start({ request: startRequest(origin), env: ENV(db) })).json();
  const response = await approve({
    request: req(`${origin}/api/beta/device/approve`, {
      method: "POST",
      cookie: who.cookie,
      headers: { "Sec-Fetch-Site": "same-origin", Origin: origin },
      body: new URLSearchParams({
        code: started.code,
        decision: "approve",
        csrf: who.csrf,
      }),
    }),
    env: ENV(db),
  });
  assert.equal(response.status, 303);
  return started;
}

test("an approved install returns a one-time download URL, not a machine session", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await approvedCode(db, who);

  const response = await poll({
    request: pollRequest(started.device_code, { purpose: "download" }),
    env: ENV(db),
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.status, "approved");
  assert.match(body.download_url, /^https:\/\/kryonsec\.in\/api\/beta\/download\?t=dl_[0-9a-f]{64}$/);
  assert.equal(body.token, undefined, "an installer must never receive a CLI session token");
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM download_tokens").get().n, 1);
});

test("the install download URL is spent by its first use", async (t) => {
  const db = testD1();
  const who = await browser(db);
  const started = await approvedCode(db, who);
  stubGithub(t);

  const body = await (
    await poll({
      request: pollRequest(started.device_code, { purpose: "download" }),
      env: ENV(db),
    })
  ).json();
  const url = new URL(body.download_url);

  const first = await download({ request: req(url.href), env: ENV(db) });
  assert.equal(first.status, 200);
  assert.match(first.headers.get("X-Kryonsec-Wheel-SHA256"), /^[0-9a-f]{64}$/);
  await first.arrayBuffer();

  const callsAfterSuccess = globalThis.fetch.mock.callCount();
  const second = await download({ request: req(url.href), env: ENV(db) });
  assert.equal(second.status, 401);
  assert.equal(globalThis.fetch.mock.callCount(), callsAfterSuccess);
});

test("an install download token past its expiry is refused", async (t) => {
  const db = testD1();
  const who = await browser(db);
  const started = await approvedCode(db, who);
  stubGithub(t);

  const body = await (
    await poll({
      request: pollRequest(started.device_code, { purpose: "download" }),
      env: ENV(db),
    })
  ).json();
  const token = new URL(body.download_url).searchParams.get("t");
  db._raw
    .prepare("UPDATE download_tokens SET expires_at = ? WHERE token_hash = ?")
    .run("2020-01-01T00:00:00.000Z", await sha256Hex(token));

  const response = await download({
    request: req(`${SITE}/api/beta/download?t=${token}`),
    env: ENV(db),
  });
  assert.equal(response.status, 401);
});

test("an install code collection with an unknown purpose is refused", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await approvedCode(db, who);

  const response = await poll({
    request: pollRequest(started.device_code, { purpose: "administrator" }),
    env: ENV(db),
  });

  assert.equal(response.status, 400);
  // Nothing was minted, and the code was not spent deciding that.
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM cli_sessions").get().n, 0);
  assert.equal(db._raw.prepare("SELECT COUNT(*) AS n FROM download_tokens").get().n, 0);
});

test("the install download URL follows the deployment that issued it", async () => {
  const db = testD1();
  const who = await browser(db);
  const started = await approvedCode(db, who, PREVIEW);

  const body = await (
    await poll({
      request: pollRequest(started.device_code, { purpose: "download" }, PREVIEW),
      env: ENV(db),
    })
  ).json();

  assert.match(
    body.download_url,
    /^https:\/\/feat-beta-onboarding\.kryonsec-landing\.pages\.dev\/api\/beta\/download\?t=dl_/,
  );
});
