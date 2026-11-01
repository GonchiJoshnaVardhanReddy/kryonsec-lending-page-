// node --test tests/wheel-hash.test.mjs
//
// The installers refuse a wheel whose SHA-256 does not match what the site
// said it would serve. That only works if both download paths hash the exact
// bytes they return and set the header in the format the installers expect.
//
// These tests are deliberately end-to-end at the handler boundary: a unit test
// of a helper would not catch a handler that computes the digest of one buffer
// and returns another.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { onRequestGet } from "../functions/api/download.js";
import { latestWheel } from "../functions/_release.js";

const WHEEL = new TextEncoder().encode("PK\u0003\u0004 fake wheel bytes \u0000\u0001");
const WHEEL_SHA256 = createHash("sha256").update(WHEEL).digest("hex");
const KEY = "KRYO-2222-2222-2222";
const ASSET_URL = "https://api.github.com/repos/owner/repo/releases/assets/1";

/** Mock the two GitHub responses and record what the handler asked for. */
function mockGitHub(t, { releaseStatus = 200, assets, assetStatus = 200 } = {}) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const href = String(url);
    calls.push({ href, headers: init.headers || {} });
    if (href.endsWith("/releases/latest")) {
      const body =
        releaseStatus === 200
          ? JSON.stringify({
              assets:
                assets ??
                [{ name: "kryonsec-1.3.8-py3-none-any.whl", url: ASSET_URL }],
            })
          : "{}";
      return new Response(body, {
        status: releaseStatus,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (href === ASSET_URL) {
      return new Response(assetStatus === 200 ? WHEEL : "no", {
        status: assetStatus,
      });
    }
    throw new Error(`unexpected fetch: ${href}`);
  };
  t.after(() => {
    globalThis.fetch = original;
  });
  return calls;
}

function legacyRequest(key = KEY) {
  return new Request("https://kryonsec.in/api/download", {
    headers: { "X-Kryonsec-Key": key },
  });
}

test("legacy download hashes the exact bytes it returns", async (t) => {
  const calls = mockGitHub(t);
  const response = await onRequestGet({
    request: legacyRequest(),
    env: { KRYONSEC_KEYS: KEY, KRYONSEC_GITHUB_TOKEN: "token" },
  });

  assert.equal(response.status, 200);
  assert.deepEqual(
    Buffer.from(await response.arrayBuffer()),
    Buffer.from(WHEEL),
  );
  assert.equal(response.headers.get("X-Kryonsec-Wheel-SHA256"), WHEEL_SHA256);
  assert.match(WHEEL_SHA256, /^[0-9a-f]{64}$/);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(calls.at(-1).href, ASSET_URL);
  assert.equal(
    calls.at(-1).headers.Accept,
    "application/octet-stream",
    "the asset URL returns JSON metadata without this Accept header",
  );
});

test("beta download hashes the exact bytes it returns", async (t) => {
  mockGitHub(t);
  const result = await latestWheel({ KRYONSEC_GITHUB_TOKEN: "token" });

  assert.equal(result.ok, true);
  assert.deepEqual(
    Buffer.from(await result.response.arrayBuffer()),
    Buffer.from(WHEEL),
  );
  assert.equal(
    result.response.headers.get("X-Kryonsec-Wheel-SHA256"),
    WHEEL_SHA256,
  );
  assert.equal(result.response.headers.get("Cache-Control"), "no-store");
});

test("legacy download refuses a missing key before touching GitHub", async (t) => {
  const calls = mockGitHub(t);
  const response = await onRequestGet({
    request: legacyRequest(""),
    env: { KRYONSEC_KEYS: KEY, KRYONSEC_GITHUB_TOKEN: "token" },
  });

  assert.equal(response.status, 400);
  assert.equal(calls.length, 0);
});

test("legacy download refuses a malformed or unlisted key", async (t) => {
  mockGitHub(t);
  for (const key of ["not-a-key", "KRYO-3333-3333-3333"]) {
    const response = await onRequestGet({
      request: legacyRequest(key),
      env: { KRYONSEC_KEYS: KEY, KRYONSEC_GITHUB_TOKEN: "token" },
    });
    assert.equal(response.status, 403, key);
  }
});

test("legacy download reports a missing GitHub token as a site failure", async () => {
  const response = await onRequestGet({
    request: legacyRequest(),
    env: { KRYONSEC_KEYS: KEY },
  });

  assert.equal(response.status, 502);
});

test("beta download reports a missing GitHub token as a site failure", async () => {
  const result = await latestWheel({});
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
});

test("legacy download maps release and asset failures to 502", async (t) => {
  for (const options of [
    { releaseStatus: 500 },
    { assets: [] },
    { assets: [{ name: "notes.txt", url: ASSET_URL }] },
    { assetStatus: 500 },
  ]) {
    const calls = mockGitHub(t, options);
    const response = await onRequestGet({
      request: legacyRequest(),
      env: { KRYONSEC_KEYS: KEY, KRYONSEC_GITHUB_TOKEN: "token" },
    });
    assert.equal(response.status, 502, JSON.stringify(options));
    assert.ok(calls.length >= 1);
  }
});
