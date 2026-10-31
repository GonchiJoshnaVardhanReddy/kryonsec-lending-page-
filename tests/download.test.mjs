// node --test tests/download.test.mjs
//
// Covers the part of the download gate that decides who gets the wheel. The
// GitHub fetch around it needs a live token, but this is the logic that
// silently breaks installs (a regex too strict) or gives the product away
// (an allowlist that matches too much).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  isAllowed,
  isWellFormedKey,
  onRequestGet,
  timingSafeEqual,
} from "../functions/api/download.js";

test("accepts the key format the app itself accepts", () => {
  // key patterns straight out of the license module's alphabet
  for (const key of ["KRYO-AB2C-DE3F-GH4J", "KRYO-2222-2222-2222", "KRYO-ZZZZ-ZZZZ-ZZZZ"]) {
    assert.equal(isWellFormedKey(key), true, key);
  }
});

test("rejects keys the app would reject", () => {
  for (const key of [
    "KRYO-AB2C-DE3F-GH4", // short group
    "KRYO-AB2C-DE3F-GH4JJ", // long group
    "KRYO-AB2C-DE3F", // missing a group
    "KRYO-AB0C-DE3F-GH4J", // 0 is not in the alphabet
    "KRYO-AB1C-DE3F-GH4J", // 1 is not in the alphabet
    "KRYO-ABOC-DE3F-GH4J", // O is not in the alphabet
    "KRYO-ABIC-DE3F-GH4J", // I is not in the alphabet
    "AB2C-DE3F-GH4J", // no prefix
    "kryo-ab2c-de3f-gh4j", // lowercase (the handler uppercases first)
    "",
  ]) {
    assert.equal(isWellFormedKey(key), false, key);
  }
});

test("allows a listed key and nothing else", () => {
  const list = "KRYO-AB2C-DE3F-GH4J, KRYO-2222-2222-2222";
  assert.equal(isAllowed("KRYO-AB2C-DE3F-GH4J", list), true);
  assert.equal(isAllowed("KRYO-2222-2222-2222", list), true); // whitespace trimmed
  assert.equal(isAllowed("KRYO-3333-3333-3333", list), false);
});

test("an unset or empty allowlist denies everyone", () => {
  // The failure mode that matters most: a missing Pages env var must not
  // become an open door.
  for (const list of [undefined, null, "", "   ", ",,,"]) {
    assert.equal(isAllowed("KRYO-AB2C-DE3F-GH4J", list), false, String(list));
  }
});

test("a key is not a prefix or superstring of another", () => {
  const list = "KRYO-AB2C-DE3F-GH4J";
  assert.equal(isAllowed("KRYO-AB2C-DE3F-GH4", list), false);
  assert.equal(isAllowed("KRYO-AB2C-DE3F-GH4JX", list), false);
});

test("timingSafeEqual agrees with equality", () => {
  assert.equal(timingSafeEqual("KRYO-AB2C-DE3F-GH4J", "KRYO-AB2C-DE3F-GH4J"), true);
  assert.equal(timingSafeEqual("KRYO-AB2C-DE3F-GH4J", "KRYO-AB2C-DE3F-GH4K"), false);
  assert.equal(timingSafeEqual("KRYO-AB2C-DE3F-GH4J", "KRYO-AB2C-DE3F-GH4"), false);
  assert.equal(timingSafeEqual("", ""), true);
});

// ---------------------------------------------------------------------------
// The gate as the installer meets it.
//
// install.sh sends the key as a header and refuses a wheel whose
// X-Kryonsec-Wheel-SHA256 is missing or wrong, so both halves of that contract
// have to hold here. These stub GitHub rather than reaching for a live token:
// the shape of the answer is what is being tested, not the release itself.
// ---------------------------------------------------------------------------

const MEMBER = "KRYO-AB2C-DE3F-GH4J";
const WHEEL_BYTES = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x57, 0x68, 0x65, 0x65, 0x6c]);

function stubGitHub(t) {
  t.mock.method(globalThis, "fetch", async (url) => {
    if (String(url).endsWith("/releases/latest")) {
      return new Response(
        JSON.stringify({
          assets: [
            {
              name: "kryonsec-1.3.8-py3-none-any.whl",
              url: "https://uploads.example.test/asset",
            },
          ],
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response(WHEEL_BYTES, {
      headers: { "Content-Type": "application/octet-stream" },
    });
  });
  return { KRYONSEC_KEYS: MEMBER, KRYONSEC_GITHUB_TOKEN: "ghp_test" };
}

function gate(key, where, env) {
  const headers = {};
  if (where === "header") headers["X-Kryonsec-Key"] = key;
  const url =
    where === "query"
      ? `https://kryonsec.in/api/download?key=${encodeURIComponent(key)}&os=linux`
      : "https://kryonsec.in/api/download?os=linux";
  return onRequestGet({ request: new Request(url, { headers }), env });
}

test("a key in the header opens the gate", async (t) => {
  const env = stubGitHub(t);
  const response = await gate(MEMBER, "header", env);
  assert.equal(response.status, 200);
});

test("the key stays out of the URL", async (t) => {
  // The reason the header exists: a query string is copied into access logs,
  // proxy logs and Referer headers. If a header request starts answering 400
  // again, installs will silently go back to putting the credential in a URL.
  const env = stubGitHub(t);
  const response = await gate(MEMBER, "header", env);
  assert.equal(response.headers.get("Content-Type"), "application/octet-stream");
});

test("the legacy query still opens the gate", async (t) => {
  const env = stubGitHub(t);
  const response = await gate(MEMBER, "query", env);
  assert.equal(response.status, 200);
});

test("the wheel is published with the SHA-256 of the bytes it returns", async (t) => {
  const env = stubGitHub(t);
  const response = await gate(MEMBER, "header", env);
  const expected = createHash("sha256").update(WHEEL_BYTES).digest("hex");
  // Read the body through a second hash before trusting the header, or the
  // test would pass on a header that describes some other artifact.
  const served = new Uint8Array(await response.arrayBuffer());
  assert.deepEqual(served, WHEEL_BYTES);
  assert.equal(response.headers.get("X-Kryonsec-Wheel-SHA256"), expected);
});

test("an unrecognised key gets no wheel and no hash", async (t) => {
  const env = stubGitHub(t);
  const response = await gate("KRYO-2222-2222-2222", "header", env);
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("X-Kryonsec-Wheel-SHA256"), null);
});
