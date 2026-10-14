// node --test tests/download.test.mjs
//
// Covers the part of the download gate that decides who gets the wheel. The
// GitHub fetch around it needs a live token, but this is the logic that
// silently breaks installs (a regex too strict) or gives the product away
// (an allowlist that matches too much).

import test from "node:test";
import assert from "node:assert/strict";

import {
  isAllowed,
  isWellFormedKey,
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
