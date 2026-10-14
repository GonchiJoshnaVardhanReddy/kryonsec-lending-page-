// node --test tests/feedback.test.mjs
//
// Exercises the real handler with a stub KV, because the failures that matter
// here are silent ones: a submission accepted but not stored, or dropped but
// reported as received.

import test from "node:test";
import assert from "node:assert/strict";

import { onRequestPost } from "../functions/api/feedback.js";

const VALID = {
  full_name: "Ada Lovelace",
  email: "ada@example.com",
  comments: "The report export drops the last row.",
  source: "kryonsec-feedback",
};

function stubKv() {
  const store = new Map();
  return {
    store,
    put: async (key, value) => void store.set(key, value),
  };
}

async function post(fields, kv = stubKv()) {
  const body = new FormData();
  for (const [name, value] of Object.entries(fields)) body.set(name, value);
  const request = new Request("https://kryonsec.in/api/feedback", {
    method: "POST",
    body,
  });
  const response = await onRequestPost({ request, env: { KRYONSEC_FEEDBACK: kv } });
  return { response, kv };
}

test("stores a complete submission and reports success", async () => {
  const { response, kv } = await post(VALID);
  assert.equal(response.status, 200);
  assert.equal(kv.store.size, 1);

  const [key, raw] = [...kv.store.entries()][0];
  assert.match(key, /^feedback\/\d{4}-\d{2}-\d{2}T/);
  const entry = JSON.parse(raw);
  assert.equal(entry.full_name, "Ada Lovelace");
  assert.equal(entry.comments, VALID.comments);
  // Server-stamped, and present even though the form did not send one.
  assert.match(entry.received_at, /^\d{4}-\d{2}-\d{2}T/);
});

test("a missing required field stores nothing", async () => {
  for (const missing of ["full_name", "email", "comments"]) {
    const fields = { ...VALID };
    delete fields[missing];
    const { response, kv } = await post(fields);
    assert.equal(response.status, 400, missing);
    assert.equal(kv.store.size, 0, missing);
  }
});

test("whitespace does not satisfy a required field", async () => {
  const { response, kv } = await post({ ...VALID, comments: "   " });
  assert.equal(response.status, 400);
  assert.equal(kv.store.size, 0);
});

test("a malformed email is rejected", async () => {
  for (const email of ["ada", "ada@", "@example.com", "ada@example", "a b@c.com"]) {
    const { response } = await post({ ...VALID, email });
    assert.equal(response.status, 400, email);
  }
});

test("an unbound namespace reports failure, not success", async () => {
  const body = new FormData();
  for (const [name, value] of Object.entries(VALID)) body.set(name, value);
  const request = new Request("https://kryonsec.in/api/feedback", {
    method: "POST",
    body,
  });
  // The failure mode that matters: a missing binding must not read as "sent".
  const response = await onRequestPost({ request, env: {} });
  assert.equal(response.status, 503);
});

test("an oversized field is truncated, not stored whole", async () => {
  const { response, kv } = await post({ ...VALID, comments: "x".repeat(9000) });
  assert.equal(response.status, 200);
  const entry = JSON.parse([...kv.store.values()][0]);
  assert.equal(entry.comments.length, 5000);
});

test("a failing KV write reports failure", async () => {
  const kv = {
    put: async () => {
      throw new Error("quota exceeded");
    },
  };
  const { response } = await post(VALID, kv);
  assert.equal(response.status, 503);
});
