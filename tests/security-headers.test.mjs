// node --test tests/security-headers.test.mjs
//
// `_headers` only decorates static asset responses. Every page and API
// response built by a Pages Function has to set its own headers, or it is
// served with none of the baseline protections the static site has.

import test from "node:test";
import assert from "node:assert/strict";

import { html, json } from "../functions/_shared.js";

test("dynamic JSON responses are no-store and non-sniffable", () => {
  const response = json({ ok: true });

  assert.equal(
    response.headers.get("Content-Type"),
    "application/json; charset=utf-8",
  );
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(
    response.headers.get("Referrer-Policy"),
    "strict-origin-when-cross-origin",
  );
  assert.equal(
    response.headers.get("Permissions-Policy"),
    "camera=(), microphone=(), geolocation=()",
  );
});

test("dynamic HTML responses carry the site CSP and no-store", () => {
  const response = html("<!doctype html><title>x</title>");
  const csp = response.headers.get("Content-Security-Policy") || "";

  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(
    response.headers.get("Referrer-Policy"),
    "strict-origin-when-cross-origin",
  );
  assert.equal(
    response.headers.get("Permissions-Policy"),
    "camera=(), microphone=(), geolocation=()",
  );
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /form-action 'self'/);
});
