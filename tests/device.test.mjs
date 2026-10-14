// node --test "tests/*.test.mjs"
//
// The connect flow's failure modes are what matter here, and most of them are
// "did the database get touched when it should not have":
//
//   * a bad key must be refused BEFORE any query, so a stranger cannot make
//     the site write anything;
//   * an unconfigured database must never answer 200 with a code that can
//     then never be claimed;
//   * an unset admin token must deny everybody, not nobody.
//
// The statements that actually talk to D1 (the guarded claim UPDATE, the
// ON CONFLICT upserts) are not faked here on purpose — faking SQLite proves
// the fake works. Those paths are exercised against the real database.

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { onRequestPost as start } from "../functions/api/device/start.js";
import { onRequestPost as poll } from "../functions/api/device/poll.js";
import { onRequestPost as claim } from "../functions/api/device/claim.js";
import { onRequestGet as connect } from "../functions/connect.js";
import { onRequestPost as admin } from "../functions/admin.js";
import {
  cleanCode,
  cleanDeviceId,
  cleanEmail,
  isAdmin,
  randomCode,
} from "../functions/_shared.js";

const GOOD = "KRYO-AB2C-DE3F-GH4J";
const KEYS = `${GOOD},KRYO-2222-2222-2222`;

/** A database that fails loudly if anything uses it. */
const UNTOUCHABLE = {
  prepare() {
    throw new Error("the database must not be touched on this path");
  },
};

function post(url, body, env) {
  return new Request(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ---- every function file must bundle ---------------------------------------

test("every file under functions/ resolves all of its imports", async () => {
  // The deploy fails, not the code, when a relative import is off by one
  // level — `../_shared.js` from functions/api/device/ points at a file that
  // does not exist. esbuild only complains at build time, so importing each
  // file here is what makes that a fast local failure instead of a red
  // deployment.
  const root = fileURLToPath(new URL("../functions", import.meta.url));
  const files = [];
  (function walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) files.push(full);
    }
  })(root);

  assert.ok(files.length >= 8, `expected the function tree, found ${files.length}`);
  for (const file of files) {
    await assert.doesNotReject(
      () => import(new URL(`file://${file.replace(/\\/g, "/")}`).href),
      `${file} must resolve its imports`,
    );
  }
});

// ---- /api/device/claim -----------------------------------------------------

function formPost(url, fields, env) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) form.set(k, v);
  return claim({
    request: new Request(url, { method: "POST", body: form }),
    env,
  });
}

test("a claim with no database redirects back, and does not pretend to work", async () => {
  const response = await formPost(
    "https://kryonsec.in/api/device/claim",
    { code: "AB2C-DE3F", email: "member@example.com" },
    {},
  );
  assert.equal(response.status, 303);
  assert.match(response.headers.get("Location"), /\/connect\?.*e=notconf/);
});

test("a bad code or email is refused before the database is touched", async () => {
  const cases = [
    [{ code: "AB10-CD34", email: "member@example.com" }, "e=code"], // 0/1 not in the alphabet
    [{ code: "", email: "member@example.com" }, "e=code"],
    [{ code: "AB2C-DE3F", email: "not-an-email" }, "e=email"],
    [{ code: "AB2C-DE3F", email: "" }, "e=email"],
  ];
  for (const [fields, expected] of cases) {
    const response = await formPost(
      "https://kryonsec.in/api/device/claim", fields, { KRYONSEC_DB: UNTOUCHABLE },
    );
    const location = response.headers.get("Location");
    assert.equal(response.status, 303, JSON.stringify(fields));
    assert.match(location, new RegExp(expected), `${JSON.stringify(fields)} -> ${location}`);
  }
});

test("the refusal redirect is 303, so a refresh cannot repost", async () => {
  const response = await formPost(
    "https://kryonsec.in/api/device/claim", { code: "nope", email: "a@b.com" }, {},
  );
  assert.equal(response.status, 303, "302 would make a refresh POST again");
});

test("the redirect stays on the origin the request arrived on", async () => {
  const response = await formPost(
    "https://kryonsec.in/api/device/claim", { code: "nope", email: "a@b.com" }, {},
  );
  assert.ok(
    response.headers.get("Location").startsWith("https://kryonsec.in/connect?"),
    "a redirect must not be pointed at another host",
  );
});

// ---- /api/device/start -----------------------------------------------------

test("a bad key is refused without touching the database", async () => {
  const cases = [
    [{ key: "" }, 400],
    [{ key: "nonsense" }, 400],
    [{ key: "KRYO-AB2C-DE3F" }, 400],
    [{ key: "KRYO-0000-OOOO-1111" }, 400], // right shape, wrong alphabet
    [{ key: "KRYO-2222-2222-2223" }, 403], // well-formed, not on the list
  ];
  for (const [body, status] of cases) {
    const response = await start({
      request: post("https://kryonsec.in/api/device/start", body),
      env: { KRYONSEC_KEYS: KEYS, KRYONSEC_DB: UNTOUCHABLE },
    });
    assert.equal(response.status, status, JSON.stringify(body));
  }
});

test("no database means 503, never a code that cannot be claimed", async () => {
  const response = await start({
    request: post("https://kryonsec.in/api/device/start", { key: GOOD }),
    env: { KRYONSEC_KEYS: KEYS },
  });
  assert.equal(response.status, 503);
  assert.ok(!(await response.json()).code);
});

test("a body that is not JSON is a 400, not a crash", async () => {
  const response = await start({
    request: new Request("https://kryonsec.in/api/device/start", {
      method: "POST",
      body: "not json",
    }),
    env: { KRYONSEC_KEYS: KEYS, KRYONSEC_DB: UNTOUCHABLE },
  });
  assert.equal(response.status, 400);
});

// ---- /api/device/poll ------------------------------------------------------

test("poll refuses a device_code that is not one of ours", async () => {
  for (const body of [{}, { device_code: "" }, { device_code: "short" },
                      { device_code: "z".repeat(64) }]) {
    const response = await poll({
      request: post("https://kryonsec.in/api/device/poll", body),
      env: { KRYONSEC_DB: UNTOUCHABLE },
    });
    // Rejected on shape alone — no lookup, and never a "connected".
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.notEqual((await response.json()).status, "connected");
  }
});

test("poll with no database is never \"connected\"", async () => {
  const response = await poll({
    request: post("https://kryonsec.in/api/device/poll", { device_code: "a".repeat(64) }),
    env: {},
  });
  assert.equal(response.status, 503);
  assert.notEqual((await response.json()).status, "connected");
});

// ---- the admin token -------------------------------------------------------

test("an unset admin token denies everybody", () => {
  // "" must mean "nobody", never "no password required".
  assert.equal(isAdmin("", ""), false);
  assert.equal(isAdmin("anything", ""), false);
  assert.equal(isAdmin("", undefined), false);
  assert.equal(isAdmin("anything", null), false);
});

test("the admin token is compared exactly", () => {
  assert.equal(isAdmin("hunter2", "hunter2"), true);
  assert.equal(isAdmin("hunter2", "hunter3"), false);
  assert.equal(isAdmin("hunter", "hunter2"), false); // length differs
  assert.equal(isAdmin("hunter22", "hunter2"), false);
});

test("the admin page refuses everything when no token is configured", async () => {
  const form = new FormData();
  form.set("token", "");
  const response = await admin({
    request: new Request("https://kryonsec.in/admin", { method: "POST", body: form }),
    env: { KRYONSEC_FEEDBACK: { get: async () => null } },
  });
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.match(body, /No admin token is configured/);
});

test("a wrong admin token does not reach the database", async () => {
  const form = new FormData();
  form.set("token", "wrong");
  const response = await admin({
    request: new Request("https://kryonsec.in/admin", { method: "POST", body: form }),
    env: {
      KRYONSEC_FEEDBACK: { get: async () => "right" },
      KRYONSEC_DB: UNTOUCHABLE,
    },
  });
  assert.match(await response.text(), /not right/);
});

// ---- the connect page ------------------------------------------------------

test("a hostile code in the URL cannot inject markup", async () => {
  const response = await connect({
    request: new Request(
      "https://kryonsec.in/connect?code=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    ),
  });
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.ok(!body.includes("<script>alert(1)</script>"), "escaped or dropped");
  assert.match(body, /CONNECT CODE/, "a bad code falls back to asking for one");
});

test("a good code is shown back so it can be matched to the terminal", async () => {
  const response = await connect({
    request: new Request("https://kryonsec.in/connect?code=AB2C-DE3F"),
  });
  const body = await response.text();
  assert.match(body, /AB2C-DE3F/);
  assert.ok(!body.includes('name="code" type="text"'), "no need to type it again");
});

test("the connect page is never indexed or cached", async () => {
  const response = await connect({
    request: new Request("https://kryonsec.in/connect?code=AB2C-DE3F"),
  });
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.match(response.headers.get("X-Robots-Tag"), /noindex/);
});

// ---- the input helpers -----------------------------------------------------

test("codes use the unambiguous alphabet", () => {
  for (let i = 0; i < 200; i += 1) {
    const code = randomCode();
    assert.match(code, /^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{4}$/);
    assert.equal(cleanCode(code), code);
  }
});

test("cleanCode normalises case and whitespace, and rejects the rest", () => {
  assert.equal(cleanCode("  ab2c-de3f "), "AB2C-DE3F");
  assert.equal(cleanCode("AB2CDE3F"), ""); // no dash
  assert.equal(cleanCode("AB10-CD34"), ""); // 0 and 1 are not in the alphabet
  assert.equal(cleanCode(""), "");
  assert.equal(cleanCode(null), "");
});

test("cleanEmail keeps a plausible address and drops the rest", () => {
  assert.equal(cleanEmail("  Member@Example.COM "), "member@example.com");
  assert.equal(cleanEmail("not-an-email"), "");
  assert.equal(cleanEmail("a@b"), "");
  assert.equal(cleanEmail(`${"x".repeat(250)}@example.com`), "");
  assert.equal(cleanEmail(""), "");
});

test("a device id must be opaque hex, so nothing else can be smuggled in", () => {
  assert.equal(cleanDeviceId("9f8e7d6c5b4a39281706"), "9f8e7d6c5b4a39281706");
  assert.equal(cleanDeviceId("GONCH-LAPTOP"), ""); // a hostname is not an id
  assert.equal(cleanDeviceId("../../etc/passwd"), "");
  assert.equal(cleanDeviceId("abc"), ""); // too short
});
