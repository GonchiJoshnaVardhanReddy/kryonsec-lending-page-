// node --test "tests/*.test.mjs"
//
// The served installer is fetched by anyone and runs with the member's
// privileges, so its contract is checked here — not only in the CLI
// repository that authors it. Three things must stay true: no credential is
// baked into the script, browser approval is what supplies the download link,
// and the wheel's hash is verified before anything is installed.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const SCRIPT = readFileSync(new URL("../install.ps1", import.meta.url), "utf8");
const CODE = SCRIPT.split("\n")
  .filter((line) => !line.trimStart().startsWith("#"))
  .join("\n");

test("the served installer carries no download or session credential", () => {
  assert.doesNotMatch(CODE, /\bdl_[0-9a-f]{64}\b/);
  assert.doesNotMatch(CODE, /\bs_[0-9a-f]{64}\b/);
  // A prepared link may be passed in, but it must never be assigned in the
  // script itself — that is how a token ends up in a copy of the installer.
  assert.doesNotMatch(CODE, /KRYONSEC_DOWNLOAD_URL\s*=\s*['"][^'"]*t=/);
});

test("the documented command is the short download-then-run form", () => {
  assert.match(
    SCRIPT,
    /irm https:\/\/kryonsec\.in\/install\.ps1 -OutFile "\$env:TEMP\\kryonsec-install\.ps1"/,
  );
  assert.match(
    SCRIPT,
    /powershell -ExecutionPolicy Bypass -File "\$env:TEMP\\kryonsec-install\.ps1"/,
  );
  assert.doesNotMatch(CODE, /\bInvoke-Expression\b|\biex\b/i);
});

test("browser approval supplies a fresh, single-use download link", () => {
  assert.match(CODE, /function Start-BetaDevice/);
  assert.match(CODE, /function Wait-BetaDownloadUrl/);
  assert.match(CODE, /purpose\s*=\s*"download"/);
  assert.match(CODE, /download_url/);
  assert.match(CODE, /\/api\/beta\/device\/start/);
  assert.match(CODE, /\/api\/beta\/device\/poll/);
});

test("the wheel hash is verified outside the network catch", () => {
  assert.match(CODE, /X-Kryonsec-Wheel-SHA256/i);
  assert.match(CODE, /-RequireMetadata/);

  const download = CODE.slice(CODE.indexOf("function Download-Wheel"));
  const tryBlock = download.slice(download.indexOf("try {"), download.indexOf("} catch"));
  // Inside the catch, a verification failure would be relabelled as a
  // connection problem and the person would retry instead of reporting it.
  assert.doesNotMatch(tryBlock, /Verify-WheelHash/);
  assert.match(download, /Verify-WheelHash \$Path \$response\.Headers -RequireMetadata/);
});

test("both server-supplied URLs are bound to the configured site", () => {
  const start = CODE.slice(CODE.indexOf("function Start-BetaDevice"), CODE.indexOf("function Wait-BetaDownloadUrl"));
  const poll = CODE.slice(CODE.indexOf("function Wait-BetaDownloadUrl"));

  // The approval page is where a member types their sign-in and the download
  // link is the credential itself. Neither may point at a host the installer
  // did not choose, and the check has to happen before the link is used.
  assert.ok(start.includes("Same-SiteOrigin $Site"));
  assert.ok(start.indexOf("Same-SiteOrigin $Site") < start.indexOf("Start-Process $started.url"));
  assert.ok(poll.includes("Same-SiteOrigin $Site"));
  assert.ok(poll.indexOf("Same-SiteOrigin $Site") < poll.indexOf("return $url"));
});

test("a refusal is not reported as an absent sign-in route", () => {
  const start = CODE.slice(CODE.indexOf("function Start-BetaDevice"), CODE.indexOf("function Wait-BetaDownloadUrl"));

  // Falling back to the membership-key prompt is correct only for a deployment
  // with no sign-in route. Any other answer must name itself, so two fall-back
  // exits in the whole function is the ceiling, not a style preference.
  assert.equal(start.match(/return \$null/g).length, 2);
  assert.match(start, /\$status -in @\(404, 503\)/);
  assert.match(start, /does not offer browser sign-in/);
  assert.match(start, /could not reach/);
  assert.match(start, /does not understand/);
  assert.doesNotMatch(start, /browser sign-in is not available from this site/);
});

test("the membership-key and prepared-link paths still work", () => {
  assert.match(CODE, /KRYONSEC_KEY/);
  assert.match(CODE, /KRYONSEC_LICENSE_KEY/);
  assert.match(CODE, /KRYONSEC_WHEEL/);
  assert.match(CODE, /X-Kryonsec-Key/);
  assert.match(CODE, /KRYONSEC_DOWNLOAD_URL/);
});
