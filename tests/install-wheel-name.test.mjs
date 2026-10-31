// node --test tests/install-wheel-name.test.mjs
//
// pip does not open the archive to decide what it is installing: it parses the
// filename first (name-version-python-abi-platform.whl) and refuses anything
// shaped differently with "Invalid wheel filename (wrong number of parts)".
// Both installers download to a temp file, so the name they save it under is
// part of the contract with the release server — and the answer is only ever
// known once the response headers are in hand.
//
// These run the real bash helper, not a copy of it: the function is lifted out
// of install.sh and executed, so a rename of the logic fails the test rather
// than silently passing a string match.

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const INSTALLER = readFileSync(new URL("../install.sh", import.meta.url), "utf8");

// Lift one shell function out of the script, braces included.
function shellFunction(name) {
  const start = INSTALLER.indexOf(`${name}() {`);
  if (start === -1) return null;
  const body = INSTALLER.slice(start);
  const end = body.indexOf("\n}\n");
  if (end === -1) return null;
  return body.slice(0, end + 3);
}

function bashAvailable() {
  try {
    execFileSync("bash", ["-c", "true"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

const haveBash = bashAvailable();
const FIXTURES = mkdtempSync(join(tmpdir(), "kryon-wheel-name-"));

// Run the real helper against one captured header file and return the path it
// chose. The fixture is a file rather than a quoted argument because a response
// header is full of quotes, semicolons and paths, and re-escaping all of that
// through a shell string tests the escaping instead of the helper.
function targetFor(headerLines) {
  const fn = shellFunction("wheel_target");
  assert.ok(fn, "install.sh must define wheel_target, the download's saved name");
  const standin = INSTALLER.match(/^WHEEL_NAME_STANDIN="([^"]+)"$/m);
  assert.ok(standin, "install.sh must define the stand-in name wheel_target falls back to");
  const headers = join(FIXTURES, `headers-${Math.random().toString(36).slice(2)}.txt`);
  writeFileSync(headers, headerLines.join("\n") + "\n");
  // Run the helper with the same constant the script gives it, so the fallback
  // is exercised as written rather than as the test imagines it.
  return execFileSync(
    "bash",
    ["-c", `${standin[0]}\n${fn}\nwheel_target /tmp/whatever '${headers}'`],
    { encoding: "utf8" },
  ).trim();
}

// The shape pip requires: five or more dash-separated parts, ending in .whl.
const PIP_ACCEPTS = /^[^-]+(-[^-]+){4,}\.whl$/;



test("the wheel is saved under the name the release advertises", { skip: !haveBash }, () => {
  const path = targetFor([
    "HTTP/1.1 200 OK",
    'content-disposition: attachment; filename="kryonsec-1.3.8-py3-none-any.whl"',
  ]);
  assert.equal(path, "/tmp/whatever/kryonsec-1.3.8-py3-none-any.whl");
  assert.match(path.split("/").pop(), PIP_ACCEPTS);
});

test("a release that names nothing still lands on a name pip accepts", { skip: !haveBash }, () => {
  // A proxy that strips Content-Disposition must not turn the install into a
  // pip error about a filename it cannot read.
  const path = targetFor(["HTTP/1.1 200 OK", "content-type: application/octet-stream"]);
  assert.match(path.split("/").pop(), PIP_ACCEPTS);
});

test("a filename from the network cannot pick a directory", { skip: !haveBash }, () => {
  for (const advertised of [
    'content-disposition: attachment; filename="/etc/kryonsec-1.3.8-py3-none-any.whl"',
    'content-disposition: attachment; filename="../../outside/kryonsec-1.3.8-py3-none-any.whl"',
  ]) {
    const path = targetFor(["HTTP/1.1 200 OK", advertised]);
    assert.equal(path, "/tmp/whatever/kryonsec-1.3.8-py3-none-any.whl", advertised);
  }
});

test("an advertised name that is not a wheel is not trusted", { skip: !haveBash }, () => {
  const path = targetFor([
    "HTTP/1.1 200 OK",
    'content-disposition: attachment; filename="payload.exe"',
  ]);
  assert.match(path.split("/").pop(), PIP_ACCEPTS);
});

test("an advertised name pip would refuse falls back, not through", { skip: !haveBash }, () => {
  // A server that calls its artifact kryonsec.whl is asking for the very pip
  // error this whole helper exists to avoid, so an unusable name is discarded
  // rather than passed on.
  const path = targetFor([
    "HTTP/1.1 200 OK",
    'content-disposition: attachment; filename="kryonsec.whl"',
  ]);
  assert.match(path.split("/").pop(), PIP_ACCEPTS);
});

test("every download is re-named before pip is handed it", () => {
  // The placeholder path a caller passes in is where the bytes land, not what
  // pip should install. One branch that forgets to pick up the stored name is
  // enough to reproduce the old kryonsec.whl failure, so every download has to
  // adopt it — which is why this counts calls rather than spot-checking one.
  const downloads = (INSTALLER.match(/^\s*download_wheel "\$WHEEL"/gm) ?? []).length;
  const pickedUp = (INSTALLER.match(/^\s*WHEEL="\$WHEEL_PATH"$/gm) ?? []).length;
  assert.ok(downloads > 0, "install.sh must download the release through download_wheel");
  assert.equal(pickedUp, downloads, "each download must adopt the name it was stored under");
  assert.match(INSTALLER, /"\$VENV\/bin\/pip" install --upgrade "\$WHEEL"/);
});

// ---- the same contract, in the Windows installer ---------------------------
// install.ps1 answers the same release with the same pip underneath, so it has
// to reach pip with the same kind of filename. These run the real PowerShell
// helper when PowerShell is on the machine and skip when it is not.

const POWERSHELL = readFileSync(new URL("../install.ps1", import.meta.url), "utf8");

function powershellAvailable() {
  try {
    execFileSync("powershell.exe", ["-NoProfile", "-Command", "1"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

const havePowerShell = powershellAvailable();

// Lift one PowerShell function out of the script by counting braces, so the
// test runs what the installer runs instead of a transcription of it.
function psFunction(name) {
  const start = POWERSHELL.indexOf(`function ${name}(`);
  if (start === -1) return null;
  let depth = 0;
  let begun = false;
  for (let i = start; i < POWERSHELL.length; i++) {
    const ch = POWERSHELL[i];
    if (ch === "{") { depth++; begun = true; }
    if (ch === "}") depth--;
    if (begun && depth === 0) return POWERSHELL.slice(start, i + 1);
  }
  return null;
}

function psTargetFor(contentDisposition) {
  const fn = psFunction("Get-WheelTarget");
  assert.ok(fn, "install.ps1 must define Get-WheelTarget, the download's saved name");
  const standin = POWERSHELL.match(/^\$WheelNameStandin = '([^']+)'$/m);
  assert.ok(standin, "install.ps1 must define the stand-in name Get-WheelTarget falls back to");
  const script = join(FIXTURES, `wheel-target-${Math.random().toString(36).slice(2)}.ps1`);
  // PowerShell has no backslash escapes: a header value full of quotes and
  // backslashes goes into a single-quoted literal, where only ' itself doubles.
  const psString = (value) => `'${value.replace(/'/g, "''")}'`;
  const fixture = contentDisposition === null
    ? "@{ 'X-Nothing' = @('1') }"
    : `@{ 'Content-Disposition' = @(${psString(contentDisposition)}) }`;
  writeFileSync(
    script,
    `$WheelNameStandin = '${standin[1]}'\n${fn}\n$h = ${fixture}\n(Get-WheelTarget 'C:\\tmp\\placeholder.whl' $h)\n`,
    "utf8",
  );
  return execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
    { encoding: "utf8" },
  ).trim();
}

test("the windows installer saves the name the release advertises", { skip: !havePowerShell }, () => {
  const quoted = psTargetFor('attachment; filename="kryonsec-1.3.8-py3-none-any.whl"');
  assert.equal(quoted, "kryonsec-1.3.8-py3-none-any.whl");
  assert.match(quoted, PIP_ACCEPTS);
  // Quoting a header parameter is optional, so an unquoted name is just as
  // much the release's name.
  const bare = psTargetFor("attachment; filename=kryonsec-1.3.8-py3-none-any.whl");
  assert.equal(bare, "kryonsec-1.3.8-py3-none-any.whl");
});

test("the windows installer names nothing at pip if the release does not", { skip: !havePowerShell }, () => {
  assert.match(psTargetFor(null), PIP_ACCEPTS);
});

test("the windows installer keeps a directory out of the name", { skip: !havePowerShell }, () => {
  const name = psTargetFor('attachment; filename="C:\\Users\\victim\\Downloads\\kryonsec-1.3.8-py3-none-any.whl"');
  assert.equal(name, "kryonsec-1.3.8-py3-none-any.whl");
});

test("the windows installer refuses a name pip cannot use", { skip: !havePowerShell }, () => {
  assert.match(psTargetFor('attachment; filename="kryonsec.whl"'), PIP_ACCEPTS);
  assert.match(psTargetFor('attachment; filename="payload.exe"'), PIP_ACCEPTS);
});

test("the windows installer hands pip the name it stored", () => {
  // Every invocation must adopt Download-Wheel's answer; the function
  // definition itself is not an invocation. One missed call is enough to reach
  // pip with a guid-named file it will refuse.
  const calls = (POWERSHELL.match(/^\s*(?!function).*Download-Wheel \$/gm) ?? []).length;
  const pickedUp = (POWERSHELL.match(/^\s*\$Wheel = Download-Wheel /gm) ?? []).length;
  assert.ok(calls > 0, "install.ps1 must download the release through Download-Wheel");
  assert.equal(pickedUp, calls, "each download must adopt the name it was stored under");
  assert.match(POWERSHELL, /& \$Pip install --upgrade \$Wheel/);
});

