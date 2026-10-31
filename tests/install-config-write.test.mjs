// node --test tests/install-config-write.test.mjs
//
// install.sh runs Python out of the wheel it just installed, and the wheel it
// installs is the one the release server publishes — not the CLI repository's
// working tree. Those two have drifted before: the published 1.3.8 wheel has no
// update_config_sections, so the installer's "remember the key" step raised
// ImportError, the script called it fatal, and an install that had already put
// kryonsec on the disk stopped before PATH, before the wizard, before doctor.
//
// So the config write has to work against the API the released wheel actually
// has. These run the real heredoc from install.sh against a stub of that API.
//
// The stub is deliberately built on tomllib and reproduces the published
// read_config contract exactly — "missing or unparseable reads as an empty
// config". That contract is the trap: writing back what it returned would
// replace a config the reader merely failed to parse with a file holding only
// the key, which is how a provider's API key and a workspace path disappear.

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const INSTALLER = readFileSync(new URL("../install.sh", import.meta.url), "utf8");

const POWERSHELL = readFileSync(new URL("../install.ps1", import.meta.url), "utf8");

const FIXTURES = mkdtempSync(join(tmpdir(), "kryon-config-write-"));

function pythonAvailable() {
  try {
    execFileSync("python3", ["-c", "pass"], { stdio: "pipe" });
    return "python3";
  } catch {
    try {
      execFileSync("python", ["-c", "pass"], { stdio: "pipe" });
      return "python";
    } catch {
      return null;
    }
  }
}

const PY = pythonAvailable();

// The config-writing heredoc, lifted out of install.sh rather than retyped: the
// point is that the shipped script is the thing under test.
function configWriteSnippet(marker) {
  const blocks = INSTALLER.split("<<'PY'\n").slice(1);
  const block = blocks.find((b) => b.includes(marker));
  assert.ok(block, `install.sh must contain a config write mentioning ${marker}`);
  return block.split("\nPY\n")[0];
}

// A stub of the kryonsec package, shaped like one of the two releases the
// installer can land on: the published one, whose config module offers
// config_path/read_config/write_config and nothing else, and the newer one that
// also offers the guarded section writer.
function stubPackage({ withSectionWriter }) {
  const root = mkdtempSync(join(FIXTURES, `pkg-${Math.random().toString(36).slice(2)}-`));
  const pkg = join(root, "kryonsec");
  mkdirSync(pkg, { recursive: true });
  writeFileSync(join(pkg, "__init__.py"), "", "utf8");
  const config = [
    "import json",
    "import os",
    "import tomllib",
    "from pathlib import Path",
    "",
    "def _scalar(value):",
    "    if isinstance(value, bool):",
    "        return 'true' if value else 'false'",
    "    if isinstance(value, (int, float)):",
    "        return str(value)",
    "    return '\"' + str(value) + '\"'",
    "",
    "def config_path(home=None):",
    "    return Path(os.environ['KRYONSEC_TEST_CONFIG'])",
    "",
    "def read_config(path):",
    "    if not path.is_file():",
    "        return {}",
    "    try:",
    "        return tomllib.loads(path.read_text(encoding='utf-8'))",
    "    except (tomllib.TOMLDecodeError, OSError):",
    "        return {}",
    "",
    "def write_config(path, data):",
    "    lines = []",
    "    for key, value in data.items():",
    "        if not isinstance(value, dict):",
    "            lines.append(f'{key} = {_scalar(value)}')",
    "    for key, value in data.items():",
    "        if not isinstance(value, dict):",
    "            continue",
    "        lines.append('')",
    "        lines.append(f'[{key}]')",
    "        for inner, v in value.items():",
    "            if isinstance(v, dict):",
    "                raise TypeError('nested table')",
    "            lines.append(f'{inner} = {_scalar(v)}')",
    "    path.parent.mkdir(parents=True, exist_ok=True)",
    "    path.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')",
    "    return path",
    "",
  ];
  if (withSectionWriter) {
    config.push(
      "def update_config_sections(path, updates):",
      "    error = config_file_error(path)",
      "    if error:",
      "        raise ValueError(error)",
      "    Path(str(path) + '.sections').write_text(json.dumps(updates))",
      "    return path",
      "",
      "def config_file_error(path):",
      "    if not path.is_file():",
      "        return None",
      "    try:",
      "        tomllib.loads(path.read_text(encoding='utf-8'))",
      "    except tomllib.TOMLDecodeError as exc:",
      "        return f'invalid TOML ({exc})'",
      "    return None",
      "",
    );
  }
  writeFileSync(join(pkg, "config.py"), config.join("\n"), "utf8");
  return root;
}

function readBack(config, root) {
  if (!existsSync(config)) return null;
  try {
    const out = execFileSync(
      PY,
      ["-c", "import json, os; from pathlib import Path; " +
        "from kryonsec.config import read_config; " +
        "print(json.dumps(read_config(Path(os.environ['KRYONSEC_TEST_CONFIG']))))"],
      {
        encoding: "utf8",
        env: { ...process.env, PYTHONPATH: root, KRYONSEC_TEST_CONFIG: config },
      },
    );
    return JSON.parse(out);
  } catch {
    return null;
  }
}

function runSnippet(snippet, { withSectionWriter }, argv, { seed } = {}) {
  const config = join(FIXTURES, `config-${Math.random().toString(36).slice(2)}.toml`);
  const root = stubPackage({ withSectionWriter });
  if (seed !== undefined) writeFileSync(config, seed, "utf8");
  const before = seed;
  let result;
  try {
    const out = execFileSync(PY, ["-c", snippet, ...argv], {
      encoding: "utf8",
      env: { ...process.env, PYTHONPATH: root, KRYONSEC_TEST_CONFIG: config },
    });
    result = { code: 0, out };
  } catch (error) {
    result = { code: error.status, out: error.stdout || "", err: error.stderr || "" };
  }
  return {
    ...result,
    saved: readBack(config, root),
    config,
    root,
    before,
    // The newer section writer is a stub that records its argument instead of
    // producing a config, so the file can legitimately still be missing here.
    after: existsSync(config) ? readFileSync(config, "utf8") : null,
  };
}

const KEY_SNIPPET = () => configWriteSnippet('"license", {}).get("key")');
const DIGEST_SNIPPET = () => configWriteSnippet('"sandbox", {}).get("image")');

const CORRUPT = "provider = [ this is not toml at all\n";

test("the key is remembered by the wheel that is actually published", { skip: !PY }, () => {
  // 1.3.8: config_path, read_config and write_config, and nothing else.
  const run = runSnippet(KEY_SNIPPET(), { withSectionWriter: false }, ["KRYO-AB2C-DE3F-GH4J"]);
  assert.equal(run.code, 0, `the published API must be enough: ${run.err}`);
  assert.deepEqual(run.saved, { license: { key: "KRYO-AB2C-DE3F-GH4J" } });
});

test("the newer section writer is still preferred when it exists", { skip: !PY }, () => {
  const run = runSnippet(KEY_SNIPPET(), { withSectionWriter: true }, ["KRYO-AB2C-DE3F-GH4J"]);
  assert.equal(run.code, 0, run.err);
  assert.match(readFileSync(`${run.config}.sections`, "utf8"), /KRYO-AB2C-DE3F-GH4J/);
});

test("a key that is already present is not rewritten", { skip: !PY }, () => {
  const first = runSnippet(KEY_SNIPPET(), { withSectionWriter: false }, ["KRYO-AB2C-DE3F-GH4J"]);
  assert.equal(first.code, 0, first.err);
  const again = runSnippet(
    KEY_SNIPPET(),
    { withSectionWriter: false },
    ["KRYO-AB2C-DE3F-GH4J"],
    { seed: first.after },
  );
  assert.equal(again.code, 0, again.err);
  assert.match(again.out, /already present/);
  assert.deepEqual(again.saved, { license: { key: "KRYO-AB2C-DE3F-GH4J" } });
});

test("an existing configuration keeps its own settings alongside the key", { skip: !PY }, () => {
  // The fallback writes the whole file from what read_config returned, so
  // everything already in it has to survive the round trip — losing a provider
  // API key while saving a membership key is not an upgrade.
  const run = runSnippet(KEY_SNIPPET(), { withSectionWriter: false }, ["KRYO-AB2C-DE3F-GH4J"], {
    seed: '[provider]\nname = "openai"\n\n[sandbox]\nimage = "ghcr.io/kryonsec/sandbox@sha256:bbbb"\n',
  });
  assert.equal(run.code, 0, run.err);
  assert.deepEqual(run.saved, {
    provider: { name: "openai" },
    sandbox: { image: "ghcr.io/kryonsec/sandbox@sha256:bbbb" },
    license: { key: "KRYO-AB2C-DE3F-GH4J" },
  });
});

test("a config the published reader cannot parse is left exactly as it was", { skip: !PY }, () => {
  // read_config reports an unparseable file as an empty config. A writer that
  // takes that at its word deletes the user's settings and leaves only the key,
  // so the fallback has to re-read the bytes and refuse instead.
  const run = runSnippet(KEY_SNIPPET(), { withSectionWriter: false }, ["KRYO-AB2C-DE3F-GH4J"], {
    seed: CORRUPT,
  });
  assert.notEqual(run.code, 0, "a corrupt config must stop the write, not be replaced");
  assert.equal(run.after, CORRUPT, `the file was overwritten: ${run.after}`);
});

test("remembering the key cannot abort the installation", () => {
  // The app installs first; a config write that still fails is a warning the
  // member can act on, not a reason to stop before PATH and the wizard.
  const block = INSTALLER.slice(
    INSTALLER.indexOf('if [ -n "$KEY" ]; then', INSTALLER.indexOf("# Remember the key.")),
  );
  const fatal = block.split("\n# ")[0];
  assert.doesNotMatch(fatal, /\bdie\b/, "the key step must not call die");
});

test("the verified sandbox digest is saved by the published wheel too", { skip: !PY }, () => {
  // Purple Team cannot start without the digest it verified, so this write goes
  // through the same two-API seam — and here a failure stays fatal.
  const digest = "ghcr.io/kryonsec/sandbox@sha256:aaaa";
  const run = runSnippet(DIGEST_SNIPPET(), { withSectionWriter: false }, [digest]);
  assert.equal(run.code, 0, `the published API must be enough: ${run.err}`);
  assert.deepEqual(run.saved, { sandbox: { image: digest } });
});

test("the sandbox digest write refuses a corrupt config as well", { skip: !PY }, () => {
  const digest = "ghcr.io/kryonsec/sandbox@sha256:aaaa";
  const run = runSnippet(DIGEST_SNIPPET(), { withSectionWriter: false }, [digest], { seed: CORRUPT });
  assert.notEqual(run.code, 0, "a corrupt config must stop the write, not be replaced");
  assert.equal(run.after, CORRUPT, `the file was overwritten: ${run.after}`);
});

test("the windows installer writes config through the same seam", () => {
  const block = POWERSHELL.slice(
    POWERSHELL.indexOf("$saveKey = @'"),
    POWERSHELL.indexOf("'@", POWERSHELL.indexOf("$saveKey = @'")),
  );
  assert.ok(block.length > 0, "install.ps1 must remember the key in config");
  assert.match(block, /except ImportError:/, "the missing section writer must not be fatal");
  assert.match(block, /write_config\(path, data\)/);
  assert.match(
    block,
    /tomllib/,
    "the fallback must re-read the config it is about to replace, as install.sh does",
  );
});

