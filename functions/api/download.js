/**
 * GET /api/download?os=linux
 *
 * The download gate for closed-source Kryonsec. install.sh and install.ps1
 * both call this with the member's key and pipe the response straight into
 * pip, so the body must be the wheel itself — never a JSON envelope, never an
 * HTML page, and never a 200 on a rejection.
 *
 *   valid key   -> 200, application/octet-stream, the wheel
 *   bad key     -> 403 (script reports the key was refused)
 *   key missing -> 400
 *   upstream    -> 502 (script reports the site was unreachable)
 *
 * The membership key is accepted in X-Kryonsec-Key.  The old query parameter
 * remains a compatibility path for older installers, but new installers never
 * put the key in a URL.
 *
 * A Cloudflare Pages Function rather than a webhook service: it deploys with
 * the site, costs nothing at this volume, and the secrets below stay on
 * Cloudflare's side instead of in a third party.
 *
 * Environment (Pages -> Settings -> Environment variables, all encrypted):
 *   KRYONSEC_KEYS          comma-separated membership keys
 *   KRYONSEC_GITHUB_TOKEN  fine-grained PAT, Contents: Read on the repo only
 *   KRYONSEC_REPO          optional, defaults to the repo below
 */

const DEFAULT_REPO = "GonchiJoshnaVardhanReddy/kryon-sec";

// Crockford base32, minus 0/O and 1/I — the same alphabet as the app's
// license.py. A key the app accepts has to be a key this endpoint accepts, or
// a member gets a wheel they cannot activate.
const KEY_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const KEY_RE = new RegExp(
  `^KRYO-[${KEY_ALPHABET}]{4}(?:-[${KEY_ALPHABET}]{4}){2}$`,
);

export function isWellFormedKey(key) {
  return KEY_RE.test(key);
}

/**
 * Compare without leaking where the first difference is.
 *
 * Keys are fixed-length, so the early length check leaks nothing useful.
 * Without this, a string compare returns as soon as two characters differ,
 * which turns "is this a valid key" into a slow oracle over many requests.
 */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Is this key on the allowlist? Missing/empty config denies everyone. */
export function isAllowed(key, allowlist) {
  const keys = String(allowlist || "")
    .split(",")
    .map((k) => k.trim().toUpperCase())
    .filter(Boolean);
  // ponytail: short-circuits on the first match, so a timing signal could
  // reveal a key's position in the list. Irrelevant at this list size — move
  // to a KV lookup if the list ever grows past a few hundred.
  return keys.some((candidate) => timingSafeEqual(candidate, key));
}

function reject(message, status) {
  // Plain text: curl -f only needs a non-2xx status, and the installer prints
  // its own sentence — but a human hitting this in a browser should still
  // read something true.
  return new Response(`${message}\n`, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const headerKey = request.headers.get("X-Kryonsec-Key") || "";
  const queryKey = url.searchParams.get("key") || "";
  const key = (headerKey || queryKey)
    .trim()
    .toUpperCase();

  if (!key) return reject("missing key", 400);
  if (!isWellFormedKey(key)) return reject("malformed key", 403);
  if (!isAllowed(key, env.KRYONSEC_KEYS)) return reject("key not recognised", 403);

  const token = env.KRYONSEC_GITHUB_TOKEN;
  if (!token) {
    // Config error, not the member's fault — 502 so the installer blames the
    // site (and says so) rather than telling a paying member their key is bad.
    return reject("download is not configured", 502);
  }

  const repo = env.KRYONSEC_REPO || DEFAULT_REPO;
  const ghHeaders = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "kryonsec-download",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  // One lookup per request. A release is a handful of JSON fields and Cloudflare
  // caches nothing here because the response is no-store, but members install
  // rarely — caching this would be premature.
  const releaseRes = await fetch(
    `https://api.github.com/repos/${repo}/releases/latest`,
    { headers: ghHeaders },
  );
  if (!releaseRes.ok) return reject("could not read the latest release", 502);

  const release = await releaseRes.json();
  const asset = (release.assets || []).find(
    (a) => typeof a.name === "string" && a.name.endsWith(".whl"),
  );
  if (!asset) return reject("the latest release has no wheel", 502);

  // The asset URL from the API needs the octet-stream Accept header to return
  // bytes; without it GitHub answers with the asset's JSON metadata, and pip
  // would be handed a JSON file named .whl.
  const assetRes = await fetch(asset.url, {
    headers: { ...ghHeaders, Accept: "application/octet-stream" },
    redirect: "follow",
  });
  if (!assetRes.ok) return reject("could not fetch the wheel", 502);

  const bytes = await assetRes.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sha256 = Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  return new Response(bytes, {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${asset.name}"`,
      "X-Kryonsec-Wheel-SHA256": sha256,
      // no-store: this response is gated by a key, and a shared cache holding
      // it would hand the wheel to the next caller regardless of their key.
      "Cache-Control": "no-store",
    },
  });
}
