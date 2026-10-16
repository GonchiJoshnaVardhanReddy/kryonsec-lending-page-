/**
 * Fetch the current wheel from GitHub Releases.
 *
 * Import-only: never served.
 *
 * Extracted from api/download.js when the beta path needed the same bytes.
 * This is worth a file of its own because of one non-obvious line: the asset
 * URL from the releases API answers with the asset's JSON *metadata* unless
 * the request carries `Accept: application/octet-stream`. Without that header
 * the installer is handed a JSON file named `kryonsec-1.3.7-py3-none-any.whl`
 * and pip fails with a parse error that says nothing about the real cause. A
 * second copy of this function is a second chance to omit it.
 *
 * The PAT is read from the environment and never leaves this process. It needs
 * Contents: Read on one repository and nothing else — it is the credential
 * that guards the product, so it is scoped to the product and nothing more.
 */

const DEFAULT_REPO = "GonchiJoshnaVardhanReddy/kryon-sec";

/**
 * The latest release's wheel, as a streamable response ready to hand back.
 *
 * Returns `{ ok: true, response }`, or `{ ok: false, status, error }` for the
 * caller to phrase in whatever shape its own consumers read. Anything that is
 * not the caller's fault is a 502: the installers distinguish "your credential
 * was refused" (403) from "the site is broken" (5xx) and tell the user which.
 */
export async function latestWheel(env) {
  const token = env.KRYONSEC_GITHUB_TOKEN;
  if (!token) return { ok: false, status: 502, error: "download is not configured" };

  const repo = env.KRYONSEC_REPO || DEFAULT_REPO;
  const ghHeaders = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "kryonsec-download",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  // One lookup per request. The release is a handful of JSON fields and the
  // result is never cached, but a download happens rarely enough that caching
  // it would be premature.
  const releaseRes = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
    headers: ghHeaders,
  });
  if (!releaseRes.ok) return { ok: false, status: 502, error: "could not read the latest release" };

  const release = await releaseRes.json();
  const asset = (release.assets || []).find(
    (a) => typeof a.name === "string" && a.name.endsWith(".whl"),
  );
  if (!asset) return { ok: false, status: 502, error: "the latest release has no wheel" };

  const assetRes = await fetch(asset.url, {
    headers: { ...ghHeaders, Accept: "application/octet-stream" },
    redirect: "follow",
  });
  if (!assetRes.ok) return { ok: false, status: 502, error: "could not fetch the wheel" };

  return {
    ok: true,
    // no-store: this body is gated by a credential, and a shared cache holding
    // it would hand the wheel to the next caller regardless of theirs.
    response: new Response(assetRes.body, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${asset.name}"`,
        "Cache-Control": "no-store",
      },
    }),
  };
}
