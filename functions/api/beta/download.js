/**
 * GET /api/beta/download — the wheel, to anyone holding an active entitlement.
 *
 * This is the security boundary the brief calls the critical one, so the order
 * below is the design:
 *
 *   1. resolve the credential to a `user_id` — a website session cookie, a
 *      CLI bearer token, or a single-use download token, in that order
 *   2. ask `accessFor()` whether that user is entitled, which is the same
 *      function the dashboard and the license endpoint ask
 *   3. only then fetch bytes from GitHub
 *
 * Step 2 is not reimplemented here. A download gate with its own copy of the
 * access rules is a download gate that keeps serving after a revocation, which
 * is precisely the failure the brief warns about — so this file decides
 * nothing and borrows the one decision that exists.
 *
 * Refusals are honest about *which* thing failed without being useful to
 * someone probing: an unrecognised credential and an unrecognised user both
 * read as refused, and the reason a legitimate user sees is the one from
 * `accessFor` ("Access to this account has been revoked"), which tells them
 * something true without telling an attacker anything.
 *
 * GET, including for the single-use token, which is spent by the request that
 * presents it. That is a side effect on a GET and worth naming: the token's
 * only purpose is to be spent exactly once by an installer that can do nothing
 * else, and requiring a POST would mean changing install.sh — which is
 * published, pinned by tag, and running on members' machines today.
 *
 * Environment: KRYONSEC_DB (D1), KRYONSEC_GITHUB_TOKEN, KRYONSEC_REPO.
 */

import { currentSession, parseCookies, SESSION_COOKIE } from "../../_auth.js";
import { bearer, cliSessionFromToken, consumeDownloadToken } from "../../_cli.js";
import { latestWheel } from "../../_release.js";
import { esc, page } from "../../_shared.js";
import { accessFor } from "../../_store.js";

/** Who is asking, or null. Cheapest credential first, so a browser never
 *  touches the CLI tables and the CLI never touches the session table. */
async function resolveUser(db, request, url) {
  const cookie = parseCookies(request)[SESSION_COOKIE];
  if (cookie) {
    const session = await currentSession(db, request);
    if (session) return session.user.user_id;
  }

  const cli = await cliSessionFromToken(db, bearer(request));
  if (cli) return cli.userId;

  return consumeDownloadToken(db, url.searchParams.get("t"));
}

/**
 * A browser gets a page it can act on; a script gets a line it can print.
 *
 * The installer does `curl -f` and reports the HTTP status, so text is right
 * for it — an HTML body there would be shown to a member as a wall of markup.
 * A person whose access lapsed between loading the dashboard and clicking the
 * button deserves better than `403 revoked`. `Accept` is what distinguishes
 * them, and it costs one header read.
 */
function refuse(request, message, status) {
  const html = String(request.headers.get("Accept") || "").includes("text/html");
  if (!html) {
    return new Response(`${message}\n`, {
      status,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  return page(
    "Download unavailable",
    `                <div class="section-bar"><span>KR / DOWNLOAD</span><span>REFUSED</span></div>
                <h2>THAT DOWNLOAD<br><em>IS NOT AVAILABLE.</em></h2>
                <p class="form-static-note is-warn" role="alert">${esc(message)}</p>
                <p class="form-note">Your dashboard is the place to check what your account is currently entitled to.</p>
                <div class="form-actions">
                    <a class="button button-secondary" href="/dashboard">BACK TO THE DASHBOARD</a>
                </div>`,
    status,
  );
}

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  const url = new URL(request.url);

  const userId = await resolveUser(db, request, url);
  if (!userId) {
    return refuse(request, "Sign in on the website, or run `kryonsec login`, to download this.", 401);
  }

  const access = await accessFor(db, userId);
  if (!access.entitled) return refuse(request, access.reason, 403);

  const wheel = await latestWheel(env);
  if (!wheel.ok) return refuse(request, wheel.error, wheel.status);

  return wheel.response;
}
