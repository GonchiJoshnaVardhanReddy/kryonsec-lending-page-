/**
 * POST /api/beta/device/approve   (an ordinary HTML form post)
 *
 * The moment a human says yes. Everything before this was the CLI asking a
 * question; this is the answer, and it is the only place in the flow where a
 * person's authority enters.
 *
 * Three things are required together and the order matters:
 *
 *   1. a session — so the answer is attributable to an account
 *   2. the `admins`-free `accessFor()` on that account, at decision time, so
 *      somebody whose access was revoked last week cannot approve their own
 *      machine in
 *   3. a CSRF token, because this is a state change a cross-site form could
 *      otherwise make on a signed-in person's behalf
 *
 * The four-eyes property the brief asks for holds without any extra
 * machinery: the account that approves is the account the token is issued
 * for, and the CLI has no way to approve itself. A stolen code is a code
 * someone has to be signed in to use, and using it puts a machine on their
 * own account.
 *
 * Approval does not mint the token — see poll.js. It records who said yes and
 * leaves the code to be collected once.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { checkCsrf, currentSession } from "../../../_auth.js";
import { CODE_TTL_MIN, cleanCode, esc, isoAgo, nowIso, page, redirect } from "../../../_shared.js";
import { accessFor } from "../../../_store.js";

/** Back to the page that asked, with a reason code. Codes, not sentences:
 *  nothing the person typed is reflected, and the words live in device.js. */
const back = (request, code, reason) => {
  const params = new URLSearchParams();
  if (code) params.set("code", code);
  params.set("e", reason);
  return redirect(`/beta/device?${params}`);
};

function refused(message, status) {
  return page(
    "Sign-in not approved",
    `                <div class="section-bar"><span>KR / DEVICE</span><span>REFUSED</span></div>
                <h2>THAT SIGN-IN<br><em>WAS NOT APPROVED.</em></h2>
                <p class="form-static-note is-warn" role="alert">${esc(message)}</p>
                <div class="form-actions"><a class="button button-secondary" href="/dashboard">BACK TO THE DASHBOARD</a></div>`,
    status,
  );
}

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return refused("Sign-in is not configured on this site yet.", 503);

  const session = await currentSession(db, request);
  if (!session) return redirect(`/signin?next=${encodeURIComponent("/dashboard")}`);

  const form = await request.formData().catch(() => null);
  if (!form) return refused("That submission could not be read.", 400);
  const csrfError = await checkCsrf(request, session, form);
  if (csrfError) return refused(csrfError, 403);

  const code = cleanCode(form.get("code"));
  if (!code) return refused("That sign-in code is missing. Start `kryonsec login` again.", 400);

  const userId = session.user.user_id;
  const email = session.user.email || "";

  // Approving is an act of an entitled account, checked here and not only
  // when the dashboard was rendered. A page loaded before a revocation, or a
  // form kept in a tab, must not be able to finish the job afterwards.
  const access = await accessFor(db, userId);
  if (!access.entitled) {
    return refused(`This account cannot approve a sign-in: ${access.reason}`, 403);
  }

  const now = nowIso();

  if (String(form.get("decision") || "") === "deny") {
    const denied = await db
      .prepare(
        `UPDATE cli_login_codes SET denied_at = ?, email = ?
          WHERE code = ? AND approved_at IS NULL AND denied_at IS NULL AND created_at > ?`,
      )
      .bind(now, email, code, isoAgo(CODE_TTL_MIN))
      .run();
    // A code that was already decided, or has expired, reports the same way —
    // there is nothing useful to tell apart, and "expired" and "already used"
    // are both "run it again".
    return back(request, code, denied.meta?.changes === 1 ? "denied" : "stale");
  }

  // The guarded UPDATE is the whole concurrency story: `approved_at IS NULL`
  // means a second click, a second tab, or a replayed form cannot overwrite
  // who approved this or move the moment it happened. It returns no row when
  // it loses, and losing is reported rather than retried.
  const approved = await db
    .prepare(
      `UPDATE cli_login_codes SET approved_at = ?, approved_by = ?, email = ?
        WHERE code = ? AND approved_at IS NULL AND denied_at IS NULL AND created_at > ?`,
    )
    .bind(now, userId, email, code, isoAgo(CODE_TTL_MIN))
    .run();

  if (approved.meta?.changes !== 1) return back(request, code, "stale");

  return back(request, code, "approved");
}
