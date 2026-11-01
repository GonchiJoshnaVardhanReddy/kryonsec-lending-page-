/**
 * POST /api/beta/machines   {id, intent=revoke, csrf}   (an HTML form post)
 *
 * "Sign that machine out." The dashboard's half of revocation — the browser
 * reaches it with a session cookie, where the CLI reaches the mirror of this
 * route with the token itself (api/beta/cli/logout.js).
 *
 * Four things are required, and the order is the guard:
 *
 *   1. a session, so the act is attributable
 *   2. a CSRF token, because this is a state change a cross-site form could
 *      otherwise make on a signed-in person's behalf
 *   3. the id from the form, but scoped to the session's own user id inside
 *      the UPDATE — so a tampered or guessed id matches no row. This is the
 *      broken-object-level-authorisation case, and the fix is to make the
 *      ownership check part of the same statement as the write rather than a
 *      read that precedes it.
 *   4. no entitlement check, deliberately. Revoking is never a way to gain
 *      anything, and an account whose access was revoked this morning must
 *      still be able to turn off a machine it signed in last week.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { checkCsrf, currentSession } from "../../_auth.js";
import { revokeCliSession } from "../../_cli.js";
import { cleanText, redirect } from "../../_shared.js";

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return new Response("Not configured.\n", { status: 503 });

  const session = await currentSession(db, request);
  if (!session) return redirect("/signin?next=%2Fdashboard");

  const form = await request.formData().catch(() => null);
  if (!form) return new Response("Bad submission.\n", { status: 400 });
  const csrfError = await checkCsrf(request, session, form);
  if (csrfError) return new Response(`${csrfError}\n`, { status: 403 });

  // The id is an opaque `s_…` minted by newId(). Bounded here so a long body
  // cannot reach the query, and trusted for nothing else — the UPDATE's
  // `user_id = ?` is what decides whether it means anything.
  const id = cleanText(form.get("id"), 64);

  await revokeCliSession(db, {
    id,
    actor: "dashboard",
    reason: "signed out from the dashboard",
    userId: session.user.user_id,
  });

  // No outcome to report either way. A revoke that matched nothing is
  // indistinguishable from one that worked, and saying which would let this
  // form be used to test whether a given session id exists.
  return redirect("/dashboard#machines");
}
