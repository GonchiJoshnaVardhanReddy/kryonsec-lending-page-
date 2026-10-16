/**
 * POST /api/admin/action — every privileged write behind one guard.
 *
 * One route rather than four, and the reason is the guard. Session, then an
 * `admins` row, then a CSRF token, then a decision. Four routes would be four
 * chances to write that order differently, and the one that got it wrong would
 * be the one nobody re-read. Here there is a single `if` and it either passed
 * or the request stops.
 *
 * The CSRF check is not ceremony even though the cookie is SameSite=Lax: Lax
 * still sends the cookie on a top-level form POST from another site, which is
 * exactly the shape of an attack that makes an admin revoke the wrong account.
 *
 * Nothing an admin types is echoed anywhere. Failures come back as a word from
 * `OUTCOMES` in `../admin.js` and the page looks the sentence up, so a note
 * field cannot become a reflected payload on a page that holds a CSRF token.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { checkCsrf, currentSession, isAdminUser } from "../../_auth.js";
import { redirect } from "../../_shared.js";
import { decideApplication, grantEntitlement, revokeEntitlement, setProgrammeStatus } from "../../_store.js";

const STATUSES = ["pending", "approved", "waitlisted", "rejected", "all"];

const DECISIONS = { approve: "approve", reject: "reject", waitlist: "waitlist" };
const ACCESS_ACTIONS = { grant: "grant", revoke: "revoke", suspend: "suspend" };

/** Where to send the admin back to, and it is never a URL they supplied.
 *  A `next` parameter taken from a form is an open redirect waiting to happen,
 *  so this accepts a bare status word and builds the path itself. */
const backTo = (status, msg) =>
  `/admin?status=${STATUSES.includes(status) ? status : "pending"}&msg=${msg}`;

/** A `{ ok, error }` from `_store.js` means the write did not happen. `already`
 *  is its own outcome because "someone else decided this" is not an error — the
 *  guard in the UPDATE did its job and the admin should be told so plainly. */
const outcome = (result, ok) =>
  result.ok ? ok : /already/i.test(result.error || "") ? "already" : "missing";

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return new Response("No database.\n", { status: 500 });

  const session = await currentSession(db, request);
  if (!session) return redirect("/signin?next=%2Fadmin");
  if (!(await isAdminUser(db, session.user.user_id))) {
    // Not an admin. The same refusal whether the account exists or not — an
    // admin-only endpoint that answers differently for a real and a fake
    // account is a way to enumerate accounts.
    return new Response("Not found.\n", { status: 404 });
  }

  const form = await request.formData().catch(() => null);
  if (!form) return new Response("Bad submission.\n", { status: 400 });
  // `checkCsrf` answers with the reason it refused, or "" — so the test is
  // truthiness of a *message*, not of a pass. Asserting on `!` here would
  // refuse every honest request and admit every forged one.
  const csrfError = await checkCsrf(request, session, form);
  if (csrfError) return new Response(`${csrfError}\n`, { status: 403 });

  // Provider-asserted, and the audit table is read by people who need to know
  // who did this. `admins.email` is stored for the same reason.
  const actor = session.user.email || session.user.user_id;
  const status = form.get("back");

  switch (form.get("intent")) {
    case "decide": {
      const decision = DECISIONS[String(form.get("decision") || "")];
      if (!decision) return redirect(backTo(status, "invalid"));
      const result = await decideApplication(db, {
        applicationId: String(form.get("application") || ""),
        decision,
        actor,
        reason: form.get("reason"),
      });
      return redirect(backTo(status, outcome(result, "decided")));
    }

    case "access": {
      const action = ACCESS_ACTIONS[String(form.get("action") || "")];
      if (!action) return redirect(backTo(status, "invalid"));
      const userId = String(form.get("user") || "");
      const reason = form.get("reason");

      if (action === "grant") {
        return redirect(backTo(status, outcome(await grantEntitlement(db, { userId, actor, reason }), "granted")));
      }

      const result = await revokeEntitlement(db, {
        userId,
        actor,
        reason,
        status: action === "suspend" ? "suspended" : "revoked",
      });
      return redirect(backTo(status, outcome(result, action === "suspend" ? "suspended" : "revoked")));
    }

    case "programme":
      return redirect(
        backTo(status, outcome(await setProgrammeStatus(db, { status: String(form.get("status") || ""), actor }), "programme")),
      );

    default:
      return redirect(backTo(status, "invalid"));
  }
}
