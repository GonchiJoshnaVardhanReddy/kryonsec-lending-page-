/**
 * POST /api/admin/action — every privileged write behind one guard.
 *
 * One route rather than several, and the reason is the guard. Session, then an
 * `admins` row, then a CSRF token, then a decision. Separate routes would be
 * separate chances to write that order differently, and the one that got it
 * wrong would be the one nobody re-read. Here there is a single `if` and it
 * either passed or the request stops.
 *
 * The CSRF check is not ceremony even though the cookie is SameSite=Lax: Lax
 * still sends the cookie on a top-level form POST from another site, which is
 * exactly the shape of an attack that makes an admin revoke the wrong account.
 *
 * Failures are recorded too. A refused non-admin attempt, a stale CSRF token,
 * and an unrecognised decision each leave an `admin.*` row naming the account
 * and the attempted action — never a token, a cookie, or a provider response.
 * Repeated failures are throttled per account before a row is written, so the
 * log cannot be grown without bound by one caller.
 *
 * Nothing an admin types is echoed anywhere. Failures come back as a word from
 * `OUTCOMES` in `../admin.js` and the page looks the sentence up, so a note
 * field cannot become a reflected payload on a page that holds a CSRF token.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { audit, checkCsrf, currentSession, isAdminUser } from "../../_auth.js";
import { revokeCliSession } from "../../_cli.js";
import { redirect } from "../../_shared.js";
import {
  decideApplication,
  grantEntitlement,
  revokeEntitlement,
  revokeWebsiteSession,
  setProgrammeStatus,
  USER_ID_RE,
} from "../../_store.js";

const STATUSES = ["pending", "approved", "waitlisted", "rejected", "all"];
const VIEWS = ["overview", "applications", "activity", "users", "devices", "security", "user"];

const DECISIONS = { approve: "approve", reject: "reject", waitlist: "waitlist" };
const ACCESS_ACTIONS = { grant: "grant", revoke: "revoke", suspend: "suspend" };

const SESSION_ROW_RE = /^s_[0-9a-f]{32}$/;
const TOKEN_HASH_RE = /^[0-9a-f]{64}$/;

const FAIL_ACTIONS = ["admin.denied", "admin.csrf_refused", "admin.invalid", "admin.throttled"];
const FAIL_LIMIT = 25;
const FAIL_WINDOW_MIN = 10;

/** Where to send the admin back to, and it is never a URL they supplied.
 *  A `next` parameter taken from a form is an open redirect waiting to happen,
 *  so this accepts a bare status word and builds the path itself. */
const backTo = (status, msg) =>
  `/admin?status=${STATUSES.includes(status) ? status : "pending"}&msg=${msg}`;

/** The same rule for the sectioned views: a whitelisted view name, a validated
 *  id, and a message code. Nothing else from the form reaches `Location`. */
function backToView(view, msg, id = "") {
  const search = new URLSearchParams({ view: VIEWS.includes(view) ? view : "overview" });
  if (view === "user" && USER_ID_RE.test(String(id || ""))) search.set("id", id);
  search.set("msg", msg);
  return `/admin?${search}`;
}

/** A `{ ok, error }` from `_store.js` means the write did not happen. `already`
 *  is its own outcome because "someone else decided this" is not an error — the
 *  guard in the UPDATE did its job and the admin should be told so plainly. */
const outcome = (result, ok) =>
  result.ok ? ok : /already/i.test(result.error || "") ? "already" : "missing";

/** A short, safe word for the audit row. An unrecognised intent is arbitrary
 *  caller text and is not copied into the log. */
const intentWord = (value) => {
  const word = String(value || "").toLowerCase();
  return /^[a-z_]{1,32}$/.test(word) ? word : "unrecognised";
};

/**
 * Count a caller's recent refusals.
 *
 * `actor` is an email for a signed-in admin and a user id for a signed-in
 * non-admin — both stable, neither a credential. Failed requests are counted
 * across all four refusal actions, so switching the shape of the attempt does
 * not reset the budget.
 */
async function recentFailures(db, actor) {
  const since = new Date(Date.now() - FAIL_WINDOW_MIN * 60_000).toISOString();
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM admin_audit
        WHERE actor = ? AND created_at > ?
          AND action IN (?, ?, ?, ?)`,
    )
    .bind(actor, since, ...FAIL_ACTIONS)
    .first();
  return Number(row?.n || 0);
}

async function logFailure(db, { actor, action, target }) {
  await audit(db, { actor, action, target: String(target || "").slice(0, 80), before: null, after: null });
}

/** Too many refusals. No row is written for the throttled request itself —
 *  writing one per refused request is exactly the unbounded growth the budget
 *  exists to stop. */
const tooMany = () => new Response("Too many refused attempts. Try again later.\n", { status: 429 });

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return new Response("No database.\n", { status: 500 });

  const session = await currentSession(db, request);
  if (!session) return redirect("/signin?next=%2Fadmin");

  const form = await request.formData().catch(() => null);
  if (!form) return new Response("Bad submission.\n", { status: 400 });

  // Provider-asserted, and the audit table is read by people who need to know
  // who did this. `admins.email` is stored for the same reason.
  const actor = session.user.email || session.user.user_id;

  if (!(await isAdminUser(db, session.user.user_id))) {
    // Not an admin. The same refusal whether the account exists or not — an
    // admin-only endpoint that answers differently for a real and a fake
    // account is a way to enumerate accounts. The attempt is recorded against
    // the signed-in user id, not against any credential.
    if ((await recentFailures(db, actor)) >= FAIL_LIMIT) return tooMany();
    await logFailure(db, { actor, action: "admin.denied", target: intentWord(form.get("intent")) });
    return new Response("Not found.\n", { status: 404 });
  }

  // `checkCsrf` answers with the reason it refused, or "" — so the test is
  // truthiness of a *message*, not of a pass. Asserting on `!` here would
  // refuse every honest request and admit every forged one.
  const csrfError = await checkCsrf(request, session, form);
  if (csrfError) {
    if ((await recentFailures(db, actor)) >= FAIL_LIMIT) return tooMany();
    await logFailure(db, { actor, action: "admin.csrf_refused", target: intentWord(form.get("intent")) });
    return new Response(`${csrfError}\n`, { status: 403 });
  }

  const status = form.get("back");

  const invalid = async (why) => {
    if ((await recentFailures(db, actor)) >= FAIL_LIMIT) return tooMany();
    await logFailure(db, { actor, action: "admin.invalid", target: intentWord(why) });
    return redirect(backTo(status, "invalid"));
  };

  switch (form.get("intent")) {
    case "decide": {
      const decision = DECISIONS[String(form.get("decision") || "")];
      if (!decision) return invalid("decide");
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
      if (!action) return invalid("access");
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

    // --- credential revocation ------------------------------------------

    case "session": {
      // One action today, and an unknown one is refused rather than treated
      // as revoke: a typo in a destructive control must fail closed.
      if (String(form.get("action") || "") !== "revoke") return invalid("session");
      const userId = String(form.get("user") || "");
      const tokenHash = String(form.get("token") || "");
      if (!USER_ID_RE.test(userId) || !TOKEN_HASH_RE.test(tokenHash)) return invalid("session");

      const result = await revokeWebsiteSession(db, { tokenHash, userId, actor });
      return redirect(backToView("user", result.ok ? "session_revoked" : "missing", userId));
    }

    case "cli": {
      if (String(form.get("action") || "") !== "revoke") return invalid("cli");
      const id = String(form.get("id") || "");
      if (!SESSION_ROW_RE.test(id)) return invalid("cli");

      // `user` is present when the request came from an account page. It
      // scopes the UPDATE to that account's row, so a tampered id matches
      // nothing. The devices view sends no user id and relies on the admin
      // privilege itself — and the audit row says which shape it was.
      const asked = String(form.get("user") || "");
      const userId = USER_ID_RE.test(asked) ? asked : null;

      const revoked = await revokeCliSession(db, {
        id,
        actor,
        reason: "revoked from the admin dashboard",
        userId,
      });
      await audit(db, {
        actor,
        action: revoked ? "cli_session.revoked" : "cli_session.revoke_missed",
        target: userId || id,
        before: null,
        after: { revoked },
      });
      return redirect(userId ? backToView("user", revoked ? "cli_revoked" : "missing", userId) : backToView("devices", revoked ? "cli_revoked" : "missing"));
    }

    default:
      return invalid("unrecognised");
  }
}
