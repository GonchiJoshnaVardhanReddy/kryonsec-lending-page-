/**
 * POST /api/beta/cli/logout   (Authorization: Bearer s_…)
 *
 * The other half of `kryonsec logout`. It revokes exactly one thing: the
 * token that was presented. No session, no admin, no CSRF token — the
 * credential *is* the authorisation, and it authorises only its own removal.
 *
 * That is narrower than it looks, and deliberately so:
 *
 *   - the caller cannot name a session to revoke. There is no id in the body,
 *     so there is no id to tamper with, and no way to revoke somebody else's
 *     machine by guessing one.
 *   - an unknown, expired, already-revoked, or malformed token revokes
 *     nothing and returns the same answer, so this endpoint cannot be used to
 *     ask whether a given token was ever real.
 *
 * A revoked token stops working immediately, because `cliSessionFromToken`
 * filters on `revoked_at IS NULL` in the query itself rather than after it —
 * the same route that feeds the download gate and the license check.
 *
 * An already-dead token is not an error. `logout` should be idempotent: a
 * person running it twice, or on a machine whose token expired months ago,
 * wants it gone, and it is.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { bearer, cliSessionFromToken, revokeCliSession } from "../../../_cli.js";
import { json } from "../../../_shared.js";

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return json({ ok: false, reason: "sign-in is not configured" }, 503);

  const cli = await cliSessionFromToken(db, bearer(request));
  // Nothing to revoke, or nothing that was ever ours. The CLI deletes its
  // local copy either way, so there is no state left to disagree about.
  if (!cli) return json({ ok: true, revoked: false });

  const revoked = await revokeCliSession(db, { id: cli.id, actor: "cli logout" });
  return json({ ok: true, revoked });
}
