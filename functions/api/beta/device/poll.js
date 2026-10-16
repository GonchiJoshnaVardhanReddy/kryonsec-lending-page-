/**
 * POST /api/beta/device/poll   {device_code}
 *
 * Step 3 of `kryonsec login`, and the only one the CLI repeats.
 *
 *   -> {status: "pending"}                              keep waiting
 *   -> {status: "approved", token: "s_…", email: "…"}    done, store it
 *   -> {status: "denied"}                               the person said no
 *   -> {status: "expired"} / {status: "unknown"}        start over
 *
 * The token is minted *here*, at collection, rather than when the person
 * clicked approve. That ordering is deliberate: a login somebody approved and
 * then walked away from leaves no credential in the database at all, where
 * minting at approval time would leave a live ninety-day token waiting for a
 * terminal that never came back. The row is deleted in the same request that
 * hands the token over, so there is exactly one collection and it happens
 * once.
 *
 * The consequence, stated plainly: whoever presents this device_code collects
 * the token. That is the standard device-authorization model, and it is safe
 * only because the device_code is 256 random bits that were never displayed,
 * never put in the URL, and never sent anywhere but here. The short code the
 * person reads off the screen is a different column for that reason.
 *
 * A denied login is reported as denied rather than as unknown, so the person
 * who clicked "no" can see the terminal say so instead of waiting out the
 * clock. It reveals nothing: the caller already had to hold the device_code.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { createCliSession, tokenPrefix } from "../../../_cli.js";
import { CODE_TTL_MIN, isoAgo, json } from "../../../_shared.js";
import { accessFor } from "../../../_store.js";

/** A device_code is `randomToken(32)` — 64 hex — and nothing else is looked up. */
const DEVICE_CODE_RE = /^[0-9a-f]{64}$/;

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return json({ status: "unknown", error: "login is not configured" }, 503);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "expected a JSON body" }, 400);
  }

  const deviceCode = String(body.device_code || "").trim();
  if (!DEVICE_CODE_RE.test(deviceCode)) return json({ status: "unknown" }, 400);

  const row = await db
    .prepare(
      `SELECT code, created_at, approved_at, approved_by, denied_at, email, os, arch, version
         FROM cli_login_codes WHERE device_code = ?`,
    )
    .bind(deviceCode)
    .first();

  if (!row) return json({ status: "unknown" });
  if (row.denied_at) {
    await db.prepare("DELETE FROM cli_login_codes WHERE device_code = ?").bind(deviceCode).run();
    return json({ status: "denied" });
  }
  if (!row.approved_at) {
    if (row.created_at < isoAgo(CODE_TTL_MIN)) return json({ status: "expired" });
    return json({ status: "pending" });
  }

  // Approved. Re-check the entitlement now rather than trusting the decision
  // made when the button was clicked: approval and collection can be minutes
  // apart, and an account revoked in between must not come away with a
  // ninety-day token minted from a stale answer.
  const access = await accessFor(db, row.approved_by);
  if (!access.entitled) {
    await db.prepare("DELETE FROM cli_login_codes WHERE device_code = ?").bind(deviceCode).run();
    return json({ status: "denied", reason: access.reason });
  }

  // Spend the code *before* minting anything. Two polls racing — a retry on a
  // slow connection, a script — must not produce two ninety-day sessions; the
  // loser changes no row and is told the code is unknown, which by then is
  // true. If minting then fails, the code is gone and the person runs login
  // again: the annoying direction, and the safe one.
  const claim = await db
    .prepare("DELETE FROM cli_login_codes WHERE device_code = ? AND approved_at IS NOT NULL")
    .bind(deviceCode)
    .run();
  if (!claim.meta || claim.meta.changes !== 1) return json({ status: "unknown" });

  const label = [row.os, row.arch].filter(Boolean).join("/") || "machine";
  const token = await createCliSession(db, { userId: row.approved_by, label });

  return json({ status: "approved", token, email: row.email || "", label, prefix: tokenPrefix(token) });
}
