/**
 * POST /api/device/poll
 *
 * Step 3 of the connect flow, and the only one the CLI repeats. It sends the
 * device_code it kept from /api/device/start and asks whether the member has
 * finished yet.
 *
 *   {device_code} -> {status: "pending"}                      keep waiting
 *                 -> {status: "connected", email: "..."}      done
 *                 -> {status: "expired"}                      start over
 *                 -> {status: "unknown"}                      start over
 *
 * The membership key is deliberately NOT in the reply. The CLI already has it
 * — it sent it to /start — so echoing a credential back would add a way for it
 * to leak without adding anything the caller needs.
 *
 * A claimed code is deleted as it is read: one claim, one collection.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { CODE_TTL_MIN, isoAgo, json } from "../../_shared.js";

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return json({ status: "unknown", error: "connect is not configured" }, 503);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "expected a JSON body" }, 400);
  }

  const deviceCode = String(body.device_code || "").trim();
  if (!/^[0-9a-f]{16,128}$/.test(deviceCode)) {
    return json({ status: "unknown" }, 400);
  }

  const row = await db
    .prepare(
      `SELECT code, created_at, claimed_at, email, name
         FROM device_codes WHERE device_code = ?`,
    )
    .bind(deviceCode)
    .first();

  if (!row) return json({ status: "unknown" });
  if (!row.claimed_at) {
    if (row.created_at < isoAgo(CODE_TTL_MIN)) return json({ status: "expired" });
    return json({ status: "pending" });
  }

  await db.prepare("DELETE FROM device_codes WHERE device_code = ?").bind(deviceCode).run();
  return json({ status: "connected", email: row.email || "", name: row.name || "" });
}
