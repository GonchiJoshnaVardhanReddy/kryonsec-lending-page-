/**
 * POST /api/device/start
 *
 * Step 1 of the connect flow. The CLI has a membership key and wants to be
 * introduced to its owner: it posts the key plus a little about the machine,
 * and gets back a short code to show the member, a secret it keeps, and the
 * URL to open.
 *
 *   {key, device_id, os, arch, version}
 *     -> {code: "AB12-CD34", device_code: "<64 hex>", url: "https://.../connect?code=..."}
 *
 * The code is what the member reads; the device_code is what the CLI polls
 * with. They are separate on purpose — whoever glimpses the URL over a
 * shoulder still cannot collect the answer.
 *
 *   rejected key -> 400 malformed / 403 not recognised
 *   no database  -> 503, never a 200 with a code that can never be claimed
 *
 * Environment: KRYONSEC_KEYS (the same allowlist the download gate uses),
 * KRYONSEC_DB (D1).
 */

import { isAllowed, isWellFormedKey } from "../download.js";
import {
  CODE_TTL_MIN,
  cleanDeviceId,
  cleanText,
  isoAgo,
  json,
  nowIso,
  randomCode,
  randomToken,
} from "../../_shared.js";

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return json({ error: "connect is not configured" }, 503);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "expected a JSON body" }, 400);
  }

  const key = String(body.key || "").trim().toUpperCase();
  if (!isWellFormedKey(key)) return json({ error: "malformed key" }, 400);
  // The key is the only credential here, so a valid key is what authorises
  // creating a code at all. An unauthenticated stranger cannot fill the table.
  if (!isAllowed(key, env.KRYONSEC_KEYS)) {
    return json({ error: "key not recognised" }, 403);
  }

  // Codes are short-lived, so anything older than a day is litter. Sweeping
  // here keeps the table from growing forever without a scheduled job.
  // ponytail: a sweep per start is fine at this volume; move it to a Cron
  // Trigger if starts ever get frequent enough for the write to matter.
  await db
    .prepare("DELETE FROM device_codes WHERE created_at < ?")
    .bind(isoAgo(24 * 60))
    .run();

  const code = randomCode();
  const deviceCode = randomToken(32);

  await db
    .prepare(
      `INSERT INTO device_codes
         (code, device_code, key, device_id, os, arch, version, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      code,
      deviceCode,
      key,
      cleanDeviceId(body.device_id),
      cleanText(body.os, 32),
      cleanText(body.arch, 32),
      cleanText(body.version, 32),
      nowIso(),
    )
    .run();

  // Built from the request, so this is right on a preview deployment too.
  const origin = new URL(request.url).origin;
  return json({
    code,
    device_code: deviceCode,
    url: `${origin}/connect?code=${code}`,
    expires_in_min: CODE_TTL_MIN,
  });
}
