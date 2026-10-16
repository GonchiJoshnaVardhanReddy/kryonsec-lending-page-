/**
 * POST /api/beta/device/start
 *
 * Step 1 of `kryonsec login`. Unlike /api/device/start, this one is not
 * authorised by anything — and that is not an oversight, it is the flow.
 *
 * The connect flow's CLI already holds a membership key, so a key is what
 * authorises minting a code. A beta account holds nothing yet; that is the
 * whole reason it is running `login`. So any client may ask for a code, and
 * the code grants nothing on its own: it sits inert until a signed-in person
 * opens the URL and approves it. Refusing to hand out codes would not protect
 * anything, it would just make login impossible.
 *
 * What that leaves is not authorisation but volume, and there is a cap for it
 * below. Two things make abuse cheap to bound: the codes are random rather
 * than sequential, so nobody can find someone else's by asking; and a code
 * that nobody approves expires in CODE_TTL_MIN and is swept.
 *
 *   {device_id, os, arch, version}
 *     -> {code: "AB12-CD34", device_code: "<64 hex>", url, expires_in_min}
 *
 * The reply carries no user, no entitlement and no token. Nothing here knows
 * who the person is yet — the API only learns that when they approve.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import {
  CODE_TTL_MIN,
  cleanDeviceId,
  cleanText,
  isoAgo,
  json,
  nowIso,
  randomCode,
  randomToken,
} from "../../../_shared.js";

/**
 * How many unclaimed codes may exist from the last minute before this starts
 * refusing. A real `kryonsec login` makes one; a script makes thousands, and
 * this is what stops the second thing from filling the table.
 *
 * ponytail: a global cap, not per-IP. A per-IP limit wants `CF-Connecting-IP`,
 * a per-IP counter, and a decision about what to do behind a shared NAT — for
 * a beta whose whole population is hand-reviewed, one counter is enough. Swap
 * in a rate-limiting rule at the edge if starts ever get noisy.
 */
const MAX_STARTS_PER_MIN = 60;

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (!db) return json({ error: "login is not configured" }, 503);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "expected a JSON body" }, 400);
  }

  // Litter first, so the cap below is measuring live codes rather than
  // everything ever issued.
  await db.prepare("DELETE FROM cli_login_codes WHERE created_at < ?").bind(isoAgo(24 * 60)).run();

  const recent = await db
    .prepare("SELECT COUNT(*) AS n FROM cli_login_codes WHERE created_at > ?")
    .bind(isoAgo(1))
    .first();
  if ((recent?.n || 0) >= MAX_STARTS_PER_MIN) {
    return json({ error: "too many sign-in attempts from this site just now — try again in a minute" }, 429);
  }

  const code = randomCode();
  const deviceCode = randomToken(32);

  await db
    .prepare(
      `INSERT INTO cli_login_codes
         (code, device_code, device_id, os, arch, version, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      code,
      deviceCode,
      cleanDeviceId(body.device_id),
      cleanText(body.os, 32),
      cleanText(body.arch, 32),
      cleanText(body.version, 32),
      nowIso(),
    )
    .run();

  // Built from the request, so the link is right on a preview deployment too.
  const origin = new URL(request.url).origin;
  return json({
    code,
    device_code: deviceCode,
    // The code is in the URL because the person has to type it into a browser
    // they may already be signed into. It is not a credential: opening this
    // page approves nothing, and the page asks before it does anything.
    url: `${origin}/beta/device?code=${code}`,
    expires_in_min: CODE_TTL_MIN,
  });
}
