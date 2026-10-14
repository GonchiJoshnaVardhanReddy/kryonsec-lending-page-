/**
 * GET /api/license/verify?device=..&os=..&arch=..&version=..
 * X-Kryonsec-Key: KRYO-XXXX-XXXX-XXXX     (or ?key=... for older installs)
 *
 * The endpoint the app phones home to. Purple Team is gated on it: license.py
 * calls this once a day and caches the answer, so a machine that never reaches
 * it can never activate.
 *
 * Response contract, read straight out of license.py:
 *
 *   {"valid": true}                       -> activated, cached for a day
 *   {"valid": false, "reason": "..."}     -> refused
 *   {"valid": false, "reason": "expired"} -> refused, reported as expired
 *
 * IT MUST ANSWER 200 EVEN WHEN REFUSING.
 *
 * This is the opposite of the download endpoint, and for a concrete reason:
 * license.py treats any non-200 as "the network is down" and falls back to a
 * grace period of GRACE_DAYS using the last successful check. Answer 403 for a
 * key you have removed from KRYONSEC_KEYS and the member keeps working for the
 * whole grace period — revocation that does not revoke. Returning 200 with
 * valid:false is what actually records the refusal.
 *
 * The optional device parameters are how the admin view learns a machine is
 * alive. They are recorded on a valid key only, and a failure to record is
 * swallowed: the daily check-in must never fail because the dashboard's table
 * was unavailable. Recorded: a random device id the CLI generates, the OS, the
 * architecture and the app version — never a hostname, a path, a target, or
 * anything about the work being done.
 *
 * Environment (Pages -> Settings -> Variables and Secrets, encrypted):
 *   KRYONSEC_KEYS   the same comma-separated list the download gate uses
 *   KRYONSEC_DB     D1 (optional — without it, check-ins just are not recorded)
 */

import { isAllowed, isWellFormedKey } from "../download.js";
import { cleanDeviceId, cleanText, nowIso } from "../../_shared.js";

function json(body) {
  return new Response(JSON.stringify(body), {
    // Always 200: see the note above. The body carries the verdict.
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      // A cached verdict would outlive a revocation for every member behind
      // the same cache, so this is never stored.
      "Cache-Control": "no-store",
    },
  });
}

/**
 * Remember this machine. Best-effort by design: see the note in the header.
 * Nothing here can change the verdict the caller receives.
 */
async function recordDevice(env, key, params) {
  const deviceId = cleanDeviceId(params.get("device"));
  if (!deviceId || !env.KRYONSEC_DB) return;
  try {
    const now = nowIso();
    await env.KRYONSEC_DB
      .prepare(
        `INSERT INTO devices (id, key, os, arch, version, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           key = excluded.key, os = excluded.os, arch = excluded.arch,
           version = excluded.version, last_seen = excluded.last_seen`,
      )
      .bind(
        deviceId,
        key,
        cleanText(params.get("os"), 32),
        cleanText(params.get("arch"), 32),
        cleanText(params.get("version"), 32),
        now,
        now,
      )
      .run();
  } catch {
    // A dashboard row is not worth a failed check-in.
  }
}

export async function onRequestGet({ request, env }) {
  const params = new URL(request.url).searchParams;
  // Header first. A membership key is a credential, and a query string is a
  // leaky place for one — it lands in access logs, proxy logs and Referer
  // headers. ?key= stays supported so installs built before this keep working.
  const key = (request.headers.get("X-Kryonsec-Key") || params.get("key") || "")
    .trim()
    .toUpperCase();

  if (!key) return json({ valid: false, reason: "no key supplied" });
  if (!isWellFormedKey(key)) return json({ valid: false, reason: "malformed" });
  if (!isAllowed(key, env.KRYONSEC_KEYS)) {
    // Not recorded: an unrecognised key is not a member's machine.
    return json({ valid: false, reason: "not recognised" });
  }

  await recordDevice(env, key, params);

  // No expiry tracking: KRYONSEC_KEYS is a flat allowlist, so a key is valid
  // until it is removed from the list. The client accepts an empty string and
  // simply reports no days-left.
  // ponytail: add an expiry to the allowlist format (KRYO-...:<iso-date>) when
  // memberships actually lapse on a date — then a lapsed key answers
  // {valid:false, reason:"expired"} and the app says so by name.
  return json({ valid: true, expires: "" });
}
