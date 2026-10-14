/**
 * GET /api/license/verify?key=KRYO-XXXX-XXXX-XXXX
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
 * Environment (Pages -> Settings -> Variables and Secrets, encrypted):
 *   KRYONSEC_KEYS   the same comma-separated list the download gate uses
 */

import { isAllowed, isWellFormedKey } from "../download.js";

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

export async function onRequestGet({ request, env }) {
  const key = (new URL(request.url).searchParams.get("key") || "")
    .trim()
    .toUpperCase();

  if (!key) return json({ valid: false, reason: "no key supplied" });
  if (!isWellFormedKey(key)) return json({ valid: false, reason: "malformed" });
  if (!isAllowed(key, env.KRYONSEC_KEYS)) {
    return json({ valid: false, reason: "not recognised" });
  }

  // No expiry tracking: KRYONSEC_KEYS is a flat allowlist, so a key is valid
  // until it is removed from the list. The client accepts an empty string and
  // simply reports no days-left.
  // ponytail: add an expiry to the allowlist format (KRYO-...:<iso-date>) when
  // memberships actually lapse on a date — then a lapsed key answers
  // {valid:false, reason:"expired"} and the app says so by name.
  return json({ valid: true, expires: "" });
}
