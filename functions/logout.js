/**
 * POST /logout — end this browser's session.
 *
 * One row, deleted. That is the whole of sign-out here, and it is the reason
 * the sessions table stores a hash rather than a signed token: ending one
 * browser is a DELETE, ending every browser an account has ever used is the
 * same DELETE without the key, and neither waits for an expiry to take effect.
 *
 * POST, and CSRF-checked, because signing someone out is a state change. The
 * worst a cross-site GET sign-out achieves is annoying — which is exactly the
 * kind of harmless that gets copied into the next handler, where it is not.
 * A failed check therefore does not sign anyone out: refusing is the right
 * answer on a handler whose whole job is to destroy something.
 *
 * No GET counterpart. A link that signs people out is a link that mail
 * scanners and prefetchers follow, and a session should not end because
 * something crawled a page. A GET here gets the 405 Pages returns for a route
 * with no `onRequestGet`.
 */

import { checkCsrf, clearSessionCookie, currentSession, destroySession } from "./_auth.js";
import { redirect } from "./_shared.js";

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  const session = await currentSession(db, request);

  if (session) {
    // An unparseable body is not a CSRF token, so it fails the check below
    // rather than throwing before it — `checkCsrf` compares against "".
    const form = await request.formData().catch(() => new FormData());
    if (await checkCsrf(request, session, form)) return redirect("/dashboard");
    await destroySession(db, request);
  }

  // The clearing cookie is built from this request's URL, so its `Secure` flag
  // matches the cookie it is replacing. A `Secure` mismatch is a cookie the
  // browser keeps, which looks exactly like sign-out being broken.
  // A stale or forged session lands on the same exit and gets the same
  // clearing header — there is no row to delete, but there is a cookie to drop.
  const headers = new Headers({ Location: "/", "Cache-Control": "no-store" });
  headers.append("Set-Cookie", clearSessionCookie(request.url));
  return new Response(null, { status: 303, headers });
}
