/**
 * Sessions, CSRF, and the OAuth round-trip helpers.
 *
 * Import-only: the Pages router ignores paths starting with an underscore, so
 * this is never served.
 *
 * The one decision worth stating up front: a session cookie is an opaque
 * random token, and the database stores only its SHA-256. There is no signing
 * key, no JWT, and no payload in the cookie. That means revocation is a row
 * delete rather than something that waits for an expiry, and a database dump
 * yields nothing a caller can present. The cost is one indexed SELECT per
 * request, which is the same read any authenticated handler was going to do
 * anyway.
 *
 * CSRF is the synchroniser-token pattern, derived rather than stored:
 *
 *     csrf = sha256(session_token + ":csrf")
 *
 * Rendering that in a form is safe — the session token is HttpOnly and
 * unreadable from the page, and SHA-256 is preimage-resistant, so the CSRF
 * value gives an attacker nothing to work backwards from. Deriving it means
 * there is no second random value to generate, store, rotate, or forget to
 * rotate, and no way for the two to drift apart. SameSite=Lax on the session
 * cookie is the first line; this is the second, and it is the one that holds
 * if a browser ever ignores the first.
 */

import { nowIso, randomToken } from "./_shared.js";

// --- cookies ----------------------------------------------------------------

export const SESSION_COOKIE = "kr_session";
// The in-flight OAuth state. Separate from the session cookie because it
// exists for seconds, on one browser, before there is any session at all.
export const OAUTH_COOKIE = "kr_oauth";
export const SESSION_TTL_DAYS = 30;

/**
 * `Secure` must be off on plain-http localhost or the browser silently drops
 * the cookie and every login appears to succeed and then not be signed in.
 */
function isSecure(url) {
  const { protocol, hostname } = new URL(url);
  if (protocol === "https:") return true;
  return !(hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]");
}

/** Parse a Cookie header into a plain object. Never throws. */
export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 1) continue;
    const name = part.slice(0, eq).trim();
    if (name) out[name] = part.slice(eq + 1).trim();
  }
  return out;
}

function cookie(name, value, { url, maxAge, httpOnly = true }) {
  const bits = [
    `${name}=${value}`,
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ];
  if (httpOnly) bits.push("HttpOnly");
  if (isSecure(url)) bits.push("Secure");
  return bits.join("; ");
}

export function sessionCookie(token, url) {
  return cookie(SESSION_COOKIE, token, { url, maxAge: SESSION_TTL_DAYS * 86_400 });
}

export function clearSessionCookie(url) {
  return cookie(SESSION_COOKIE, "", { url, maxAge: 0 });
}

export function oauthCookie(value, url) {
  // Ten minutes: long enough to read a consent screen, short enough that a
  // stale flow cannot be resumed later. The server-side grant expires on the
  // same scale.
  return cookie(OAUTH_COOKIE, value, { url, maxAge: 600 });
}

export function clearOauthCookie(url) {
  return cookie(OAUTH_COOKIE, "", { url, maxAge: 0 });
}

// --- crypto -----------------------------------------------------------------

/** SHA-256 as lowercase hex. */
export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** base64url without padding — the OAuth/PKCE wire encoding. */
export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Opaque ids, so a leaked row does not reveal its neighbours or its age. */
export function newId(prefix) {
  return `${prefix}_${randomToken(16)}`;
}

/**
 * Compare two strings without leaking where they first differ.
 *
 * Re-exported under this module's own name so callers importing from _auth
 * do not have to reach into api/download.js for it.
 */
export function timingSafeEqual(a, b) {
  const x = String(a || "");
  const y = String(b || "");
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

/**
 * The CSRF value for a session. Deterministic, so nothing has to be stored.
 * See the module comment for why this is safe to put in a form.
 */
export async function csrfFor(sessionToken) {
  return sha256Hex(`${sessionToken}:csrf`);
}

// --- sessions ---------------------------------------------------------------

/**
 * Create a session and return the raw token. The caller sets the cookie; the
 * token is returned rather than the row because it is the only moment the raw
 * value exists — the database keeps the hash.
 */
export async function createSession(db, userId) {
  const token = randomToken(32);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_DAYS * 86_400_000);
  await db
    .prepare(
      `INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(await sha256Hex(token), userId, nowIso(), expires.toISOString(), nowIso())
    .run();
  return token;
}

/**
 * Resolve the request's session cookie to a user row, or null.
 *
 * An expired row is deleted on sight rather than merely ignored: the sweep
 * has to happen somewhere, and the request that notices is the cheapest
 * place. Nothing depends on it for correctness — the expiry is checked here
 * either way — so a session that is never looked at again is simply a row
 * that lingers, which the /admin sessions view can also clear.
 */
export async function currentSession(db, request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token || !/^[0-9a-f]{16,128}$/.test(token)) return null;

  const row = await db
    .prepare(
      `SELECT s.token_hash, s.user_id, s.expires_at,
              u.email, u.email_verified, u.name
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?`,
    )
    .bind(await sha256Hex(token))
    .first();

  if (!row) return null;

  if (row.expires_at <= nowIso()) {
    await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(row.token_hash).run();
    return null;
  }

  return { token, user: row };
}

/** Delete this request's session. The cookie is cleared by the caller. */
export async function destroySession(db, request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return;
  await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
}

// --- request-origin checks --------------------------------------------------

/**
 * Is this a request the browser made from our own pages?
 *
 * SameSite=Lax already stops the session cookie riding along on a cross-site
 * POST, so this is the second lock on the same door — but it is the lock that
 * still works for a handler that authenticates some other way, and it costs
 * one header read.
 *
 * `Sec-Fetch-Site` is preferred where present because a page cannot forge it.
 * `Origin` is the fallback. A request with neither is refused: an absent
 * header is not evidence of same-origin, and treating it as such is how a
 * curl-shaped CSRF gets in.
 */
export function isSameOrigin(request) {
  const site = request.headers.get("Sec-Fetch-Site");
  if (site) return site === "same-origin" || site === "none";

  const origin = request.headers.get("Origin");
  if (!origin) return false;
  return origin === new URL(request.url).origin;
}

/**
 * Validate a POST: same origin AND the derived CSRF token.
 *
 * Both, not either. The origin check is per-request and the CSRF token is
 * per-session, so they fail in different ways — a proxy that strips
 * Sec-Fetch-Site, or a browser that ignores SameSite. Returns "" when the
 * request is fine, or a human-readable reason when it is not.
 */
export async function checkCsrf(request, session, form) {
  if (!isSameOrigin(request)) return "That request did not come from this site.";
  const expected = await csrfFor(session.token);
  if (!timingSafeEqual(form.get("csrf"), expected)) {
    return "That form had expired. Reload the page and try again.";
  }
  return "";
}

// --- admin ------------------------------------------------------------------

/** Is this user an administrator? Reads the table, never a form field. */
export async function isAdminUser(db, userId) {
  if (!userId) return false;
  const row = await db.prepare("SELECT 1 AS ok FROM admins WHERE user_id = ?").bind(userId).first();
  return Boolean(row);
}

/**
 * Record a privileged action.
 *
 * `before`/`after` carry changed fields only. This is called on every admin
 * mutation, and it must never be handed a token, a session cookie, or a raw
 * provider response — the audit table is read by more people than the thing
 * it audits.
 */
export async function audit(db, { actor, action, target = null, before = null, after = null }) {
  await db
    .prepare(
      `INSERT INTO admin_audit (actor, action, target, before, after, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      String(actor),
      String(action),
      target,
      before ? JSON.stringify(before) : null,
      after ? JSON.stringify(after) : null,
      nowIso(),
    )
    .run();
}
