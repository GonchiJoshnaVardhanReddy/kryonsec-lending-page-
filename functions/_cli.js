/**
 * Credentials presented by things that are not a browser.
 *
 * Import-only: never served.
 *
 * Two clients need access without a session cookie — the command line, which
 * holds a long-lived token it obtained once through `kryonsec login`, and the
 * installer, which is handed a token that expires in minutes and works once.
 * Both resolve to a `user_id` here, and every caller then asks `accessFor()`
 * the same question the website asks. That is the whole design: the credential
 * says *who*, never *whether*. An entitlement check that lives in this file
 * would be a second answer to a question that already has one.
 *
 * Both are stored hashed, so a database dump yields nothing presentable — the
 * same reasoning as `sessions`. Neither is ever returned to a caller; only the
 * `user_id` behind them is.
 */

import { newId, sha256Hex } from "./_auth.js";
import { CODE_TTL_MIN, nowIso, randomToken } from "./_shared.js";

/** `s_` + 64 hex. The prefix is what `token_prefix` shows on the dashboard. */
const CLI_TOKEN_RE = /^s_[0-9a-f]{64}$/;

/** `dl_` + 64 hex. Short-lived, single-use, and it travels in a URL. */
const DOWNLOAD_TOKEN_RE = /^dl_[0-9a-f]{64}$/;

/** What a token looks like on screen, so a person can match a row to a machine
 *  without the row containing anything anyone could use. */
export const tokenPrefix = (raw) => `${raw.slice(0, 10)}…`;

/** The `Authorization: Bearer …` value, or "". A malformed header is "". */
export function bearer(request) {
  const match = /^Bearer\s+(\S+)$/i.exec(String(request.headers.get("Authorization") || "").trim());
  return match ? match[1] : "";
}

/**
 * A live CLI session, or null.
 *
 * `revoked_at IS NULL` is checked in the query rather than after it: a revoked
 * row must never reach the caller, not even briefly, and putting the condition
 * in the WHERE clause means there is no version of this function that forgets.
 */
export async function cliSessionFromToken(db, raw) {
  if (!CLI_TOKEN_RE.test(String(raw || ""))) return null;

  const row = await db
    .prepare(
      `SELECT id, user_id, expires_at, revoked_at
         FROM cli_sessions
        WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?`,
    )
    .bind(await sha256Hex(raw), nowIso())
    .first();

  if (!row) return null;

  // Best-effort, and loud about failing. `last_used_at` drives the "last seen"
  // column on the dashboard and is not part of the authorisation decision, so a
  // write failure must not refuse a request the query above already allowed —
  // but a silent catch here would hide a broken column indefinitely.
  await db
    .prepare("UPDATE cli_sessions SET last_used_at = ? WHERE id = ?")
    .bind(nowIso(), row.id)
    .run()
    .catch((error) => console.warn(`cli: could not stamp last_used_at on ${row.id}:`, error));

  return { id: row.id, userId: row.user_id };
}

/**
 * What `kryonsec login` leaves on the machine, and how it is taken away.
 *
 * Ninety days rather than forever. A credential that never expires is not a
 * session, it is a permanent key with a friendlier name — and the brief is
 * explicit that permanent reusable credentials are the thing to avoid. Ninety
 * days is long enough that nobody re-authenticates mid-engagement and short
 * enough that an abandoned machine stops working on its own.
 */
export const CLI_SESSION_TTL_DAYS = 90;

/** Mint a CLI session and return the raw token. Stored hashed, like a session. */
export async function createCliSession(db, { userId, label = null }) {
  const raw = `s_${randomToken(32)}`;
  const now = new Date();
  await db
    .prepare(
      `INSERT INTO cli_sessions (id, token_hash, user_id, token_prefix, label, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      newId("s"),
      await sha256Hex(raw),
      userId,
      tokenPrefix(raw),
      label,
      nowIso(),
      new Date(now.getTime() + CLI_SESSION_TTL_DAYS * 86_400_000).toISOString(),
    )
    .run();
  return raw;
}

/** Every machine this account has signed in on, revoked ones included, so the
 *  dashboard can show what was cut off as well as what is live. */
export async function listCliSessions(db, userId) {
  const { results } = await db
    .prepare(
      `SELECT id, token_prefix, label, created_at, expires_at, last_used_at, revoked_at, revoked_reason
         FROM cli_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
    )
    .bind(userId)
    .all();
  return results || [];
}

/**
 * Cut off one machine.
 *
 * Guarded (`WHERE revoked_at IS NULL`) so revoking twice is a no-op that
 * reports honestly rather than overwriting the original reason with a later
 * one.
 *
 * `userId` is optional and is what the *browser* path passes: the dashboard
 * revokes by session id, and a session id is a value that arrives from a form.
 * Scoping the statement to the owner means a tampered id matches nothing
 * rather than cutting off a stranger's machine — the ownership check and the
 * revocation are then one statement, with no window between them for the row
 * to change hands. The CLI path passes no `userId` on purpose: it has no id at
 * all, only its own token, and `onRequestPost` in api/beta/cli/logout.js
 * resolves that token to a session this account already owns.
 *
 * An entitlement check is not repeated here either way: revoking a session
 * never grants anything, and access is decided at the gate that hands out
 * downloads and license verdicts, by `accessFor()`, every time.
 */
export async function revokeCliSession(db, { id, actor = "self", reason = null, userId = null }) {
  const scoped = Boolean(userId);
  const claim = await db
    .prepare(
      `UPDATE cli_sessions SET revoked_at = ?, revoked_reason = ?
        WHERE id = ? AND revoked_at IS NULL${scoped ? " AND user_id = ?" : ""}`,
    )
    .bind(
      ...(scoped
        ? [nowIso(), reason ? `${actor}: ${reason}` : actor, id, userId]
        : [nowIso(), reason ? `${actor}: ${reason}` : actor, id]),
    )
    .run();
  return Boolean(claim.meta && claim.meta.changes === 1);
}

/**
 * Mint a download token and return the raw value.
 *
 * This is the only moment the raw token exists; the row keeps the hash. It is
 * returned rather than stored-and-read-back for the same reason `createSession`
 * does it: a function that can read a live credential back out of the database
 * is a function that can hand one to the wrong caller later.
 *
 * Lives `CODE_TTL_MIN` — the same window the connect flow's device codes use,
 * which is long enough to copy one command into a terminal and short enough
 * that the credential left in the shell history is worthless by the time
 * anyone finds it. Unused tokens simply expire; there is nothing to sweep,
 * because a row with `used_at IS NULL` past its `expires_at` fails the same
 * guarded UPDATE a used one does.
 */
export async function mintDownloadToken(db, userId) {
  const raw = `dl_${randomToken(32)}`;
  const now = new Date();
  await db
    .prepare(
      `INSERT INTO download_tokens (token_hash, user_id, created_at, expires_at, used_at)
       VALUES (?, ?, ?, ?, NULL)`,
    )
    .bind(
      await sha256Hex(raw),
      userId,
      nowIso(),
      new Date(now.getTime() + CODE_TTL_MIN * 60_000).toISOString(),
    )
    .run();
  return raw;
}

/**
 * Spend a download token. Returns the `user_id`, or null.
 *
 * Consumed by a guarded UPDATE, so two requests arriving with the same token
 * cannot both be authorised — one changes the row and the other does not. That
 * matters more here than anywhere else in this codebase: the token is valid
 * for minutes and its whole purpose is to make a credential that leaks into a
 * shell history or a process list worthless to whoever finds it.
 *
 * Deliberately spent *before* the wheel is fetched. If the fetch then fails the
 * token is gone and the person mints another one, which is a small annoyance
 * in exchange for there being no window in which a token can be replayed.
 */
export async function consumeDownloadToken(db, raw) {
  const token = String(raw || "");
  if (!DOWNLOAD_TOKEN_RE.test(token)) return null;

  const now = nowIso();
  const hash = await sha256Hex(token);
  const claim = await db
    .prepare(
      `UPDATE download_tokens SET used_at = ?
        WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
    )
    .bind(now, hash, now)
    .run();

  if (!claim.meta || claim.meta.changes !== 1) return null;

  // The UPDATE just matched a row, so this SELECT is a read of something this
  // request has already claimed. Not observable to anyone else.
  const row = await db
    .prepare("SELECT user_id FROM download_tokens WHERE token_hash = ?")
    .bind(hash)
    .first();
  return row?.user_id || null;
}
