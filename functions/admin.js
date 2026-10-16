/**
 * GET|POST /admin — the review desk.
 *
 * Two doors, and they are genuinely different:
 *
 *   - a signed-in account listed in `admins`. Authorisation is a row in a
 *     table, checked on every request. Nothing is inferred from an email
 *     address, and there is no way to become an admin by filling in a form.
 *   - the KRYONSEC_ADMIN_TOKEN, which predates accounts and still opens the
 *     read-only member view. Left exactly as it was so that what works today
 *     keeps working.
 *
 * The token door is a POST and the review desk is a GET, which is the right way
 * round: a token in a query string lands in the browser history, the Referer,
 * and any proxy log, and the token has no expiry. The session cookie that opens
 * the review desk is HttpOnly, SameSite, and expires.
 *
 * Every mutation lives in `api/admin/action.js` rather than here, because the
 * guard those actions need — session, then `admins`, then CSRF — is a single
 * thing and this file has no business having a second copy of it.
 *
 * Environment: KRYONSEC_DB (D1), KRYONSEC_ADMIN_TOKEN or KV `admin/token`.
 */

import { csrfFor, currentSession, isAdminUser } from "./_auth.js";
import { betaPage, csrfField, notice, when } from "./_pages.js";
import { esc, isAdmin, page } from "./_shared.js";
import {
  listAccess,
  listApplications,
  listAudit,
  listOutbox,
  programmeStatus,
  queueCounts,
} from "./_store.js";

/**
 * The admin token lives in KV (`admin/token`), or in KRYONSEC_ADMIN_TOKEN if
 * one is ever set.
 *
 * KV rather than an env var for a specific reason: this project's other two
 * secrets are secret_text, and the API does not hand their values back. Adding
 * a third variable means writing the whole env_vars map, which is how you
 * blank the two you cannot read. A KV value also rotates without a redeploy.
 */
async function adminToken(env) {
  if (env.KRYONSEC_ADMIN_TOKEN) return String(env.KRYONSEC_ADMIN_TOKEN);
  if (!env.KRYONSEC_FEEDBACK) return "";
  try {
    return (await env.KRYONSEC_FEEDBACK.get("admin/token")) || "";
  } catch {
    return "";
  }
}

/** What the action route sends back after a write. Codes, not sentences, so
 *  nothing an admin typed is ever reflected into a page — the message is looked
 *  up here and the URL only ever carries a word from this list. */
const OUTCOMES = {
  decided: ["ok", "Decision recorded."],
  granted: ["ok", "Access granted."],
  revoked: ["ok", "Access revoked. Downloads and the command line stop now."],
  suspended: ["ok", "Access suspended."],
  programme: ["ok", "Programme status changed."],
  already: ["warn", "Someone else got there first — nothing was changed."],
  invalid: ["error", "That decision was not understood, so nothing was changed."],
  missing: ["error", "That record no longer exists."],
};

function prompt(message) {
  const notice = message
    ? `<p class="form-static-note" role="alert">${esc(message)}</p>`
    : "";
  return `                <div class="section-bar"><span>KR / ADMIN</span><span>MEMBERS</span></div>
                <h2 id="admin-title">WHO IS<br><em>CONNECTED.</em></h2>
                ${notice}
                <form class="feedback-form" method="post" action="/admin">
                    <div class="form-field form-field-full"><label for="admin-token">ADMIN TOKEN *</label><input id="admin-token" name="token" type="password" autocomplete="off" required></div>
                    <div class="form-actions"><button class="button button-primary" type="submit">OPEN <span aria-hidden="true">↗</span></button></div>
                </form>`;
}

function ago(iso) {
  const then = Date.parse(iso || "");
  if (Number.isNaN(then)) return "—";
  const mins = Math.floor((Date.now() - then) / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function shortKey(key) {
  // A key is a credential even in your own dashboard — showing the tail is
  // enough to tell two members apart without putting the whole thing on
  // screen in a shared window.
  return `…${String(key || "").slice(-4)}`;
}

/**
 * A table. Cells are escaped unless they are `{ html }`.
 *
 * The marker exists because the review desk's tables carry buttons, which
 * cannot be escaped text. Naming the exception at the call site rather than
 * making the whole table unescaped keeps the default the safe one.
 */
function table(headers, rows) {
  if (!rows.length) return `<p class="form-note">Nothing here yet.</p>`;
  const cell = (c) => (c && typeof c === "object" && "html" in c ? c.html : esc(c));
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join("");
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${cell(c)}</td>`).join("")}</tr>`).join("");
  return `<div class="admin-table-wrap"><table class="admin-table">
                    <thead><tr>${head}</tr></thead>
                    <tbody>${body}</tbody>
                </table></div>`;
}

// --- the review desk --------------------------------------------------------

const STATUSES = ["pending", "approved", "waitlisted", "rejected", "all"];
const FILTER_LABELS = { all: "ALL", pending: "PENDING", approved: "APPROVED", waitlisted: "WAITLISTED", rejected: "REJECTED" };

const QUESTION = (label, value) =>
  value ? `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>` : "";

/**
 * One application, with its decision controls.
 *
 * The reason field is deliberately inside the same form as the buttons: an
 * admin who types a reason and then clicks "reject" sends both, and there is no
 * state in between for the two to drift apart.
 */
function applicationCard(a, csrf) {
  const contact = [a.contact_email, a.portfolio_url].filter(Boolean).join(" · ");
  return `<div class="review-card">
                <div class="review-head"><span>${esc(a.full_name || a.account_name || "—")}</span><span>${esc(when(a.submitted_at).toUpperCase())}</span></div>
                <div class="review-body">
                    <dl>
                        ${QUESTION("ACCOUNT", a.account_email)}
                        ${QUESTION("REPLY TO", contact)}
                        ${QUESTION("WHAT THEY DO", a.role)}
                        ${QUESTION("WHERE THEY RUN IT", a.primary_os)}
                        ${QUESTION("WHAT THEY WOULD TEST", a.intended_use)}
                        ${QUESTION("EXPERIENCE", a.experience)}
                        ${QUESTION("GITHUB", a.github_handle)}
                        ${QUESTION("HOW THEY HEARD", a.referral_source)}
                    </dl>
                    <form class="feedback-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="decide">
                        <input type="hidden" name="application" value="${esc(a.id)}">
                        <input type="hidden" name="back" value="${esc(a.status)}">
                        <div class="review-actions">
                            <div class="form-field"><label for="reason-${esc(a.id)}">NOTE (OPTIONAL)</label><input id="reason-${esc(a.id)}" name="reason" type="text" maxlength="400" autocomplete="off"></div>
                            <button class="button button-primary button-small" type="submit" name="decision" value="approve">APPROVE</button>
                            <button class="button button-secondary button-small" type="submit" name="decision" value="waitlist">WAITLIST</button>
                            <button class="button button-secondary button-small" type="submit" name="decision" value="reject">REJECT</button>
                        </div>
                    </form>
                </div>
            </div>`;
}

/** An entitlement that exists, and the two things that can be done to it. */
function accessCard(row, csrf) {
  const live = row.status === "active";
  return `<div class="review-card">
                <div class="review-head"><span>${esc(row.name || row.email || row.user_id)}</span><span>${esc(live ? "ACTIVE" : row.status.toUpperCase())}</span></div>
                <div class="review-body">
                    <dl>
                        ${QUESTION("ACCOUNT", row.email)}
                        ${QUESTION("GRANTED", row.granted_at ? when(row.granted_at) : "")}
                        ${QUESTION("CHANGED", row.changed_at ? `${when(row.changed_at)} by ${row.changed_by || "—"}` : "")}
                        ${QUESTION("NOTE", row.reason)}
                        ${QUESTION("CLI MACHINES", `${row.live_cli_sessions || 0} signed in`)}
                    </dl>
                    <form class="feedback-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="access">
                        <input type="hidden" name="user" value="${esc(row.user_id)}">
                        <div class="review-actions">
                            <div class="form-field"><label for="ar-${esc(row.user_id)}">NOTE (OPTIONAL)</label><input id="ar-${esc(row.user_id)}" name="reason" type="text" maxlength="400" autocomplete="off"></div>
                            ${
                              live
                                ? `<button class="button button-primary button-small" type="submit" name="action" value="revoke">REVOKE</button>
                            <button class="button button-secondary button-small" type="submit" name="action" value="suspend">SUSPEND</button>`
                                : `<button class="button button-primary button-small" type="submit" name="action" value="grant">RESTORE</button>`
                            }
                        </div>
                    </form>
                </div>
            </div>`;
}

async function review({ request, env, db, session }) {
  const url = new URL(request.url);
  const asked = url.searchParams.get("status") || "pending";
  const status = STATUSES.includes(asked) ? asked : "pending";

  const csrf = await csrfFor(session.token);
  const [counts, programme, applications, access, outbox, auditLog] = await Promise.all([
    queueCounts(db),
    programmeStatus(db),
    listApplications(db, { status }),
    listAccess(db, { limit: 50 }),
    listOutbox(db, { limit: 25 }),
    listAudit(db, { limit: 25 }),
  ]);

  const outcome = OUTCOMES[url.searchParams.get("msg") || ""];
  const actor = session.user.email || session.user.user_id;

  const filters = STATUSES.map((s) => {
    const label = `${FILTER_LABELS[s]} ${s === "all" ? "" : counts[s] ?? 0}`.trim();
    const cls = s === status ? "button button-primary button-small" : "button button-secondary button-small";
    return `<a class="${cls}" href="/admin?status=${s}">${esc(label)}</a>`;
  }).join(" ");

  const ended = programme.status === "ended";

  return betaPage({
    title: "Review",
    kicker: "KR / REVIEW",
    right: "ADMINS",
    heading: ended ? "THE BETA IS" : "WHO GETS",
    accent: ended ? "CLOSED." : "IN.",
    lede: `Signed in as ${actor}. Every action here is written to the audit log, and none of it is reversible without another entry.`,
    notice: outcome ? notice(outcome[0], outcome[1]) : "",
    session,
    admin: true,
    csrf,
    wide: true,
    body: `                <div class="form-actions">${filters}</div>

                <h3>PROGRAMME</h3>
                ${programmeCard(programme, ended, csrf)}

                <h3>APPLICATIONS</h3>
                ${
                  applications.length
                    ? applications.map((a) => applicationCard(a, csrf)).join("")
                    : `<p class="review-empty">Nothing is ${esc(FILTER_LABELS[status].toLowerCase())}.</p>`
                }

                <h3>ACCESS</h3>
                <p class="form-note">Accounts that hold, held, or lost an entitlement. Revoking stops downloads and the command line on the next request — it does not reach onto a machine that already has the software.</p>
                ${
                  access.length
                    ? access.map((r) => accessCard(r, csrf)).join("")
                    : `<p class="review-empty">Nobody holds access yet.</p>`
                }

                <h3>EMAIL</h3>
                <p class="form-note">Queued and sent notifications. Bodies are not stored, so there is none here to leak.</p>
                ${table(
                  ["WHEN", "KIND", "TO", "STATUS", "ATTEMPTS", "LAST ERROR"],
                  outbox.map((r) => [ago(r.created_at), r.kind, r.to_email, r.sent_at ? "sent" : r.status, r.attempts, r.last_error || "—"]),
                )}

                <h3>AUDIT</h3>
                ${table(
                  ["WHEN", "ACTOR", "ACTION", "TARGET", "BEFORE", "AFTER"],
                  auditLog.map((r) => [ago(r.created_at), r.actor, r.action, r.target || "—", r.before || "—", r.after || "—"]),
                )}

                <h3>MEMBERS (READ-ONLY)</h3>
                <p class="form-note">The membership-key view, unchanged. It is behind the admin token, not behind an account.</p>
                ${await memberTables(db)}`,
  });
}

/** The programme switch. Ending it is stated as what it does, because the
 *  consequence lands on people who are not in the room. */
function programmeCard(programme, ended, csrf) {
  return `<div class="review-card">
                <div class="review-head"><span>EARLY ACCESS</span><span>${esc(String(programme.status || "active").toUpperCase())}</span></div>
                <div class="review-body">
                    <p class="form-note">${
                      ended
                        ? `Closed${programme.ended_at ? ` on ${esc(when(programme.ended_at))}` : ""}. Every account is refused at the download gate and at the command line, including accounts whose own access was still active.`
                        : "Open. Accounts with an active entitlement can download and use the command line."
                    }</p>
                    <form class="feedback-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="programme">
                        <div class="review-actions">
                            ${
                              ended
                                ? `<button class="button button-primary button-small" type="submit" name="status" value="active">REOPEN</button>`
                                : `<button class="button button-secondary button-small" type="submit" name="status" value="ended">END THE PROGRAMME</button>`
                            }
                        </div>
                    </form>
                </div>
            </div>`;
}

/** The legacy member/machine tables, kept for the account-holding admin too —
 *  the token door is not always the one someone came through. */
async function memberTables(db) {
  const members = await db
    .prepare(
      `SELECT m.key, m.email, m.name, m.created_at, m.updated_at,
              (SELECT COUNT(*) FROM devices d WHERE d.key = m.key) AS device_count
         FROM members m
        ORDER BY m.updated_at DESC
        LIMIT 500`,
    )
    .all();

  const devices = await db
    .prepare(
      `SELECT d.id, d.key, d.os, d.arch, d.version, d.last_seen, m.email
         FROM devices d
         LEFT JOIN members m ON m.key = d.key
        ORDER BY d.last_seen DESC
        LIMIT 500`,
    )
    .all();

  const memberRows = (members.results || []).map((r) => [
    shortKey(r.key),
    r.email || "—",
    r.name || "—",
    r.device_count,
    ago(r.updated_at),
  ]);

  const deviceRows = (devices.results || []).map((r) => [
    r.email || "—",
    shortKey(r.key),
    `${r.os || "?"} / ${r.arch || "?"}`,
    r.version || "—",
    r.id ? `${r.id.slice(0, 8)}…` : "—",
    ago(r.last_seen),
  ]);

  return `<p class="form-note">${memberRows.length} member(s), ${deviceRows.length} machine(s).</p>
                ${table(["KEY", "EMAIL", "NAME", "MACHINES", "LAST CONNECT"], memberRows)}
                ${table(["MEMBER", "KEY", "PLATFORM", "VERSION", "DEVICE", "LAST SEEN"], deviceRows)}`;
}

// --- the two doors ----------------------------------------------------------

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  if (db) {
    const session = await currentSession(db, request);
    if (session && (await isAdminUser(db, session.user.user_id))) {
      return review({ request, env, db, session });
    }
  }
  return page("Admin", prompt(""));
}

export async function onRequestPost({ request, env }) {
  const expected = await adminToken(env);
  if (!expected) {
    return page("Admin", prompt("No admin token is configured yet (KV key admin/token)."));
  }

  let form;
  try {
    form = await request.formData();
  } catch {
    return page("Admin", prompt("Bad submission."));
  }
  if (!isAdmin(form.get("token"), expected)) {
    return page("Admin", prompt("That token is not right."));
  }

  const db = env.KRYONSEC_DB;
  if (!db) return page("Admin", prompt("The database is not bound to this project."));

  return page(
    "Admin",
    `                <div class="section-bar"><span>KR / ADMIN</span><span>MEMBERS</span></div>
                <h2 id="admin-title">WHO IS<br><em>CONNECTED.</em></h2>
                ${await memberTables(db)}`,
  );
}
