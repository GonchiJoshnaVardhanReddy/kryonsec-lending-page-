/**
 * GET|POST /admin — the review desk and the operational dashboard.
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
 * The token door is a POST and the dashboard is a GET, which is the right way
 * round: a token in a query string lands in the browser history, the Referer,
 * and any proxy log, and the token has no expiry. The session cookie that opens
 * the dashboard is HttpOnly, SameSite, and expires.
 *
 * Every mutation lives in `api/admin/action.js` rather than here, because the
 * guard those actions need — session, then `admins`, then CSRF — is a single
 * thing and this file has no business having a second copy of it.
 *
 * The sections are views of the same route (`?view=`), not separate routes with
 * separate guards. One authorization check, one place to read it, one place to
 * get it wrong. Nothing on this page is trusted: every value is escaped, every
 * table cell defaults to escaped text, and no variable or secret value is ever
 * read into the markup — the security view reports presence, never contents.
 *
 * Environment: KRYONSEC_DB (D1), KRYONSEC_ADMIN_TOKEN or KV `admin/token`.
 */

import { csrfFor, currentSession, isAdminUser } from "./_auth.js";
import { betaPage, csrfField, notice, statusPill, when } from "./_pages.js";
import { esc, isAdmin, page } from "./_shared.js";
import {
  AUDIT_PREFIXES,
  countAllCliSessions,
  countApplications,
  countAudit,
  countUsers,
  listAccess,
  listAllCliSessions,
  listApplications,
  listAudit,
  listDevices,
  listOutbox,
  listUsers,
  overviewCounts,
  programmeStatus,
  queueCounts,
  schemaSnapshot,
  userAdminDetail,
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
  session_revoked: ["ok", "Website session revoked. That browser is signed out on its next request."],
  cli_revoked: ["ok", "Command-line session revoked. The machine is refused on its next check-in."],
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

// --- navigation -------------------------------------------------------------

const VIEWS = [
  ["overview", "OVERVIEW"],
  ["applications", "APPLICATIONS"],
  ["activity", "ACTIVITY"],
  ["users", "USERS & ACCESS"],
  ["devices", "DEVICES & CLI"],
  ["security", "SECURITY"],
];

const href = (view, params = {}) => {
  const search = new URLSearchParams({ view, ...params });
  return `/admin?${search}`;
};

function tabs(view) {
  const current = view === "user" ? "users" : view;
  const links = VIEWS.map(([key, label]) => {
    const cls = key === current ? "button button-primary button-small" : "button button-secondary button-small";
    return `<a class="${cls}" href="${esc(href(key))}">${esc(label)}</a>`;
  }).join(" ");
  return `<nav class="admin-tabs" aria-label="Admin sections">${links}</nav>`;
}

function pager({ view, params = {}, page, pages, label }) {
  if (pages <= 1) return "";
  const back = page > 1
    ? `<a class="button button-secondary button-small" href="${esc(href(view, { ...params, page: page - 1 }))}">PREVIOUS</a>`
    : "";
  const next = page < pages
    ? `<a class="button button-secondary button-small" href="${esc(href(view, { ...params, page: page + 1 }))}">NEXT</a>`
    : "";
  return `<div class="form-actions admin-pager">${back}<span class="form-note">PAGE ${page} / ${pages} · ${esc(label)}</span>${next}</div>`;
}

function searchForm({ view, params = {}, q = "", placeholder }) {
  const hidden = Object.entries(params)
    .filter(([name]) => name !== "page")
    .map(([name, value]) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`)
    .join("");
  return `<form class="admin-search" method="get" action="/admin">
                    <input type="hidden" name="view" value="${esc(view)}">${hidden}
                    <input type="search" name="q" value="${esc(q)}" maxlength="80" placeholder="${esc(placeholder)}" aria-label="${esc(placeholder)}">
                    <button class="button button-secondary button-small" type="submit">SEARCH</button>
                    ${q ? `<a class="button button-secondary button-small" href="${esc(href(view, params))}">CLEAR</a>` : ""}
                </form>`;
}

// --- cards ------------------------------------------------------------------

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

/** The programme switch. Ending it is stated as what it does, because the
 *  consequence lands on people who are not in the room. */
function programmeCard(programme, csrf) {
  const ended = programme.status === "ended";
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

/** An entitlement that exists, and the things that can be done to it. */
function accessCard(row, csrf) {
  const live = row.status === "active";
  return `<div class="review-card">
                <div class="review-head"><span>${esc(row.name || row.email || row.user_id)}</span><span>${esc(live ? "ACTIVE" : String(row.status).toUpperCase())}</span></div>
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

// --- overview ---------------------------------------------------------------

function statGrid(counts) {
  const items = [
    ["ACCOUNTS", counts.users, ""],
    ["PENDING REVIEW", counts.pending, ""],
    ["ACTIVE ACCESS", counts.active_access, ""],
    ["WEB SESSIONS", counts.live_sessions, ""],
    ["CLI MACHINES", counts.live_cli, ""],
    ["ADMINS", counts.admins, ""],
    ["REFUSED 24H", counts.refused_day, Number(counts.refused_day) ? "is-warn" : ""],
    ["FAILED MAIL", counts.failed_mail, Number(counts.failed_mail) ? "is-warn" : ""],
  ];
  return `<div class="stat-grid">${items
    .map(([label, value, tone]) => `<div class="stat ${tone}"><span>${esc(label)}</span><strong>${esc(Number(value || 0))}</strong></div>`)
    .join("")}</div>`;
}

/**
 * Configuration presence, never values.
 *
 * Reading a secret into a page — even into a comparison that renders only a
 * word — is how a secret ends up in a template cache or a debugger. Every row
 * below tests truthiness of an environment name and nothing else.
 */
async function configState(env) {
  const both = (id, secret) => Boolean(env[id]) && Boolean(env[secret]);
  const tokenConfigured = Boolean(await adminToken(env));
  return [
    ["DATABASE (KRYONSEC_DB)", "ok", "Bound."],
    ["FEEDBACK KV (KRYONSEC_FEEDBACK)", env.KRYONSEC_FEEDBACK ? "ok" : "warn", env.KRYONSEC_FEEDBACK ? "Bound." : "Not bound. Feedback storage and the KV admin-token lookup are unavailable."],
    ["GITHUB SIGN-IN", both("KRYONSEC_GITHUB_CLIENT_ID", "KRYONSEC_GITHUB_CLIENT_SECRET") ? "ok" : "warn", both("KRYONSEC_GITHUB_CLIENT_ID", "KRYONSEC_GITHUB_CLIENT_SECRET") ? "Client id and encrypted secret configured." : "Client id and/or secret not configured. GitHub sign-in is offered nowhere and its callback refuses."],
    ["GOOGLE SIGN-IN", both("KRYONSEC_GOOGLE_CLIENT_ID", "KRYONSEC_GOOGLE_CLIENT_SECRET") ? "ok" : "warn", both("KRYONSEC_GOOGLE_CLIENT_ID", "KRYONSEC_GOOGLE_CLIENT_SECRET") ? "Client id and encrypted secret configured." : "Client id and/or secret not configured. Google sign-in is offered nowhere and its callback refuses."],
    ["LEGACY ADMIN TOKEN", tokenConfigured ? "ok" : "warn", tokenConfigured ? "Configured (value never read into this page)." : "No token in KRYONSEC_ADMIN_TOKEN or KV admin/token. The read-only member door is closed."],
    ["EMAIL PROVIDER", env.KRYONSEC_EMAIL_PROVIDER ? "ok" : "warn", env.KRYONSEC_EMAIL_PROVIDER ? "Provider configured." : "No provider. Notifications are queued and marked sent without delivery (log mode)."],
    ["RELEASE REPOSITORY", env.KRYONSEC_REPO ? "ok" : "warn", env.KRYONSEC_REPO ? "Repository configured." : "KRYONSEC_REPO is unset, so release lookups have no source."],
  ];
}

async function overviewView({ env, db, csrf, session }) {
  const [counts, programme, applications, auditLog, outbox, config] = await Promise.all([
    overviewCounts(db),
    programmeStatus(db),
    listApplications(db, { status: "pending", limit: 5 }),
    listAudit(db, { limit: 10 }),
    listOutbox(db, { limit: 5 }),
    configState(env),
  ]);

  const warnings = config.filter(([, state]) => state === "warn").map(([name]) => `${name} is not configured`);
  if (Number(counts.failed_mail)) warnings.push(`${counts.failed_mail} notification(s) failed to send`);

  return `${tabs("overview")}
                ${statGrid(counts)}
                ${warnings.length ? notice("warn", `Needs attention: ${warnings.join("; ")}. See SECURITY.`) : ""}

                <h3>PROGRAMME</h3>
                ${programmeCard(programme, csrf)}

                <h3>PENDING APPLICATIONS</h3>
                <p>${Number(counts.pending || 0)} waiting. <a href="${esc(href("applications", { status: "pending" }))}">Open the queue</a>.</p>
                ${
                  applications.length
                    ? applications.map((a) => applicationCard(a, csrf)).join("")
                    : `<p class="review-empty">Nothing is pending.</p>`
                }

                <h3>AUDIT — RECENT ACTIVITY</h3>
                ${table(
                  ["WHEN", "ACTOR", "ACTION", "TARGET"],
                  auditLog.map((r) => [ago(r.created_at), r.actor, r.action, r.target || "—"]),
                )}
                <p><a href="${esc(href("activity"))}">All activity</a> · signed in as ${esc(session.user.email || session.user.user_id)}</p>

                <h3>NOTIFICATIONS</h3>
                ${table(
                  ["WHEN", "KIND", "TO", "STATUS", "ATTEMPTS"],
                  outbox.map((r) => [ago(r.created_at), r.kind, r.to_email, r.sent_at ? "sent" : r.status, r.attempts]),
                )}`;
}

// --- applications -----------------------------------------------------------

async function applicationsView({ db, csrf, url }) {
  const asked = url.searchParams.get("status") || "pending";
  const status = STATUSES.includes(asked) ? asked : "pending";
  const q = String(url.searchParams.get("q") || "").slice(0, 80);
  const askedPage = Math.max(1, Math.min(Number(url.searchParams.get("page")) || 1, 10_000));
  const size = 20;

  const [counts, total] = await Promise.all([
    queueCounts(db),
    countApplications(db, { status, q }),
  ]);
  // Clamp after the count is known, so `?page=999` lands on the last real page
  // rather than on an empty one that looks like a failed search.
  const pages = Math.max(1, Math.ceil(total / size));
  const page = Math.min(askedPage, pages);
  const applications = await listApplications(db, { status, q, limit: size, offset: (page - 1) * size });

  const filters = STATUSES.map((s) => {
    const label = `${FILTER_LABELS[s]} ${s === "all" ? "" : counts[s] ?? 0}`.trim();
    const cls = s === status ? "button button-primary button-small" : "button button-secondary button-small";
    return `<a class="${cls}" href="${esc(href("applications", q ? { status: s, q } : { status: s }))}">${esc(label)}</a>`;
  }).join(" ");

  const params = q ? { status, q } : { status };

  return `${tabs("applications")}
                <div class="form-actions">${filters}</div>
                ${searchForm({ view: "applications", params: { status }, q, placeholder: "SEARCH NAME, ACCOUNT, GITHUB" })}
                <p class="form-note">${total} application(s) matching. Showing at most ${size} per page.</p>
                ${
                  applications.length
                    ? applications.map((a) => applicationCard(a, csrf)).join("")
                    : `<p class="review-empty">Nothing matches that filter.</p>`
                }
                ${pager({ view: "applications", params, page, pages, label: `${total} total` })}`;
}

// --- activity ---------------------------------------------------------------

async function activityView({ db, url }) {
  const asked = String(url.searchParams.get("type") || "").toLowerCase();
  const prefix = AUDIT_PREFIXES.includes(asked) ? asked : "";
  const page = Math.max(1, Math.min(Number(url.searchParams.get("page")) || 1, 10_000));
  const size = 50;
  const total = await countAudit(db, { prefix });
  const pages = Math.max(1, Math.ceil(total / size));
  const actual = Math.min(page, pages);
  const rows = await listAudit(db, { prefix, limit: size, offset: (actual - 1) * size });

  const filters = ["", ...AUDIT_PREFIXES].map((key) => {
    const label = key ? key.toUpperCase() : "ALL";
    const cls = key === prefix ? "button button-primary button-small" : "button button-secondary button-small";
    return `<a class="${cls}" href="${esc(href("activity", key ? { type: key } : {}))}">${esc(label)}</a>`;
  }).join(" ");

  return `${tabs("activity")}
                <div class="form-actions">${filters}</div>
                <p class="form-note">${total} entr${total === 1 ? "y" : "ies"}. Append-only: the dashboard can read this table but has no control that edits or deletes it, and neither does the action route. Credentials are never written here.</p>
                ${table(
                  ["WHEN", "ACTOR", "ACTION", "TARGET", "BEFORE", "AFTER"],
                  rows.map((r) => [ago(r.created_at), r.actor, r.action, r.target || "—", r.before || "—", r.after || "—"]),
                )}
                ${pager({ view: "activity", params: prefix ? { type: prefix } : {}, page: actual, pages, label: `${total} total` })}`;
}

// --- users ------------------------------------------------------------------

async function usersView({ db, url }) {
  const q = String(url.searchParams.get("q") || "").slice(0, 80);
  const askedPage = Math.max(1, Math.min(Number(url.searchParams.get("page")) || 1, 10_000));
  const size = 50;
  const total = await countUsers(db, { q });
  const pages = Math.max(1, Math.ceil(total / size));
  const page = Math.min(askedPage, pages);
  const users = await listUsers(db, { q, limit: size, offset: (page - 1) * size });

  const rows = users.map((u) => [
    {
      html: `<a href="${esc(href("user", { id: u.id }))}">${esc(u.email)}</a><br><span class="form-note">${esc(u.name || "no name")} · ${esc(u.id)}</span>`,
    },
    u.entitlement_status ? { html: statusPill(u.entitlement_status) } : `<span class="form-note">no access row</span>`,
    u.live_sessions,
    u.live_cli,
    u.email_verified ? "verified" : "unverified",
    when(u.created_at),
  ]);

  return `${tabs("users")}
                ${searchForm({ view: "users", q, placeholder: "SEARCH EMAIL, NAME OR ID" })}
                <p class="form-note">${total} account(s). Access is a row in <code>entitlements</code>, not an application status; open an account to see both.</p>
                ${table(["ACCOUNT", "ACCESS", "WEB SESSIONS", "CLI MACHINES", "EMAIL", "CREATED"], rows)}
                ${pager({ view: "users", params: q ? { q } : {}, page, pages, label: `${total} total` })}`;
}

async function userView({ db, csrf, url }) {
  const id = String(url.searchParams.get("id") || "");
  const detail = await userAdminDetail(db, id);
  if (!detail) {
    return `${tabs("user")}<p class="review-empty">That account does not exist.</p>`;
  }

  const { user, entitlement, identities, application, sessions, cli, appEvents, entitlementEvents } = detail;
  const userId = user.id;

  const entitlementPanel = entitlement
    ? `<div class="review-card">
                <div class="review-head"><span>ENTITLEMENT</span><span>${esc(String(entitlement.status).toUpperCase())}</span></div>
                <div class="review-body">
                    <dl>
                        ${QUESTION("GRANTED", entitlement.granted_at ? when(entitlement.granted_at) : "")}
                        ${QUESTION("EXPIRES", entitlement.expires_at ? when(entitlement.expires_at) : "no individual expiry")}
                        ${QUESTION("CHANGED", entitlement.changed_at ? `${when(entitlement.changed_at)} by ${entitlement.changed_by || "—"}` : "")}
                        ${QUESTION("NOTE", entitlement.reason)}
                    </dl>
                    <form class="feedback-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="access">
                        <input type="hidden" name="user" value="${esc(userId)}">
                        <div class="review-actions">
                            <div class="form-field"><label for="ur-ent">NOTE (OPTIONAL)</label><input id="ur-ent" name="reason" type="text" maxlength="400" autocomplete="off"></div>
                            ${
                              entitlement.status === "active"
                                ? `<button class="button button-primary button-small" type="submit" name="action" value="revoke">REVOKE</button>
                            <button class="button button-secondary button-small" type="submit" name="action" value="suspend">SUSPEND</button>`
                                : `<button class="button button-primary button-small" type="submit" name="action" value="grant">RESTORE</button>`
                            }
                        </div>
                    </form>
                </div>
            </div>`
    : `<div class="review-card">
                <div class="review-head"><span>ENTITLEMENT</span><span>NONE</span></div>
                <div class="review-body">
                    <p class="form-note">No entitlement row. This account cannot download or use the command line${application?.status === "approved" ? ", although its application says approved — that is an inconsistency worth fixing by granting access." : "."}</p>
                    <form class="feedback-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="access">
                        <input type="hidden" name="user" value="${esc(userId)}">
                        <div class="review-actions">
                            <div class="form-field"><label for="ur-grant">NOTE (OPTIONAL)</label><input id="ur-grant" name="reason" type="text" maxlength="400" autocomplete="off"></div>
                            <button class="button button-primary button-small" type="submit" name="action" value="grant">GRANT ACCESS</button>
                        </div>
                    </form>
                </div>
            </div>`;

  const sessionRows = sessions.map((s) => [
    { html: `<code>${esc(s.token_hash.slice(0, 8))}…</code>` },
    when(s.created_at),
    when(s.last_seen_at),
    when(s.expires_at),
    {
      html: `<form class="admin-inline-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="session">
                        <input type="hidden" name="action" value="revoke">
                        <input type="hidden" name="user" value="${esc(user.id)}">
                        <input type="hidden" name="token" value="${esc(s.token_hash)}">
                        <button class="button button-secondary button-small" type="submit">REVOKE</button>
                    </form>`,
    },
  ]);

  const cliRows = cli.map((c) => [
    { html: `<code>${esc(c.token_prefix)}</code><br><span class="form-note">${esc(c.label || "machine")}</span>` },
    when(c.created_at),
    c.revoked_at ? { html: statusPill("revoked") } : when(c.last_used_at || c.created_at),
    when(c.expires_at),
    c.revoked_at
      ? `<span class="form-note">${esc(c.revoked_reason || "revoked")}</span>`
      : {
          html: `<form class="admin-inline-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="cli">
                        <input type="hidden" name="action" value="revoke">
                        <input type="hidden" name="user" value="${esc(user.id)}">
                        <input type="hidden" name="id" value="${esc(c.id)}">
                        <button class="button button-secondary button-small" type="submit">REVOKE</button>
                    </form>`,
        },
  ]);

  const identityRows = identities.map((i) => [i.provider, i.email || "—", i.email_verified ? "verified" : "unverified", when(i.created_at), when(i.last_login_at)]);

  return `${tabs("user")}
                <p><a href="${esc(href("users"))}">← All accounts</a></p>
                <div class="detail-grid">
                    <div><span>ACCOUNT</span><strong>${esc(user.email)}<br>${esc(user.name || "no name")}</strong></div>
                    <div><span>USER ID</span><strong><code>${esc(user.id)}</code></strong></div>
                    <div><span>CREATED</span><strong>${esc(when(user.created_at))}</strong></div>
                    <div><span>EMAIL</span><strong>${user.email_verified ? "verified" : "unverified"}</strong></div>
                </div>

                <h3>ACCESS</h3>
                ${entitlementPanel}

                <h3>APPLICATION</h3>
                ${
                  application
                    ? table(
                        ["STATUS", "SUBMITTED", "DECIDED", "DECIDED BY"],
                        [[{ html: statusPill(application.status) }, when(application.submitted_at), when(application.decided_at), application.decided_by || "—"]],
                      )
                    : `<p class="form-note">No active application.</p>`
                }
                ${table(["WHEN", "FROM", "TO", "ACTOR", "NOTE"], appEvents.map((e) => [when(e.created_at), e.from_status || "—", e.to_status, e.actor, e.note || "—"]))}

                <h3>SIGN-IN IDENTITIES</h3>
                ${table(["PROVIDER", "EMAIL", "VERIFIED", "LINKED", "LAST LOGIN"], identityRows)}

                <h3>WEBSITE SESSIONS</h3>
                <p class="form-note">A session is removed from the database immediately. The browser is signed out on its next request. The value shown is the first eight characters of the stored SHA-256, which is not a credential.</p>
                ${table(["SESSION", "CREATED", "LAST SEEN", "EXPIRES", ""], sessionRows)}

                <h3>COMMAND-LINE MACHINES</h3>
                <p class="form-note">Revoking ends the token on the server. The machine is refused on its next check-in, within the hour. Only the display prefix is stored or shown.</p>
                ${table(["MACHINE", "ADDED", "LAST USED", "EXPIRES", ""], cliRows)}

                <h3>ENTITLEMENT HISTORY</h3>
                ${table(["WHEN", "FROM", "TO", "ACTOR", "NOTE"], entitlementEvents.map((e) => [when(e.created_at), e.from_status || "—", e.to_status, e.actor, e.reason || "—"]))}`;
}

// --- devices / CLI ----------------------------------------------------------

async function devicesView({ db, csrf, url }) {
  const q = String(url.searchParams.get("q") || "").slice(0, 80);
  const askedPage = Math.max(1, Math.min(Number(url.searchParams.get("page")) || 1, 10_000));
  const size = 50;
  const total = await countAllCliSessions(db, { q });
  const pages = Math.max(1, Math.ceil(total / size));
  const page = Math.min(askedPage, pages);
  const [sessions, devices] = await Promise.all([
    listAllCliSessions(db, { q, limit: size, offset: (page - 1) * size }),
    listDevices(db, { q, limit: 100 }),
  ]);

  const cliRows = sessions.map((c) => [
    { html: `<a href="${esc(href("user", { id: c.user_id }))}">${esc(c.email)}</a>` },
    { html: `<code>${esc(c.token_prefix)}</code><br><span class="form-note">${esc(c.label || "machine")}</span>` },
    when(c.created_at),
    c.revoked_at ? { html: statusPill("revoked") } : when(c.last_used_at || c.created_at),
    when(c.expires_at),
    c.revoked_at
      ? `<span class="form-note">${esc(c.revoked_reason || "revoked")}</span>`
      : {
          html: `<form class="admin-inline-form" method="post" action="/api/admin/action">
                        ${csrfField(csrf)}
                        <input type="hidden" name="intent" value="cli">
                        <input type="hidden" name="action" value="revoke">
                        <input type="hidden" name="id" value="${esc(c.id)}">
                        <button class="button button-secondary button-small" type="submit">REVOKE</button>
                    </form>`,
        },
  ]);

  const legacyRows = devices.map((d) => [
    d.email || "—",
    shortKey(d.key),
    `${d.os || "?"} / ${d.arch || "?"}`,
    d.version || "—",
    d.id ? `${d.id.slice(0, 8)}…` : "—",
    ago(d.last_seen),
  ]);

  const members = await db
    .prepare(
      `SELECT m.key, m.email, m.name, m.created_at, m.updated_at,
              (SELECT COUNT(*) FROM devices d WHERE d.key = m.key) AS device_count
         FROM members m ORDER BY m.updated_at DESC LIMIT 500`,
    )
    .all();

  const memberRows = (members.results || []).map((r) => [shortKey(r.key), r.email || "—", r.name || "—", r.device_count, ago(r.updated_at)]);

  return `${tabs("devices")}
                <h3>COMMAND-LINE SESSIONS</h3>
                ${searchForm({ view: "devices", q, placeholder: "SEARCH ACCOUNT, LABEL OR PREFIX" })}
                <p class="form-note">${total} command-line session(s), live and revoked. Tokens are stored hashed; only the display prefix exists.</p>
                ${table(["ACCOUNT", "MACHINE", "ADDED", "LAST USED", "EXPIRES", ""], cliRows)}
                ${pager({ view: "devices", params: q ? { q } : {}, page, pages, label: `${total} total` })}

                <h3>LEGACY DEVICES</h3>
                <p class="form-note">The membership-key model. Read-only here: a key is all-or-nothing, so there is no per-machine switch to offer. Revoking a key is an environment change, not a dashboard action.</p>
                ${table(["MEMBER", "KEY", "PLATFORM", "VERSION", "DEVICE", "LAST SEEN"], legacyRows)}

                <h3>LEGACY MEMBERS</h3>
                ${table(["KEY", "EMAIL", "NAME", "MACHINES", "LAST CONNECT"], memberRows)}`;
}

// --- security ---------------------------------------------------------------

async function securityView({ env, db }) {
  const [counts, config, schema] = await Promise.all([
    overviewCounts(db),
    configState(env),
    schemaSnapshot(db),
  ]);

  const configRows = config.map(([name, state, detail]) => [
    name,
    { html: `<span class="status-pill ${state === "ok" ? "is-ok" : "is-warn"}">${state === "ok" ? "CONFIGURED" : "DEGRADED"}</span>` },
    detail,
  ]);

  const hygiene = [
    ["Administrators", counts.admins, counts.admins ? "" : "No account can open this desk."],
    ["Unverified accounts", counts.unverified, counts.unverified ? "Signed in with a provider that did not assert a verified address." : ""],
    ["Live website sessions", counts.live_sessions, ""],
    ["Expired session rows", counts.expired_sessions, counts.expired_sessions ? "Removed lazily when the cookie is next presented." : ""],
    ["Live CLI sessions", counts.live_cli, ""],
    ["Queued notifications", counts.queued_mail, ""],
    ["Failed notifications", counts.failed_mail, counts.failed_mail ? "A mail adapter is missing or a send failed; decisions are still recorded." : ""],
    ["Refused privileged requests (24h)", counts.refused_day, counts.refused_day ? "Includes non-admin attempts, CSRF failures, invalid parameters and throttled attempts." : ""],
    ["Audit entries (24h)", counts.audit_day, ""],
  ];

  const refused = await listAudit(db, { prefix: "admin", limit: 25, offset: 0 });

  return `${tabs("security")}
                <h3>CONFIGURATION</h3>
                <p class="form-note">Presence only. No variable or secret value is read into this page, logged, or written to the database.</p>
                ${table(["SETTING", "STATE", "DETAIL"], configRows)}

                <h3>SCHEMA</h3>
                ${
                  schema.missing.length
                    ? notice("error", `Missing required table(s): ${schema.missing.join(", ")}. Apply migrations/0000–0002 before this build serves traffic.`)
                    : `<p class="form-note">All ${schema.required} required tables are present.</p>`
                }

                <h3>ACCESS AND HYGIENE</h3>
                ${table(["MEASURE", "VALUE", "NOTE"], hygiene.map(([a, b, c]) => [a, b, c || "—"]))}

                <h3>AUDIT INTEGRITY</h3>
                <p class="form-note">The audit table is append-only. This dashboard renders it and offers no edit or delete; the action route only inserts. A failed privileged request is recorded with the account that made it and never with a credential.</p>
                ${table(
                  ["WHEN", "ACTOR", "ACTION", "TARGET"],
                  refused.map((r) => [ago(r.created_at), r.actor, r.action, r.target || "—"]),
                )}`;
}

// --- the token door's member tables ----------------------------------------

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

// --- dispatch ---------------------------------------------------------------

async function review({ request, env, db, session }) {
  const url = new URL(request.url);
  const asked = url.searchParams.get("view") || "overview";
  const view = [...VIEWS.map(([key]) => key), "user"].includes(asked) ? asked : "overview";

  const csrf = await csrfFor(session.token);
  const outcome = OUTCOMES[url.searchParams.get("msg") || ""];
  const actor = session.user.email || session.user.user_id;

  let body;
  switch (view) {
    case "applications":
      body = await applicationsView({ db, csrf, url });
      break;
    case "activity":
      body = await activityView({ db, url });
      break;
    case "users":
      body = await usersView({ db, url });
      break;
    case "user":
      body = await userView({ db, csrf, url });
      break;
    case "devices":
      body = await devicesView({ db, csrf, url });
      break;
    case "security":
      body = await securityView({ env, db });
      break;
    default:
      body = await overviewView({ env, db, csrf, session });
  }

  const headings = {
    overview: ["OPERATIONS", "AT A GLANCE."],
    applications: ["WHO GETS", "IN."],
    activity: ["WHAT WAS", "DONE."],
    users: ["WHO IS", "HERE."],
    user: ["ONE", "ACCOUNT."],
    devices: ["WHERE IT", "RUNS."],
    security: ["WHAT IS", "EXPOSED."],
  };
  const [heading, accent] = headings[view];

  return betaPage({
    title: "Admin",
    kicker: "KR / ADMIN",
    right: "ADMINS ONLY",
    heading,
    accent,
    lede: `Signed in as ${actor}. Every action here is written to the audit log, and none of it is reversible without another entry.`,
    notice: outcome ? notice(outcome[0], outcome[1]) : "",
    session,
    admin: true,
    csrf,
    wide: true,
    body,
  });
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
