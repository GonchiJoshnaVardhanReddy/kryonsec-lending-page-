/**
 * GET|POST /admin
 *
 * You, looking at who is connected. Deliberately a page and not a JSON API:
 * it takes a token in a form post, so the token stays out of the URL, the
 * browser history, and any proxy log.
 *
 * There is no admin account and no session — the token is the whole
 * authorisation, checked on every request with a timing-safe compare. An unset
 * KRYONSEC_ADMIN_TOKEN denies everyone; a missing secret must never mean "no
 * password needed".
 *
 *   GET  -> the token prompt
 *   POST -> the tables (members, and the machines seen for each)
 *
 * Environment: KRYONSEC_ADMIN_TOKEN (secret), KRYONSEC_DB (D1).
 */

import { esc, isAdmin, page } from "./_shared.js";

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

function table(headers, rows) {
  if (!rows.length) return `<p class="form-note">Nothing here yet.</p>`;
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join("");
  const body = rows
    .map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`)
    .join("");
  return `<div class="admin-table-wrap"><table class="admin-table">
                    <thead><tr>${head}</tr></thead>
                    <tbody>${body}</tbody>
                </table></div>`;
}

export async function onRequestGet() {
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

  return page(
    "Admin",
    `                <div class="section-bar"><span>KR / ADMIN</span><span>MEMBERS</span></div>
                <h2 id="admin-title">WHO IS<br><em>CONNECTED.</em></h2>
                <p class="form-note">${memberRows.length} member(s), ${deviceRows.length} machine(s). Read-only.</p>

                <h3>MEMBERS</h3>
                ${table(["KEY", "EMAIL", "NAME", "MACHINES", "LAST CONNECT"], memberRows)}

                <h3>MACHINES</h3>
                <p class="form-note">A machine appears here once it has connected or checked in. <code>kryonsec doctor</code> reports a machine's own view of this.</p>
                ${table(["MEMBER", "KEY", "PLATFORM", "VERSION", "DEVICE", "LAST SEEN"], deviceRows)}`,
  );
}
