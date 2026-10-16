/**
 * The pieces every signed-in page is built from.
 *
 * Import-only: never served.
 *
 * These pages live under the same CSP as the rest of the site — `style-src
 * 'self'` and `script-src 'self'`, no inline anything. So there is no style
 * attribute here, no `onclick`, and nowhere for a stray `innerHTML` to go even
 * if someone later wanted one. Every visual state is a class in style.css and
 * every value goes through `esc()`. That is not a restriction to work around;
 * it is why an applicant's own text cannot become script on a page an admin
 * reads.
 */

import { esc, page } from "./_shared.js";

// --- the shell --------------------------------------------------------------

/**
 * The account links in the header.
 *
 * Sign out is a POST, not a link. A GET sign-out is the one CSRF that reads
 * as harmless — the worst an attacker gets is logging you out — but it is
 * still a state change driven by a cross-site request, and the CSRF token
 * already exists on every one of these pages. Using it costs nothing.
 */
function navFor({ session, admin, csrf }) {
  if (!session) {
    return `<nav class="site-nav account-nav" aria-label="Account"><a href="/signin">SIGN IN</a></nav>`;
  }
  return `<nav class="site-nav account-nav" aria-label="Account">
                <a href="/dashboard">DASHBOARD</a>
                ${admin ? `<a href="/admin">REVIEW</a>` : ""}
                <form class="nav-form" method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="nav-button" type="submit">SIGN OUT</button></form>
            </nav>`;
}

/**
 * A page in the site's chrome.
 *
 * `heading` and `accent` are plain strings and both get escaped — the markup
 * convention on this site is a two-line heading with the second line in the
 * accent colour, and making that a pair of arguments means no caller has to
 * hand-assemble HTML to get it.
 */
export function betaPage({
  title,
  kicker,
  right = "",
  heading,
  accent = "",
  lede = "",
  notice = "",
  body = "",
  session = null,
  admin = false,
  csrf = "",
  wide = false,
  status = 200,
}) {
  const markup = `                <div class="section-bar"><span>${esc(kicker)}</span><span>${esc(right)}</span></div>
                <h2>${esc(heading)}${accent ? `<br><em>${esc(accent)}</em>` : ""}</h2>
                ${lede ? `<p class="form-note">${esc(lede)}</p>` : ""}
                ${notice}
${body}`;

  return page(title, markup, status, {
    nav: navFor({ session, admin, csrf }),
    shellClass: wide ? "is-wide" : "",
  });
}

/** An error or informational banner. `kind` picks the border colour. */
export function notice(kind, message) {
  const tone = { error: "is-bad", warn: "is-warn", ok: "is-ok" }[kind] || "";
  return `<p class="form-static-note ${tone}" role="alert">${esc(message)}</p>`;
}

/** The status of an application or an entitlement, as a labelled pill. */
const STATUS_LABELS = {
  pending: ["IN REVIEW", "is-pending"],
  approved: ["APPROVED", "is-ok"],
  rejected: ["NOT ACCEPTED", "is-bad"],
  waitlisted: ["WAITLISTED", "is-pending"],
  active: ["ACTIVE", "is-ok"],
  suspended: ["SUSPENDED", "is-warn"],
  revoked: ["REVOKED", "is-bad"],
  expired: ["EXPIRED", "is-warn"],
  ended: ["PROGRAMME ENDED", "is-bad"],
  none: ["NO ACCESS YET", "is-idle"],
  programme_ended: ["PROGRAMME ENDED", "is-bad"],
  anonymous: ["NOT SIGNED IN", "is-idle"],
  unknown: ["UNKNOWN", "is-bad"],
};

export function statusPill(status, label = null) {
  const [text, tone] = STATUS_LABELS[status] || [String(status).toUpperCase(), "is-idle"];
  return `<span class="status-pill ${tone}">${esc(label || text)}</span>`;
}

// --- form pieces ------------------------------------------------------------

/**
 * A labelled control.
 *
 * `hint` renders as the same `.form-note` the rest of the site uses. `required`
 * is passed through to the browser AND relied on by the handler — the browser
 * attribute is a convenience for the person, the server check is the one that
 * counts, and both exist because a form that only checks one way is either
 * annoying or unsafe.
 */
export function field({
  name,
  label,
  type = "text",
  value = "",
  required = false,
  placeholder = "",
  autocomplete = "",
  maxlength = 0,
  hint = "",
  full = false,
  rows = 0,
}) {
  const id = `f-${name}`;
  const attrs = [
    `id="${id}"`,
    `name="${esc(name)}"`,
    required ? "required" : "",
    placeholder ? `placeholder="${esc(placeholder)}"` : "",
    autocomplete ? `autocomplete="${esc(autocomplete)}"` : "",
    maxlength ? `maxlength="${Number(maxlength)}"` : "",
  ].filter(Boolean).join(" ");

  // A textarea is the same field with different tags — an applicant writing
  // three paragraphs in a one-line input is the fastest way to lose them.
  const control = rows
    ? `<textarea ${attrs} rows="${Number(rows)}">${esc(value)}</textarea>`
    : `<input ${attrs} type="${esc(type)}" value="${esc(value)}">`;

  return `<div class="form-field${full ? " form-field-full" : ""}">
                    <label for="${id}">${esc(label)}${required ? " *" : ""}</label>
                    ${control}
                    ${hint ? `<p class="form-note">${esc(hint)}</p>` : ""}
                </div>`;
}

/** A dropdown. `options` is a list of strings; `value` is preselected. */
export function select({ name, label, options, value = "", full = true, hint = "" }) {
  const id = `f-${name}`;
  const body = options
    .map((o) => `<option value="${esc(o)}"${o === value ? " selected" : ""}>${esc(o)}</option>`)
    .join("");
  return `<div class="form-field${full ? " form-field-full" : ""}">
                    <label for="${id}">${esc(label)}</label>
                    <select id="${id}" name="${esc(name)}"><option value="">—</option>${body}</select>
                    ${hint ? `<p class="form-note">${esc(hint)}</p>` : ""}
                </div>`;
}

export function checkbox({ name, label, checked = false, hint = "" }) {
  const id = `f-${name}`;
  return `<div class="form-field form-field-full check-field">
                    <label class="check-label" for="${id}"><input id="${id}" name="${esc(name)}" type="checkbox" value="1"${checked ? " checked" : ""}> <span>${esc(label)}</span></label>
                    ${hint ? `<p class="form-note">${esc(hint)}</p>` : ""}
                </div>`;
}

/** The hidden field every POST on this site carries. */
export const csrfField = (token) =>
  `<input type="hidden" name="csrf" value="${esc(token)}">`;

// --- small renderers --------------------------------------------------------

/** A definition row for the read-only panels on the dashboard. */
export const detail = (label, value, raw = false) =>
  `<div><span>${esc(label)}</span><strong>${raw ? value : esc(value || "—")}</strong></div>`;

/**
 * A friendly date, from a stored ISO string.
 *
 * Deliberately coarse. "3 days ago" is what a person waiting on a decision
 * wants; the exact second is in the audit table for anyone who needs it. An
 * unparseable value renders as a dash rather than "Invalid Date".
 */
export function when(iso) {
  if (!iso) return "—";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "—";

  const days = Math.floor((Date.now() - then.getTime()) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;

  // An absolute date once "days ago" stops being useful to read.
  return then.toISOString().slice(0, 10);
}

/** The current path, for building `?next=` links that do not lose the place. */
export const here = (request) => new URL(request.url).pathname;
