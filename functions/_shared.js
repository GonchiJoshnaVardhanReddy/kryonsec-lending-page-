/**
 * Helpers shared by the Pages Functions in this directory.
 *
 * Import-only: the Pages router ignores paths that start with an underscore,
 * so this file is never served.
 */

import { timingSafeEqual } from "./api/download.js";

// --- responses --------------------------------------------------------------

export function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      // Every response here is tied to one member's key or one admin session.
      // A shared cache holding it would hand it to the next caller.
      "Cache-Control": "no-store",
    },
  });
}

export function html(markup, status = 200) {
  return new Response(markup, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

/**
 * Send the browser somewhere else.
 *
 * 303, not 302: a redirect that follows a POST has to turn the follow-up into
 * a GET, or a refresh re-submits the form. Every redirect on this site is
 * either a GET in the first place or a form submission, and 303 is correct for
 * both.
 *
 * `Location` is only ever given a value this code built or a path that has
 * been through `safeNext()` — a redirect assembled from a query parameter is
 * an open redirect, which is how a link on our own domain ends up on someone
 * else's page.
 */
export function redirect(location, status = 303) {
  return new Response(null, {
    status,
    headers: { Location: location, "Cache-Control": "no-store" },
  });
}

// --- randomness -------------------------------------------------------------

// Crockford base32 minus 0/O and 1/I — the alphabet the membership keys use,
// so a code a member reads off one screen and types into another cannot be
// mistyped into a different valid code.
const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/** An 8-character user code, shown to the member as "XXXX-XXXX". */
export function randomCode() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) {
    // 256 % 32 === 0, so the modulo is uniform — no bias to correct for
    out += CODE_ALPHABET[b % CODE_ALPHABET.length];
  }
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

/** A hex secret of `bytes` bytes. The device_code never leaves the CLI. */
export function randomToken(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const nowIso = () => new Date().toISOString();

/** ISO timestamp `minutes` in the past — what "older than an hour" compares to. */
export function isoAgo(minutes) {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

// ISO-8601 UTC strings sort lexicographically, which is why created_at can be
// compared to one of these with a plain `<` in SQL.

// --- input ------------------------------------------------------------------

const CODE_RE = /^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{4}$/;

export function cleanCode(value) {
  const code = String(value || "").trim().toUpperCase();
  return CODE_RE.test(code) ? code : "";
}

/** A plausible address, or "". Deliberately not RFC 5322 — this is a label. */
export function cleanEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (email.length < 6 || email.length > 254) return "";
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) ? email : "";
}

/** Free text, collapsed to one line and capped. */
export function cleanText(value, max) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
}

/** A device id is opaque hex the CLI generated; anything else is dropped. */
export function cleanDeviceId(value) {
  const id = String(value || "").trim().toLowerCase();
  return /^[0-9a-f]{8,64}$/.test(id) ? id : "";
}

export function esc(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]),
  );
}

// --- shared behaviours ------------------------------------------------------

/** Codes and sessions both stop working after this long. */
export const CODE_TTL_MIN = 15;

/**
 * Does this admin token match? Empty/unset config denies everyone — an unset
 * secret must never mean "no password required".
 */
export function isAdmin(token, configured) {
  const expected = String(configured || "");
  if (!expected) return false;
  const given = String(token || "");
  if (given.length !== expected.length) return false;
  return timingSafeEqual(expected, given);
}

// --- the page shell ---------------------------------------------------------

/**
 * The site's own chrome, so these pages do not look like a different site.
 *
 * `nav` renders inside the header's flex row, to the right of the brand — the
 * account links on the beta pages. `shellClass` widens the content column for
 * pages that are tables rather than a form. Both default to the original
 * behaviour, so the pages written before either existed are unchanged.
 */
export function page(title, body, status = 200, { nav = "", shellClass = "" } = {}) {
  return html(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)} — Kryonsec</title>
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&family=VT323&display=swap" rel="stylesheet">
<script src="/theme-init.js"></script>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>
<header class="site-header">
    <div class="container header-inner">
        <a class="brand" href="/" aria-label="Kryonsec home"><img class="brand-mark" src="/assets/octopus-reference.png" alt="" width="32" height="32" aria-hidden="true"><span>KRYONSEC</span></a>
        ${nav}
    </div>
</header>
<main id="main-content">
<section class="section">
    <div class="container">
        <div class="feedback-form-shell${shellClass ? ` ${shellClass}` : ""}">
${body}
        </div>
    </div>
</section>
</main>
</body>
</html>`, status);
}
