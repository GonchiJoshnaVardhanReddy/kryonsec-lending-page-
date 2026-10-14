/**
 * GET /connect?code=XXXX-XXXX
 *
 * The page the CLI opens. It is the whole "sign in" of the connect flow, and
 * it has no password: the membership key is the credential, and having run
 * `kryonsec connect` on a machine holding that key IS the proof. This page's
 * job is to record who that key belongs to, so the dashboard can say which
 * member is on which machine.
 *
 * All the writing happens on POST to /api/device/claim; this page only
 * renders. A failure there comes back here as ?e=<reason>, which is why the
 * form lives in exactly one file.
 *
 * noindex: a connect URL is personal and one-time. It must not be crawled.
 */

import { cleanCode, esc, page } from "./_shared.js";

const ERRORS = {
  email: "That email address does not look right. Check it and try again.",
  code: "That connect code is not valid. Copy it from the terminal again.",
  unknown:
    "That connect code is not recognised. It may already have been used — run <code>kryonsec connect</code> again for a new one.",
  expired:
    "That connect code has expired. Run <code>kryonsec connect</code> again for a new one.",
  used: "That code has already been used. Run <code>kryonsec connect</code> again for a new one.",
  notconf: "Connect is not configured on this site yet.",
};

function fields(code) {
  if (!code) {
    // Opened from a bookmark or typed by hand — ask for the code instead.
    return `<div class="form-field form-field-full"><label for="connect-code">CONNECT CODE *</label><input id="connect-code" name="code" type="text" inputmode="latin" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX" required></div>`;
  }
  return `<input type="hidden" name="code" value="${esc(code)}">
                        <p class="form-note">Code <b>${esc(code)}</b> — it should be the same one your terminal printed.</p>`;
}

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const code = cleanCode(url.searchParams.get("code"));
  const reason = String(url.searchParams.get("e") || "");
  const message = ERRORS[reason];

  const notice = message
    ? `<p class="form-static-note" role="alert">${message}</p>`
    : "";

  return page(
    "Connect this machine",
    `                <div class="section-bar"><span>KR / CONNECT</span><span>AUTHORISE THIS MACHINE</span></div>
                <h2 id="connect-title">CONNECT<br><em>THIS MACHINE.</em></h2>
                <p class="form-note">Kryonsec opened this page from the machine that is asking to connect. Confirm your email and that machine is registered to your membership.</p>
                ${notice}
                <form class="feedback-form" method="post" action="/api/device/claim">
                    ${fields(code)}
                    <div class="form-field form-field-full"><label for="connect-email">MAIL *</label><input id="connect-email" name="email" type="email" autocomplete="email" required></div>
                    <div class="form-field form-field-full"><label for="connect-name">NAME</label><input id="connect-name" name="name" type="text" autocomplete="name"></div>
                    <div class="form-actions"><button class="button button-primary" type="submit">CONNECT <span aria-hidden="true">↗</span></button></div>
                </form>
                <p class="form-note">Your membership key is the credential — this page never asks for it and never stores a password. It records which member this machine belongs to.</p>`,
  );
}
