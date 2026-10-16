/**
 * GET /beta/device?code=XXXX-XXXX — "is this you?"
 *
 * The page `kryonsec login` opens. It is the whole browser half of the flow,
 * and it renders only: every write is a POST to /api/beta/device/approve, so
 * the form lives in one file and a failure can come back here as a reason
 * code.
 *
 * It shows the machine before it asks. That is not decoration — RFC 8628
 * calls the failure it prevents a "mix-up", and it is the obvious one here: a
 * person with two terminals open approves the wrong one, and the mistake is
 * invisible until a machine they do not recognise appears in their dashboard.
 * The device id is truncated because it is a random value, not an address;
 * what a person can actually check is the OS, the architecture and the
 * version.
 *
 * Signed-in only, and *entitled* only. Both are checked here for the message
 * and again on the POST for the decision — a page that was rendered before a
 * revocation must not be the thing that decides.
 *
 * noindex: the URL carries a code, and the code is personal even though it is
 * not a credential.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import { csrfFor, currentSession } from "../_auth.js";
import { betaPage, notice } from "../_pages.js";
import { CODE_TTL_MIN, cleanCode, esc, isoAgo, redirect } from "../_shared.js";
import { accessFor } from "../_store.js";

/** Reason codes come back in the URL, so the sentences live here. */
const MESSAGES = {
  approved: ["ok", "Approved. Go back to your terminal — it will pick this up on its own."],
  denied: ["warn", "Denied. Nothing was granted and the terminal has been told."],
  stale: [
    "warn",
    `That code has already been used, denied, or has expired (they last ${CODE_TTL_MIN} minutes). Run \`kryonsec login\` again for a new one.`,
  ],
};

const field = (label, value) =>
  value ? `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>` : "";

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  const url = new URL(request.url);
  const session = await currentSession(db, request);
  if (!session) {
    return redirect(`/signin?next=${encodeURIComponent(`${url.pathname}${url.search}`)}`);
  }

  const code = cleanCode(url.searchParams.get("code"));
  if (!code) return render({ session, csrf: await csrfFor(session.token), message: "", machine: null });

  const row = await db
    .prepare("SELECT code, device_id, os, arch, version, created_at, approved_at, denied_at FROM cli_login_codes WHERE code = ?")
    .bind(code)
    .first();

  const access = await accessFor(db, session.user.user_id);
  const csrf = await csrfFor(session.token);

  // A code that is unknown, expired, or already decided renders the same
  // "not there any more" panel. Telling them apart would make this page a way
  // to test whether a guessed code once existed.
  const live = row && !row.approved_at && !row.denied_at && row.created_at > isoAgo(CODE_TTL_MIN);
  if (!live) {
    return render({
      session,
      csrf,
      message: row && !row.approved_at && !row.denied_at ? "expired" : "stale",
      machine: null,
      status: 410,
    });
  }

  return render({
    session,
    csrf,
    message: url.searchParams.get("e") || "",
    machine: row,
    entitled: access.entitled,
    reason: access.reason,
  });
}

function render({ session, csrf, message, machine, entitled = false, reason = "", status = 200 }) {
  const said = MESSAGES[message];
  const banner = said
    ? notice(said[0], said[1])
    : message === "expired"
      ? notice("warn", `That code expired. They last ${CODE_TTL_MIN} minutes — run \`kryonsec login\` again.`)
      : "";

  if (!machine) {
    return betaPage({
      title: "Authorise a sign-in",
      kicker: "KR / DEVICE",
      right: "SIGN-IN",
      heading: "THAT CODE IS",
      accent: "NO LONGER LIVE.",
      lede: "Sign-in codes are single-use and short-lived. Nothing was granted, and nothing needs undoing.",
      notice: banner,
      body: `<div class="form-actions"><a class="button button-secondary" href="/dashboard">BACK TO THE DASHBOARD</a></div>`,
      session,
      csrf,
      status,
    });
  }

  if (!entitled) {
    return betaPage({
      title: "Authorise a sign-in",
      kicker: "KR / DEVICE",
      right: "SIGN-IN",
      heading: "THIS ACCOUNT CANNOT",
      accent: "AUTHORISE.",
      lede: "A machine is signed in as the account that approves it, so approving needs an account with active access.",
      notice: notice("warn", reason || "This account has no active access."),
      body: `<div class="form-actions"><a class="button button-secondary" href="/dashboard">BACK TO THE DASHBOARD</a></div>`,
      session,
      csrf,
      status: 403,
    });
  }

  return betaPage({
    title: "Authorise a sign-in",
    kicker: "KR / DEVICE",
    right: "SIGN-IN",
    heading: "A MACHINE WANTS",
    accent: "TO SIGN IN.",
    lede: `If you just ran \`kryonsec login\`, this is it. Approving signs that machine in as ${session.user.email}, and it stays signed in until you revoke it or it expires.`,
    notice: banner,
    body: `                <div class="review-card">
                    <div class="review-head"><span>THE MACHINE</span><span>CODE ${esc(machine.code)}</span></div>
                    <div class="review-body">
                        <dl>
                            ${field("PLATFORM", [machine.os, machine.arch].filter(Boolean).join(" / "))}
                            ${field("VERSION", machine.version)}
                            ${field("DEVICE", machine.device_id ? `${String(machine.device_id).slice(0, 12)}…` : "")}
                            ${field("ASKED", `${Math.max(0, Math.round((Date.now() - Date.parse(machine.created_at)) / 60000))} minute(s) ago`)}
                        </dl>
                        <p class="form-note">Check the platform and version match the machine in front of you. If you did not run <code>kryonsec login</code>, deny it — approving would give whoever did access to this account.</p>
                        <form class="feedback-form" method="post" action="/api/beta/device/approve">
                            <input type="hidden" name="csrf" value="${esc(csrf)}">
                            <input type="hidden" name="code" value="${esc(machine.code)}">
                            <div class="review-actions">
                                <button class="button button-primary button-small" type="submit" name="decision" value="approve">APPROVE THIS MACHINE</button>
                                <button class="button button-secondary button-small" type="submit" name="decision" value="deny">DENY</button>
                            </div>
                        </form>
                    </div>
                </div>`,
    session,
    csrf,
    wide: true,
    status,
  });
}
