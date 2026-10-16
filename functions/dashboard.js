/**
 * GET /dashboard — the applicant's own page.
 *
 * One page, several states, and the state is never guessed: `accessFor()` is
 * asked once and everything below is a rendering of its answer. The dashboard
 * does not decide whether anyone has access — it cannot, because the download
 * gate and the license endpoint ask the same function and would disagree.
 *
 * The install command is built here, at page-render time, around a fresh
 * single-use token. That is deliberate and it is the whole reason the token
 * lives in the query string: an installer instruction has to be copy-pasteable,
 * and the only way to make a copy-pasteable credential safe is to make it
 * worthless within minutes. It is not the person's account, it cannot be used
 * twice, and reloading this page mints a new one.
 */

import { csrfFor, currentSession, isAdminUser } from "./_auth.js";
import { listCliSessions, mintDownloadToken } from "./_cli.js";
import { betaPage, detail, notice, statusPill, when } from "./_pages.js";
import { CODE_TTL_MIN, esc, redirect } from "./_shared.js";
import { accessFor, listIdentities } from "./_store.js";

const PROVIDER_NAMES = { google: "Google", github: "GitHub" };

const identityLabel = (identities) =>
  identities.map((i) => PROVIDER_NAMES[i.provider] || i.provider).join(" + ") || "—";

const facts = (...rows) => `<div class="detail-grid">${rows.filter(Boolean).join("")}</div>`;

/** A bordered panel with a numbered header — the shape the review view uses,
 *  reused here so a signed-in page reads as one design and not three. */
const card = (kicker, right, body) =>
  `<div class="review-card">
                <div class="review-head"><span>${esc(kicker)}</span><span>${esc(right)}</span></div>
                <div class="review-body">${body}</div>
            </div>`;

/** A copy-pasteable command, in the component the landing page already uses. */
const command = (text) => `<div class="install-command"><code>${esc(text)}</code></div>`;

/**
 * The machines signed in to this account, and the way to turn one off.
 *
 * The revoke button is a form and not a link because it changes something —
 * a GET that revoked would be revocable by any image tag on any page. It
 * carries no confirmation dialogue: the action is "sign this machine out",
 * it is easily undone by signing in again, and a modal on a page like this is
 * a way to teach people to click through modals.
 *
 * Revoked rows stay in the table. A machine that disappears when it is cut off
 * cannot be told apart from one that was never there, and "which of my
 * machines did I turn off" is the question this table exists to answer.
 */
function machinesCard(rows, csrf) {
  if (!rows.length) {
    return card(
      "02 / THE COMMAND LINE",
      "NO MACHINES YET",
      `<p class="form-note">Run <code>kryonsec login</code> on the machine you want to use, then approve it here. Nothing is signed in yet.</p>
                    ${command("kryonsec login")}`,
    );
  }

  const live = rows.filter((r) => !r.revoked_at);
  // Every cell is `{html}` rather than a bare string: `esc(when(…))` is what
  // keeps a value that came out of the database from being markup, and the two
  // cells that *are* markup say so explicitly instead of by accident.
  const cells = rows.slice(0, 10).map((r) => {
    const revoked = Boolean(r.revoked_at);
    return [
      {
        html: `<code>${esc(r.token_prefix)}</code><br><span class="form-note">${esc(r.label || "machine")}</span>`,
      },
      { html: esc(when(r.created_at)) },
      { html: revoked ? statusPill("revoked") : esc(when(r.last_used_at || r.created_at)) },
      {
        html: revoked
          ? `<span class="form-note">signed out</span>`
          : `<form class="feedback-form" method="post" action="/api/beta/machines">
                            <input type="hidden" name="csrf" value="${esc(csrf)}">
                            <input type="hidden" name="id" value="${esc(r.id)}">
                            <input type="hidden" name="intent" value="revoke">
                            <button class="button button-secondary button-small" type="submit">SIGN OUT</button>
                        </form>`,
      },
    ];
  });

  const head = ["MACHINE", "ADDED", "LAST SEEN", ""].map((h) => `<th>${esc(h)}</th>`).join("");
  const body = cells.map((r) => `<tr>${r.map((c) => `<td>${c.html}</td>`).join("")}</tr>`).join("");

  return card(
    "02 / THE COMMAND LINE",
    `${live.length} SIGNED IN`,
    `<p class="form-note">Run this in a terminal on the machine you want to use. It opens a browser once; approve it and the terminal picks the sign-in up on its own.</p>
                    ${command("kryonsec login")}
                    <div class="admin-table-wrap"><table class="admin-table">
                        <thead><tr>${head}</tr></thead>
                        <tbody>${body}</tbody>
                    </table></div>
                    <p class="form-note">A token lasts 90 days. Signing out here ends it on the server straight away; the machine itself finds out the next time it checks in, which is within the hour. The installer command above is a different, one-time credential and is not affected.</p>`,
  );
}

function installCard(origin, token) {
  const url = `${origin}/api/beta/download?t=${token}`;
  const unix = `curl -fsSL ${origin}/install.sh | KRYONSEC_DOWNLOAD_URL='${url}' bash`;
  const windows = `$env:KRYONSEC_DOWNLOAD_URL='${url}'; irm ${origin}/install.ps1 -OutFile $env:TEMP\\install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\install.ps1`;

  return card(
    "01 / INSTALL",
    "LINUX · MACOS · WSL2 · WINDOWS",
    `<p class="form-note">Paste this into a terminal. It creates a virtualenv under <b>~/.kryonsec</b>, installs the newest build, and takes a few minutes.</p>
                    <p class="form-note">Linux, macOS, or WSL2:</p>
                    ${command(unix)}
                    <p class="form-note">Windows, in PowerShell:</p>
                    ${command(windows)}
                    <p class="form-note">The link inside it carries a one-time credential that stops working after ${CODE_TTL_MIN} minutes and cannot be used twice. It is not your account and it is not a membership key. Reload this page for a fresh one.</p>`,
  );
}

/**
 * The page, per state.
 *
 * `access.status` is the only input. Every branch below is a different true
 * sentence about the same account, and there is no branch that guesses.
 */
function view({ access, identities, origin, token, machines = [], csrf = "" }) {
  const a = access.application;
  const heading = (h, accent = "") => ({ heading: h, accent });

  const accountFacts = facts(
    detail("ACCOUNT", `${esc(access.user?.name || "—")}<br>${esc(access.user?.email || "")}`, true),
    detail("SIGN-IN", esc(identityLabel(identities)), true),
  );

  switch (access.status) {
    // --- in ---------------------------------------------------------------

    case "active":
      return {
        ...heading("YOU ARE", "IN."),
        lede: "Your access is active. There is nothing to remember and no key to keep: this page is where you get the software, and signing in is what proves it is you.",
        body: `${facts(
          detail("STATUS", statusPill("active"), true),
          detail("ACCESS SINCE", when(access.entitlement?.granted_at)),
          detail("APPLICATION", when(a?.submitted_at)),
          detail("SIGN-IN", esc(identityLabel(identities)), true),
        )}
                ${installCard(origin, token)}
                <a id="machines"></a>${machinesCard(machines, csrf)}`,
      };

    // --- applied, waiting -------------------------------------------------

    case "none": {
      // An application can be approved while the entitlement is missing or
      // being fixed up. Saying "in review" then would be a lie in the direction
      // that makes someone apply again.
      if (a?.status === "approved") {
        return {
          ...heading("YOU ARE", "APPROVED."),
          lede: "Your application was approved. Access is being set up on this page and will appear shortly — there is nothing for you to do.",
          body: accountFacts,
          banner: notice("warn", "Approved, but the access record is not in place yet. Reload in a few minutes."),
        };
      }
      if (a?.status === "pending") {
        return {
          ...heading("YOUR APPLICATION", "IS IN REVIEW."),
          lede: "A person reads every application, so this takes a few days rather than a few minutes. You will get an email when there is an answer, and this page will change on its own.",
          body: `${accountFacts}${card(
            "01 / WHAT YOU SENT",
            when(a.submitted_at).toUpperCase(),
            `<dl>
                        <dt>What you want to test</dt><dd>${esc(a.intended_use || "—")}</dd>
                        <dt>What you do</dt><dd>${esc(a.role || "—")}</dd>
                        <dt>Where you will run it</dt><dd>${esc(a.primary_os || "—")}</dd>
                        <dt>Reply address</dt><dd>${esc(a.contact_email || "—")}</dd>
                    </dl>
                    <p class="form-note">Spotted a mistake? Send a reply to the acknowledgement email — editing a submitted application is not something this page can do.</p>`,
          )}`,
        };
      }
      if (a?.status === "waitlisted") {
        return {
          ...heading("YOU ARE ON", "THE LIST."),
          lede: "Your application is on the waiting list. Places open as the programme grows, and yours moves up as they do.",
          body: accountFacts,
          banner: notice("warn", "You are waitlisted. There is nothing to do — you will get an email if a place opens."),
        };
      }
      // Nothing in play. Either they never applied, or they were turned down
      // in an earlier round and are welcome to try again — `rejected` sits
      // outside the one-active-application index exactly so this is possible.
      const wasRejected = access.lastRejected;
      return {
        ...heading(wasRejected ? "NOT ACCEPTED" : "NOT APPLIED", wasRejected ? "THIS ROUND." : "YET."),
        lede: wasRejected
          ? "The last round was full, which is a statement about capacity rather than about you. You can apply again whenever you like."
          : "Access is by application. It is a short form, a person reads it, and it is how the beta stays small enough to support.",
        body: accountFacts,
        banner: wasRejected
          ? notice("warn", `Your last application was not accepted${access.lastRejected?.decided_at ? ` on ${when(access.lastRejected.decided_at)}` : ""}.`)
          : "",
        actions: `<div class="form-actions"><a class="button button-primary" href="/apply">APPLY FOR ACCESS <span aria-hidden="true">↗</span></a></div>`,
      };
    }

    // --- had it, lost it --------------------------------------------------

    case "revoked":
    case "suspended":
      return {
        ...heading("ACCESS", `${access.status.toUpperCase()}.`),
        lede: "Your account still exists and your application is still on record. What has changed is that this account is no longer entitled to download or run Kryonsec.",
        body: `${accountFacts}${access.entitlement?.reason ? notice("warn", `Reason given: ${access.entitlement.reason}`) : ""}`,
        banner: notice("error", access.reason),
      };

    case "expired":
      return {
        ...heading("ACCESS HAS", "EXPIRED."),
        lede: "The access attached to this account has run out.",
        body: accountFacts,
        banner: notice("warn", access.reason),
      };

    // --- the programme ----------------------------------------------------

    case "programme_ended":
      return {
        ...heading("THE BETA HAS", "ENDED."),
        lede: "The early access programme is closed. This stops downloads and the command line for every account at once, including accounts whose access was still active.",
        body: accountFacts,
        banner: notice("error", access.reason),
      };

    default:
      // `accessFor` returns "unknown" only when the users row has gone, which
      // means the session outlived the account it points at.
      return {
        ...heading("SOMETHING IS", "WRONG."),
        lede: "This account could not be read. Signing out and back in should fix it.",
        body: accountFacts,
        banner: notice("error", access.reason || "The account behind this session is not readable."),
      };
  }
}

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  const session = await currentSession(db, request);
  if (!session) return redirect(`/signin?next=${encodeURIComponent("/dashboard")}`);

  const userId = session.user.user_id;
  const [access, identities, csrf, admin] = await Promise.all([
    accessFor(db, userId),
    listIdentities(db, userId),
    csrfFor(session.token),
    isAdminUser(db, userId),
  ]);

  const origin = new URL(request.url).origin;

  // Only minted for an account that can actually spend it. A token for someone
  // who would be refused at the gate is a live credential with no purpose, and
  // the schema would accumulate them for every page view of every refusal.
  const token = access.entitled ? await mintDownloadToken(db, userId) : "";

  // Asked for only where it is shown. An applicant waiting on a decision has
  // no machines and no use for the query, and that is most page views.
  const machines = access.status === "active" ? await listCliSessions(db, userId) : [];
  const rendered = view({ access, identities, origin, token, machines, csrf });

  return betaPage({
    title: "Your account",
    kicker: "KR / ACCOUNT",
    right: "BETA ACCESS",
    heading: rendered.heading,
    accent: rendered.accent,
    lede: rendered.lede,
    notice: rendered.banner || "",
    body: `${rendered.body}${rendered.actions || ""}`,
    session,
    csrf,
    admin,
    wide: true,
  });
}
