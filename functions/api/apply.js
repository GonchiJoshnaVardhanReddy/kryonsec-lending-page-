/**
 * POST /api/apply — file an application.
 *
 * An ordinary HTML form post, not JSON, so a validation failure re-renders the
 * form with what the person typed still in it. Losing someone's three
 * paragraphs because they mistyped their email address is the single rudest
 * thing a form can do, and this is the file that decides not to.
 *
 * The form markup itself lives in `../apply.js` and is imported, so the page
 * that shows the form and the page that rejects it cannot drift apart.
 *
 * Two things here are security rather than tidiness:
 *
 *   - `checkCsrf` runs before anything is read, so a cross-site post cannot
 *     create rows even if SameSite were ignored.
 *   - `portfolio_url` is only accepted when it parses with an http or https
 *     scheme. That value is rendered as a clickable link on a page an admin
 *     reads, and `javascript:` parses perfectly well as a URL. Validating at
 *     the write is the boundary; escaping at the read is the belt.
 *
 * Role and operating system are checked against the same lists the dropdowns
 * were built from. Not because a crafted value is dangerous — it is escaped
 * everywhere it is shown — but because a filter that can be filled with
 * arbitrary text is a filter nobody can trust later.
 */

import { checkCsrf, csrfFor, currentSession } from "../_auth.js";
import { drain } from "../_email.js";
import { notice } from "../_pages.js";
import { cleanEmail, redirect } from "../_shared.js";
import { ROLES, SYSTEMS, renderApply } from "../apply.js";
import { submitApplication } from "../_store.js";

/** The two fields the dropdowns offer, and nothing else. */
const inList = (value, list) => (!value ? "" : list.includes(value) ? value : "");

/**
 * A GitHub handle, or "". Accepts what people actually paste — `@name`, or a
 * profile URL — and keeps the handle. The pattern is deliberately loose:
 * GitHub's own rules have changed more than once, and a handle that is merely
 * unusual is not a reason to refuse someone.
 */
function cleanGithub(value) {
  const raw = String(value || "").trim().replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/^@/, "").replace(/\/.*$/, "");
  return /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/.test(raw) ? raw : "";
}

/** An http(s) URL, or "". Anything else — including `javascript:` — is dropped. */
function cleanUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : "";
  } catch {
    return "";
  }
}

/** What the person typed, kept for the re-render. Never trusted, only echoed. */
function submitted(form) {
  return {
    full_name: form.get("full_name"),
    contact_email: form.get("contact_email"),
    github_username: form.get("github_username"),
    portfolio_url: form.get("portfolio_url"),
    role: form.get("role"),
    primary_os: form.get("primary_os"),
    intended_use: form.get("intended_use"),
    experience: form.get("experience"),
    comments: form.get("comments"),
    feedback_willing: form.get("feedback_willing"),
  };
}

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  const session = await currentSession(db, request);
  if (!session) return redirect(`/signin?next=${encodeURIComponent("/apply")}`);

  let form;
  try {
    form = await request.formData();
  } catch {
    return redirect("/apply");
  }

  const refuse = async (message) =>
    renderApply({
      session,
      csrf: await csrfFor(session.token),
      values: submitted(form),
      banner: notice("error", message),
      status: 400,
    });

  const badCsrf = await checkCsrf(request, session, form);
  if (badCsrf) return refuse(badCsrf);

  const name = String(form.get("full_name") || "").replace(/\s+/g, " ").trim();
  if (!name) return refuse("We need a name to put on the application.");

  const contactEmail = cleanEmail(form.get("contact_email"));
  if (!contactEmail) return refuse("That email address does not look right. It is where the decision gets sent.");

  const intendedUse = String(form.get("intended_use") || "").trim();
  if (!intendedUse) return refuse("Tell us what you want to test — it is the field that actually gets read.");

  // Consent is an affirmative act. If it was not given, the box comes back
  // empty: restoring a ticked box would turn "I agree" into something the
  // browser asserted on the applicant's behalf.
  if (!form.get("terms")) {
    return refuse("Please confirm you will only test systems you own or have permission to test.");
  }

  const rawGithub = String(form.get("github_username") || "").trim();
  if (rawGithub && !cleanGithub(rawGithub)) {
    return refuse("That GitHub handle does not look right. Leave it blank if you would rather not give one.");
  }

  const rawUrl = String(form.get("portfolio_url") || "").trim();
  if (rawUrl && !cleanUrl(rawUrl)) {
    return refuse("That website address does not look right. It needs to start with http:// or https://.");
  }

  const result = await submitApplication(db, session.user.user_id, {
    full_name: name,
    contact_email: contactEmail,
    github_username: cleanGithub(rawGithub),
    portfolio_url: cleanUrl(rawUrl),
    role: inList(String(form.get("role") || ""), ROLES),
    primary_os: inList(String(form.get("primary_os") || ""), SYSTEMS),
    intended_use: intendedUse,
    experience: form.get("experience"),
    comments: form.get("comments"),
    feedback_willing: Boolean(form.get("feedback_willing")),
  });

  // "Already applied" is not an error — it is the answer. A double submit, or
  // a second tab, lands here and the dashboard is exactly where they should
  // end up either way. The database refused the duplicate; nothing to undo.
  if (!result.ok && result.code !== "exists") {
    return refuse(String(result.error || "Something went wrong filing that."));
  }

  if (result.ok) {
    // The row is committed. Sending the acknowledgement is best-effort from
    // here: a mail problem must not tell an applicant their application failed
    // when it is sitting in the queue.
    await drain(db, env).catch((error) => console.error("mail: drain failed after application:", error));
  }

  return redirect("/dashboard");
}
