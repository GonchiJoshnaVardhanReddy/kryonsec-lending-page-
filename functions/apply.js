/**
 * GET /apply — the application form.
 *
 * The renderer lives here and is imported by api/apply.js, so a validation
 * failure re-renders from the same markup that produced the form. Two copies
 * of a form is how a field ends up on the page but not in the handler, which
 * looks fine until an applicant fills it in and it goes nowhere.
 *
 * Applying needs an account. That is not gatekeeping for its own sake: an
 * application has to be attached to a stable identity, or the same person
 * files three and nobody can tell. Signing in is two clicks and asks for
 * nothing a provider does not already hold.
 */

import { csrfFor, currentSession } from "./_auth.js";
import { betaPage, checkbox, csrfField, field, select } from "./_pages.js";
import { redirect } from "./_shared.js";
import { LIMITS, activeApplication, TERMS_VERSION } from "./_store.js";

/** Exported so the POST handler can check against the same two lists these
 *  dropdowns were built from, rather than a second copy that drifts. */
export const ROLES = [
  "Security engineer",
  "Application developer",
  "DevOps / SRE",
  "Founder / engineering lead",
  "Researcher or student",
  "Something else",
];

export const SYSTEMS = ["Windows", "macOS", "Linux", "More than one"];

/**
 * What the applicant is agreeing to, and why it is not a legal document.
 *
 * The brief asks the acknowledgement to be recorded with its version and a
 * timestamp, so that consent is evidence rather than a boolean. It does not
 * ask for terms and conditions, and this is not a substitute for them — it is
 * the three things a person running a pre-release security tool on real
 * systems actually needs to have read. `TERMS_VERSION` names the text; the
 * sentence below is that text.
 */
const ACKNOWLEDGEMENT =
  "I will only point Kryonsec at systems I own or have written permission to test. " +
  "I understand this is pre-release software, that beta access may end, and that my access is personal to me.";

export function renderApply({ session, csrf, values = {}, banner = "", status = 200 }) {
  const v = (name) => values[name] ?? "";
  const body = `<form class="feedback-form" method="post" action="/api/apply">
                    ${csrfField(csrf)}
                    ${field({ name: "full_name", label: "NAME", value: v("full_name"), required: true, autocomplete: "name", maxlength: LIMITS.full_name })}
                    ${field({ name: "contact_email", label: "EMAIL", type: "email", value: v("contact_email") || session.user.email, required: true, autocomplete: "email", maxlength: LIMITS.contact_email, hint: "Where we send the decision. It defaults to the address on your account." })}
                    ${field({ name: "github_username", label: "GITHUB HANDLE", value: v("github_username"), maxlength: LIMITS.github_username, placeholder: "octocat", hint: "Optional, and only used to look at work you have made public." })}
                    ${field({ name: "portfolio_url", label: "WEBSITE", type: "url", value: v("portfolio_url"), maxlength: LIMITS.portfolio_url, placeholder: "https://", hint: "Optional." })}
                    ${select({ name: "role", label: "WHAT DO YOU DO?", options: ROLES, value: v("role") })}
                    ${select({ name: "primary_os", label: "WHAT WILL YOU RUN IT ON?", options: SYSTEMS, value: v("primary_os"), hint: "The command-line engine needs Linux with Docker. The assistant works anywhere." })}
                    ${field({ name: "intended_use", label: "WHAT DO YOU WANT TO USE IT FOR?", value: v("intended_use"), rows: 5, maxlength: LIMITS.intended_use, full: true, hint: "A few sentences is plenty. This is the field that actually gets read." })}
                    ${field({ name: "experience", label: "ANY SECURITY TOOLING YOU ALREADY USE?", value: v("experience"), rows: 3, maxlength: LIMITS.experience, full: true })}
                    ${field({ name: "comments", label: "ANYTHING ELSE?", value: v("comments"), rows: 3, maxlength: LIMITS.comments, full: true })}
                    ${checkbox({ name: "feedback_willing", label: "I am willing to send feedback while the beta runs.", checked: Boolean(v("feedback_willing")) })}
                    ${checkbox({ name: "terms", label: ACKNOWLEDGEMENT, checked: Boolean(v("terms")), hint: `Recorded as version ${TERMS_VERSION}.` })}
                    <div class="form-actions">
                        <button class="button button-primary" type="submit">SEND APPLICATION <span aria-hidden="true">↗</span></button>
                    </div>
                </form>
                <p class="form-note">One application per account. A person reads every one, so give it a few days rather than a few minutes.</p>`;

  return betaPage({
    title: "Apply for the beta",
    kicker: "KR / EARLY ACCESS",
    right: "APPLICATION",
    heading: "TELL US WHAT",
    accent: "YOU WOULD TEST.",
    lede: "The beta is small and hand-reviewed. Everything below is optional except your name, an address to reply to, a sentence on what you want to test, and the acknowledgement.",
    notice: banner,
    body,
    session,
    csrf,
    status,
  });
}

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  const session = await currentSession(db, request);

  // Bounce through sign-in and come back here, rather than showing a form
  // whose submission would be rejected for having nobody attached to it.
  if (!session) return redirect(`/signin?next=${encodeURIComponent("/apply")}`);

  // Already in the queue, or already in. Either way there is nothing to ask
  // for, and a second application is refused by the database anyway — showing
  // the form would only invite a submission that cannot land.
  if (await activeApplication(db, session.user.user_id)) return redirect("/dashboard");

  return renderApply({ session, csrf: await csrfFor(session.token) });
}
