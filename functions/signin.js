/**
 * GET /signin — the one way in.
 *
 * There is no password on this site and no email magic link. Signing in means
 * proving control of a Google or GitHub account, and the provider tells us
 * which account it was. Everything else — whether that account has access —
 * is answered later, by the entitlement table, not here.
 *
 * A provider with no client id registered is not linked. A button that leads
 * to the provider's own error page is worse than no button: it looks like our
 * bug, it teaches the person nothing, and it invites them to try again. It is
 * still shown — disabled, and named — because "sign-in is not available"
 * without saying which one is a puzzle, not a message.
 *
 * noindex: this URL is in every applicant's history and has no business in a
 * search result.
 */

import { currentSession } from "./_auth.js";
import {
  PROVIDER_NAMES,
  configuredProviders,
  providerTitle,
  safeNext,
} from "./_oauth.js";
import { betaPage, notice } from "./_pages.js";
import { redirect } from "./_shared.js";

const PROVIDER_LABELS = {
  google: ["CONTINUE WITH GOOGLE", "button-primary"],
  github: ["CONTINUE WITH GITHUB", "button-secondary"],
};

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  const next = safeNext(new URL(request.url).searchParams.get("next"));

  const session = db ? await currentSession(db, request) : null;
  if (session) return redirect(next);

  const providers = configuredProviders(env);
  const buttons = PROVIDER_NAMES.map((name) => {
    const [label, tone] = PROVIDER_LABELS[name] || [name.toUpperCase(), "button-secondary"];
    if (providers.includes(name)) {
      // GET, because starting a flow has no side effect worth protecting: it
      // writes a cookie this browser cannot read and nothing else, and the
      // callback still demands the state value that cookie holds.
      return `<a class="button ${tone}" data-provider="${name}" href="/api/auth/${name}/start?next=${encodeURIComponent(next)}"><span class="button-label">${label}</span> <span aria-hidden="true">↗</span></a>`;
    }
    return `<button class="button ${tone} is-unavailable" type="button" data-provider="${name}" disabled><span class="button-label">${label}</span> <span aria-hidden="true">↗</span></button>`;
  }).join("\n                    ");

  // Name the provider that is missing, not just the fact that something is.
  // "Google and GitHub still need to be registered" was a guess; the server
  // only knows which of its own variables are set.
  const unavailable = PROVIDER_NAMES.filter((name) => !providers.includes(name));
  const available = providers.map(providerTitle).join(" or ");
  const banner = providers.length
    ? unavailable
        .map((name) =>
          notice(
            "warn",
            `${providerTitle(name)} sign-in is not available on this deployment yet. Use ${available} instead.`,
          ),
        )
        .join("\n                ")
    : notice(
        "warn",
        "Sign-in is not switched on yet — neither Google nor GitHub sign-in has been configured on this deployment. Check back shortly.",
      );

  return betaPage({
    title: "Sign in",
    kicker: "KR / SIGN IN",
    right: "BETA ACCESS",
    heading: "EARLY ACCESS",
    accent: "IS BY INVITATION.",
    lede: "Sign in with the account you applied with and you can follow your application, download the beta, and connect the command line.",
    notice: banner,
    body: `<div class="form-actions">
                    ${buttons}
                </div>
                <script src="/signin.js" defer></script>
                <p class="form-note">We ask for your name and email address, and nothing else. We cannot read your repositories, your files, or your mail.</p>`,
  });
}
