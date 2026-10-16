/**
 * GET /signin — the one way in.
 *
 * There is no password on this site and no email magic link. Signing in means
 * proving control of a Google or GitHub account, and the provider tells us
 * which account it was. Everything else — whether that account has access —
 * is answered later, by the entitlement table, not here.
 *
 * A provider with no client id registered is not shown. A button that leads to
 * the provider's own error page is worse than no button: it looks like our
 * bug, it teaches the person nothing, and it invites them to try again.
 *
 * noindex: this URL is in every applicant's history and has no business in a
 * search result.
 */

import { currentSession } from "./_auth.js";
import { configuredProviders, safeNext } from "./_oauth.js";
import { betaPage, notice } from "./_pages.js";
import { redirect } from "./_shared.js";

const PROVIDER_LABELS = {
  google: ["CONTINUE WITH GOOGLE", "button-primary"],
  github: ["CONTINUE WITH GITHUB", "button-secondary"],
};

export async function onRequestGet({ request, env }) {
  const db = env.KRYONSEC_DB;
  const next = safeNext(new URL(request.url).searchParams.get("next"));

  const session = await currentSession(db, request);
  if (session) return redirect(next);

  const providers = configuredProviders(env);
  const buttons = providers
    .map((name) => {
      const [label, tone] = PROVIDER_LABELS[name] || [name.toUpperCase(), "button-secondary"];
      // GET, because starting a flow has no side effect worth protecting: it
      // writes a cookie this browser cannot read and nothing else, and the
      // callback still demands the state value that cookie holds.
      return `<a class="button ${tone}" href="/api/auth/${name}/start?next=${encodeURIComponent(next)}">${label} <span aria-hidden="true">↗</span></a>`;
    })
    .join("\n                    ");

  const banner = providers.length
    ? ""
    : notice(
        "warn",
        "Sign-in is not switched on yet — the Google and GitHub apps still need to be registered. Check back shortly.",
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
                <p class="form-note">We ask for your name and email address, and nothing else. We cannot read your repositories, your files, or your mail.</p>`,
  });
}
