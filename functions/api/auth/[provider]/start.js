/**
 * GET /api/auth/:provider/start — begin a sign-in.
 *
 * A plain link on the site points here. This handler does no database work and
 * touches no session: it mints the state and PKCE verifier, parks them in a
 * short-lived cookie, and hands the browser to the provider. Everything that
 * could go wrong happens in the callback, which is the only place that has
 * something worth protecting.
 *
 * GET only. A cross-site GET that starts a flow is harmless — it cannot read
 * the cookie it sets, and the callback still demands the matching state — so
 * there is no POST variant to defend.
 */

import { oauthCookie } from "../../../_auth.js";
import {
  authFailure,
  beginFlow,
  encodeFlow,
  isConfigured,
  isProvider,
  providerTitle,
} from "../../../_oauth.js";

export async function onRequestGet({ request, env, params }) {
  const provider = String(params.provider || "");

  if (!isProvider(provider)) {
    return authFailure("UNKNOWN PROVIDER", "That sign-in option does not exist", "Pick one of the options on the front page.", { status: 404 });
  }

  // The honest failure. Until the Google and GitHub apps are registered there
  // is no client id, and sending someone to a provider URL with an empty
  // `client_id` lands them on the provider's own error screen — which looks
  // like our bug and tells them nothing.
  if (!isConfigured(env, provider)) {
    return authFailure(
      "NOT CONFIGURED",
      `${providerTitle(provider)} sign-in is not switched on yet`,
      "The beta is still being set up. Check back shortly.",
      { status: 503 },
    );
  }

  const next = new URL(request.url).searchParams.get("next");
  const { flow, redirect } = await beginFlow({ request, env, provider, next });

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirect,
      "Set-Cookie": oauthCookie(encodeFlow(flow), request.url),
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}
