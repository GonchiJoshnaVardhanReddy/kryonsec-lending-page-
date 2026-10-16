/**
 * GET /api/auth/:provider/callback — finish a sign-in.
 *
 * The provider sends the browser back here with a one-time code. This handler
 * is the whole trust boundary for identity, so the order below is not
 * cosmetic:
 *
 *   1. the in-flight cookie must exist, name this same provider, and carry the
 *      state value the provider just echoed back
 *   2. only then is the code exchanged — and it is exchanged with a client
 *      secret that never leaves this process, which is what stops a stolen
 *      code from being redeemable by whoever stole it
 *   3. only then is a user resolved and a session minted
 *
 * Every exit path clears the flow cookie, including the successful one. The
 * cookie holds the PKCE verifier, and a verifier that outlives its flow is a
 * second chance for a replayed callback. Clearing on the way out means a
 * callback URL can be used exactly once, whatever it does.
 *
 * The session is always freshly created — never re-keyed onto an existing
 * cookie. That makes session fixation structurally impossible rather than
 * merely unlikely: there is no code path in which an attacker-chosen session
 * identifier becomes an authenticated one.
 */

import {
  OAUTH_COOKIE,
  clearOauthCookie,
  createSession,
  parseCookies,
  sessionCookie,
} from "../../../_auth.js";
import {
  DEFAULT_NEXT,
  OAuthError,
  authFailure,
  callbackUrl,
  completeFlow,
  decodeFlow,
  findOrCreateUser,
  isConfigured,
  isProvider,
  stateMatches,
} from "../../../_oauth.js";

export async function onRequestGet({ request, env, params }) {
  const provider = String(params.provider || "");
  const url = new URL(request.url);

  // Rendered once, attached to whichever branch is taken. `status` is not 400
  // for a cancellation — the person did nothing wrong and a red error code in
  // the logs would misread it as a fault.
  const fail = (kicker, title, message, status = 400) => {
    const response = authFailure(kicker, title, message, { status });
    response.headers.append("Set-Cookie", clearOauthCookie(request.url));
    return response;
  };

  if (!isProvider(provider) || !isConfigured(env, provider)) {
    return fail("NOT CONFIGURED", "Sign-in is not switched on yet", "The beta is still being set up.", 503);
  }

  const flow = decodeFlow(parseCookies(request)[OAUTH_COOKIE]);

  // The state check. Two things are being proved at once: that this browser
  // started this flow (the cookie is HttpOnly, so another site could not have
  // read it), and that the callback is a genuine reply to it rather than a
  // link an attacker talked the victim into opening. A missing cookie and a
  // wrong state get the same answer on purpose — distinguishing them would
  // tell an attacker which half of the pair they had guessed.
  if (!flow || flow.provider !== provider || !stateMatches(flow, url.searchParams.get("state"))) {
    return fail("EXPIRED", "That sign-in link had expired", "Sign-in links only work once. Start again from the front page.");
  }

  // The person pressed "cancel", or the provider refused. Not our failure.
  if (url.searchParams.get("error")) {
    return fail("CANCELLED", "Sign-in was cancelled", "Nothing was changed. You can try again whenever you like.", 200);
  }

  const code = url.searchParams.get("code");
  if (!code) {
    return fail("INCOMPLETE", "That sign-in did not finish", "The provider did not send an authorization code. Try again.");
  }

  let identity;
  try {
    identity = await completeFlow({
      env,
      provider,
      code,
      verifier: flow.verifier,
      redirectUri: callbackUrl(request, provider),
    });
  } catch (error) {
    // The detail is for the operator's log, not for the page. A failed
    // exchange can carry a response body naming our client id or echoing the
    // request, and the person reading the page can do nothing with either.
    console.error(`auth: ${provider} exchange failed:`, error instanceof OAuthError ? error.message : error);
    return fail("FAILED", "We could not complete that sign-in", "Nothing was changed. Please try again.", 502);
  }

  const db = env.KRYONSEC_DB;
  const userId = await findOrCreateUser(db, identity);
  const session = await createSession(db, userId);

  const headers = new Headers({
    Location: flow.next || DEFAULT_NEXT,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
  });
  headers.append("Set-Cookie", sessionCookie(session, request.url));
  headers.append("Set-Cookie", clearOauthCookie(request.url));

  return new Response(null, { status: 302, headers });
}
