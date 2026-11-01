/**
 * Google and GitHub sign-in, hand-rolled over fetch.
 *
 * Why not a library: this repository has no build step, no package.json, and
 * no bundler, and adding one to obtain two authorization-code flows would
 * cost more than the flows do. Both providers speak ordinary OAuth 2.0 with
 * PKCE, and PKCE is what makes a correct hand-rolled flow safe here — the
 * code is useless without the verifier, which never leaves the cookie.
 *
 * Import-only: the Pages router ignores paths starting with an underscore.
 *
 * ---------------------------------------------------------------------------
 * The rule this file exists to enforce
 * ---------------------------------------------------------------------------
 *
 * An identity is (provider, subject). It is NEVER the email address.
 *
 * `sub` at Google and `id` at GitHub are stable for the life of the account
 * and cannot be reassigned. An email address can be changed by its owner, and
 * — at both providers — can later be released and claimed by somebody else.
 * Keying an account on email means the second person to hold an address
 * inherits the first person's access.
 *
 * So nothing here matches users by email, and nothing merges two identities
 * that happen to share one. Signing in with GitHub after signing in with
 * Google creates a second account; the brief asks for that explicitly, and it
 * is the safe direction. The cost is a duplicate account for someone who
 * forgets which button they pressed, which a human can merge, and which the
 * applicant dashboard reports honestly.
 *
 * ---------------------------------------------------------------------------
 * Environment
 * ---------------------------------------------------------------------------
 *
 *   KRYONSEC_GOOGLE_CLIENT_ID / KRYONSEC_GOOGLE_CLIENT_SECRET
 *   KRYONSEC_GITHUB_CLIENT_ID / KRYONSEC_GITHUB_CLIENT_SECRET
 *
 * Register both apps with these exact redirect URIs:
 *
 *   https://kryonsec.in/api/auth/google/callback
 *   https://kryonsec.in/api/auth/github/callback
 *
 * A mismatch on any character is an error at the provider, before any of this
 * runs, which is why the URI is built from the request origin rather than a
 * constant — a preview deployment then works without a second registration.
 */

import { b64url, newId, timingSafeEqual } from "./_auth.js";
import { esc, nowIso, page, randomToken } from "./_shared.js";

/** Default landing page after sign-in, when no safe `next` was supplied. */
export const DEFAULT_NEXT = "/dashboard";

const PROVIDERS = {
  google: {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    // openid is what returns the `sub` claim; without it there is no stable
    // identifier and the whole design above falls apart.
    scope: "openid email profile",
    idEnv: ["KRYONSEC_GOOGLE_CLIENT_ID"],
    secretEnv: ["KRYONSEC_GOOGLE_CLIENT_SECRET"],
  },
  github: {
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    // read:user is the public profile. user:email is required to read the
    // address at all when the account keeps it private — and it is read-only,
    // which matters because the brief forbids asking for repository access
    // just to sign somebody in. No `repo` scope, ever.
    scope: "read:user user:email",
    idEnv: ["KRYONSEC_GITHUB_CLIENT_ID"],
    secretEnv: ["KRYONSEC_GITHUB_CLIENT_SECRET"],
  },
};

export const PROVIDER_NAMES = Object.keys(PROVIDERS);
export const isProvider = (name) => Object.hasOwn(PROVIDERS, name);

const PROVIDER_TITLES = { google: "Google", github: "GitHub" };

/** The provider's name as a person reads it, for headings and messages. */
export const providerTitle = (name) => PROVIDER_TITLES[name] || String(name);

/** First non-empty env value, or "". */
function envValue(env, names) {
  for (const name of names) if (env?.[name]) return String(env[name]);
  return "";
}

/**
 * Is this provider usable on this deployment? A provider with no client id
 * cannot be offered, and a sign-in button that leads to a provider error
 * screen is worse than no button — so the pages ask this before rendering one.
 */
export function isConfigured(env, provider) {
  const p = PROVIDERS[provider];
  if (!p) return false;
  return Boolean(envValue(env, p.idEnv) && envValue(env, p.secretEnv));
}

export const configuredProviders = (env) => PROVIDER_NAMES.filter((n) => isConfigured(env, n));

export function callbackUrl(request, provider) {
  return `${new URL(request.url).origin}/api/auth/${provider}/callback`;
}

/**
 * Where to send someone after sign-in.
 *
 * Only a same-site absolute path is allowed. Everything else — a full URL, a
 * protocol-relative `//evil.example`, a backslash variant that some browsers
 * normalise into one, a `javascript:` — falls back to the default.
 *
 * This is the open-redirect guard, and it is a guard rather than a
 * convenience: the callback URL is one an attacker can hand a victim, and
 * `?next=` is exactly where a phishing flow wants to land them on a page that
 * looks like ours.
 */
export function safeNext(value) {
  const next = String(value || "").trim();
  if (!next.startsWith("/")) return DEFAULT_NEXT;
  // `//host` and `/\host` are both read as protocol-relative by browsers.
  if (next.startsWith("//") || next.startsWith("/\\")) return DEFAULT_NEXT;
  if (next.includes("\\")) return DEFAULT_NEXT;
  // Control characters can smuggle a newline into a Location header.
  if (/[\u0000-\u001f\u007f]/.test(next)) return DEFAULT_NEXT;
  return next;
}

// --- the state cookie -------------------------------------------------------

/**
 * The in-flight flow, as one cookie.
 *
 * `state` is the CSRF binding between this browser and this callback.
 * `verifier` is the PKCE secret. `next` rides along because the callback is a
 * fresh request with no memory of why the user started.
 *
 * base64url of a compact JSON object. It is HttpOnly, so no script can read
 * it, and it is cleared the moment the callback consumes it.
 */
export function encodeFlow({ state, verifier, next, provider }) {
  const json = JSON.stringify({ s: state, v: verifier, n: next, p: provider });
  return b64url(new TextEncoder().encode(json));
}

export function decodeFlow(value) {
  try {
    const padded = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(padded));
    if (!json || typeof json !== "object") return null;
    if (!json.s || !json.v || !json.p) return null;
    return { state: json.s, verifier: json.v, next: json.n, provider: json.p };
  } catch {
    return null;
  }
}

/** Start a flow: the values to store, and the URL to send the browser to. */
export async function beginFlow({ request, env, provider, next }) {
  const p = PROVIDERS[provider];
  const state = randomToken(16);
  const verifier = randomToken(32);
  const challenge = b64url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );

  const url = new URL(p.authorizeUrl);
  url.searchParams.set("client_id", envValue(env, p.idEnv));
  url.searchParams.set("redirect_uri", callbackUrl(request, provider));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", p.scope);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");

  return {
    flow: { state, verifier, next: safeNext(next), provider },
    redirect: url.toString(),
  };
}

// --- the callback -----------------------------------------------------------

export class OAuthError extends Error {
  constructor(message, { retryable = false } = {}) {
    super(message);
    this.retryable = retryable;
  }
}

async function postForm(url, body, headers = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", ...headers },
    body: new URLSearchParams(body).toString(),
  });
  if (!res.ok) {
    // The body can carry a useful reason ("incorrect_client_credentials"), but
    // it can also echo the request, so it is never surfaced to the user —
    // only logged, and only the status is turned into a message.
    throw new OAuthError(`the provider refused the token request (${res.status})`);
  }
  return res.json();
}

async function getJson(url, token, headers = {}) {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      // GitHub rejects a request with no User-Agent.
      "User-Agent": "kryonsec-site",
      ...headers,
    },
  });
  if (!res.ok) throw new OAuthError(`the provider refused the profile request (${res.status})`);
  return res.json();
}

/** Exchange the code, then read the profile. Returns a normalised identity. */
export async function completeFlow({ env, provider, code, verifier, redirectUri }) {
  const p = PROVIDERS[provider];
  const token = await postForm(p.tokenUrl, {
    client_id: envValue(env, p.idEnv),
    client_secret: envValue(env, p.secretEnv),
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: verifier,
  });

  if (!token?.access_token) throw new OAuthError("the provider returned no access token");

  if (provider === "google") {
    const me = await getJson("https://openidconnect.googleapis.com/v1/userinfo", token.access_token);
    if (!me?.sub) throw new OAuthError("the provider returned no stable subject id");
    return {
      provider,
      subject: String(me.sub),
      email: me.email ? String(me.email).toLowerCase() : "",
      // Google states this explicitly and it is trustworthy for a Workspace-
      // or Gmail-hosted address. Recorded, never assumed.
      emailVerified: me.email_verified === true,
      name: me.name ? String(me.name) : "",
    };
  }

  // GitHub. `/user` reports `email: null` whenever the address is private,
  // which is the common case, so the emails endpoint is the real source.
  const me = await getJson("https://api.github.com/user", token.access_token);
  if (!me?.id) throw new OAuthError("the provider returned no stable subject id");

  let email = me.email ? String(me.email).toLowerCase() : "";
  let emailVerified = Boolean(email);

  if (!email) {
    const emails = await getJson("https://api.github.com/user/emails", token.access_token);
    const list = Array.isArray(emails) ? emails : [];
    // Prefer the primary address, and only among verified ones. An unverified
    // address is one GitHub has not confirmed the person controls, so it is
    // not usable as a contact address.
    const verified = list.filter((e) => e?.verified === true);
    const chosen = verified.find((e) => e.primary === true) || verified[0];
    if (chosen?.email) {
      email = String(chosen.email).toLowerCase();
      emailVerified = true;
    }
  }

  return {
    provider,
    subject: String(me.id),
    // Deliberately left empty rather than derived from the login name: the
    // brief says not to invent an address, and `login@users.noreply.github.com`
    // is an address we made up on the user's behalf.
    email,
    emailVerified,
    name: me.name ? String(me.name) : me.login ? String(me.login) : "",
  };
}

// --- persistence ------------------------------------------------------------

/**
 * Resolve an identity to its user, creating both on first sight.
 *
 * No email matching happens here, on purpose — see the module comment. Two
 * identities with one email are two users.
 *
 * Returns the user id. The caller creates the session.
 */
export async function findOrCreateUser(db, identity) {
  const known = await db
    .prepare("SELECT user_id FROM identities WHERE provider = ? AND subject = ?")
    .bind(identity.provider, identity.subject)
    .first();

  const now = nowIso();

  if (known) {
    // Keep the row's contact address current without touching the identity
    // key. `email_verified` follows the provider's latest statement — an
    // address can lose verification as well as gain it.
    await db
      .prepare(
        `UPDATE identities
            SET email = ?, email_verified = ?, last_login_at = ?
          WHERE provider = ? AND subject = ?`,
      )
      .bind(
        identity.email || null,
        identity.emailVerified ? 1 : 0,
        now,
        identity.provider,
        identity.subject,
      )
      .run();

    if (identity.email) {
      await db
        .prepare("UPDATE users SET email = ?, email_verified = ?, updated_at = ? WHERE id = ?")
        .bind(identity.email, identity.emailVerified ? 1 : 0, now, known.user_id)
        .run();
    }
    return known.user_id;
  }

  const userId = newId("u");
  // A user with no email at all is possible (a GitHub account with no
  // verified address). Storing "" keeps the column NOT NULL while making the
  // absence visible; nothing downstream may treat "" as an address.
  await db
    .prepare(
      `INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      userId,
      identity.email || "",
      identity.emailVerified ? 1 : 0,
      identity.name || "",
      now,
      now,
    )
    .run();

  await db
    .prepare(
      `INSERT INTO identities
         (provider, subject, user_id, email, email_verified, created_at, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      identity.provider,
      identity.subject,
      userId,
      identity.email || null,
      identity.emailVerified ? 1 : 0,
      now,
      now,
    )
    .run();

  return userId;
}

/** Does the state in the callback match the one we put in the cookie? */
export function stateMatches(flow, received) {
  if (!flow || !flow.state) return false;
  return timingSafeEqual(flow.state, String(received || ""));
}

// --- how a failed sign-in looks ---------------------------------------------

/**
 * Render a sign-in failure.
 *
 * What is shown is deliberately thin. The provider's error text can name the
 * client id, echo the redirect URI, or describe our configuration; the
 * exception message from a failed exchange can carry a response body. None of
 * that belongs on a public page, and none of it helps the person reading it —
 * they need to know the attempt did not work and what to do next. The real
 * cause goes to the Worker log, where an operator can see it.
 *
 * `?detail=` is never read from the URL. An attacker who can put text on our
 * own sign-in failure page has a phishing surface with our domain on it.
 */
export function authFailure(kicker, title, message, { status = 400 } = {}) {
  return page(
    title,
    `                <div class="section-bar"><span>KR / SIGN IN</span><span>${esc(kicker)}</span></div>
                <h2>${esc(title)}</h2>
                <p class="form-note">${esc(message)}</p>
                <div class="form-actions">
                    <a class="button button-secondary" href="/">BACK TO THE SITE</a>
                </div>`,
    status,
  );
}
