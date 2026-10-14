/**
 * POST /api/feedback
 *
 * The sink for the feedback form, replacing the n8n webhook that used to sit at
 * n8n.kryonsec.in. A Cloudflare Pages Function writing to a KV namespace: no
 * server to run, no third party holding the submissions, and it deploys with
 * the site.
 *
 *   stored        -> 200, a short HTML page
 *   bad input     -> 400
 *   not bound     -> 503, and nothing is claimed to have been saved
 *
 * Always HTML, never JSON: the page's script only reads the status code, and a
 * browser posting without JavaScript should land on something readable.
 *
 * Environment (Pages -> Settings -> Functions -> KV namespace bindings):
 *   KRYONSEC_FEEDBACK   KV namespace, binding name exactly this
 *
 * The form's fields are full_name, phone_number, email, comments,
 * feature_request, source, submitted_at.
 */

const LIMITS = {
  full_name: 200,
  phone_number: 100,
  email: 320,
  comments: 5000,
  feature_request: 5000,
  source: 100,
  submitted_at: 40,
};

const REQUIRED = ["full_name", "email", "comments"];

// Deliberately loose: this rejects obvious garbage, not unusual-but-valid
// addresses, and the address is never used for anything but replying.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function page(message, status) {
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>Kryonsec feedback</title>` +
      `<body style="font-family:system-ui;background:#f5f5f0;color:#111;padding:2rem">` +
      `<p>${message}</p><p><a href="/feedback.html">Back</a></p>`,
    {
      status,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        // Nothing here should be indexed or framed.
        "X-Robots-Tag": "noindex",
      },
    },
  );
}

// ponytail: no spam guard. A bot can burn the free KV write quota (1000/day)
// and fill the namespace with junk. Add a honeypot field, or Turnstile, when
// that actually happens — at current traffic it is not worth the field.
export async function onRequestPost({ request, env }) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return page("That submission could not be read.", 400);
  }

  const field = (name) => String(form.get(name) ?? "").trim();

  const missing = REQUIRED.filter((name) => !field(name));
  if (missing.length) {
    return page(`Missing required fields: ${missing.join(", ")}.`, 400);
  }
  if (!EMAIL_RE.test(field("email"))) {
    return page("That email address does not look right.", 400);
  }

  const entry = {};
  for (const [name, limit] of Object.entries(LIMITS)) {
    const value = field(name);
    if (value) entry[name] = value.slice(0, limit);
  }

  // Server time, not the form's submitted_at: the client value is spoofable and
  // absent without JavaScript, and this key is what orders the namespace.
  entry.received_at = new Date().toISOString();
  entry.country = request.cf?.country ?? null;

  const kv = env.KRYONSEC_FEEDBACK;
  if (!kv) {
    // Setup error. 503 rather than 200 — a submission that was dropped must not
    // read as "thank you, we got it".
    return page("Feedback is not configured yet. Please email us instead.", 503);
  }

  // ISO timestamps sort chronologically, so `wrangler kv key list` reads in
  // order. The suffix keeps same-millisecond submissions apart.
  const key = `feedback/${entry.received_at}-${crypto.randomUUID().slice(0, 8)}`;

  try {
    await kv.put(key, JSON.stringify(entry));
  } catch {
    return page("Could not save that. Please try again later.", 503);
  }

  return page("Thanks — your feedback was received.", 200);
}
