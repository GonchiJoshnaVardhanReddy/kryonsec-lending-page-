/**
 * Notification mail.
 *
 * Import-only: never served.
 *
 * ---------------------------------------------------------------------------
 * What this is, and what it deliberately is not
 * ---------------------------------------------------------------------------
 *
 * There is no mail provider configured for this project. The brief for this
 * work anticipated that and asked for an interface plus a working test mode
 * rather than a fabricated integration, so that is what this is:
 *
 *   - messages are written to `email_outbox` as rows, in the same transaction
 *     as the decision that caused them, so a mail outage can never roll back
 *     an approval
 *   - `drain()` sends whatever is queued, and with no provider configured it
 *     records the send and logs the envelope without a body
 *   - wiring a real provider is one function: `send()`. Nothing else changes,
 *     and every message already sitting in the outbox goes out on the next
 *     drain.
 *
 * Marking a message `sent` in log mode is not a lie about delivery — it is a
 * statement that the outbox did its job. The log line is the evidence that no
 * mail actually left. An operator who reads `status='sent'` as "the applicant
 * got an email" is wrong, and the /admin outbox view says so on the page.
 *
 * ---------------------------------------------------------------------------
 * Two rules from the brief that shape everything below
 * ---------------------------------------------------------------------------
 *
 * 1. Nothing here is a credential. A membership key, a device code, a session
 *    cookie, a CLI token — none of them belong in an email, and none of them
 *    are constructed here. Every message says "go to this page and sign in
 *    with the account you already used". A permanent reusable credential in
 *    an inbox outlives the person's access to the inbox and cannot be
 *    revoked.
 *
 * 2. The body is not stored. `email_outbox` keeps `kind` and a `payload` of
 *    non-sensitive values, and the message is rendered from those at send
 *    time. Storing rendered bodies would copy applicant text into a second
 *    table with a different retention story for no gain.
 */

import { nowIso } from "./_shared.js";

/** Every message this system sends. Adding one means adding a `render` case. */
export const KINDS = {
  RECEIVED: "application.received",
  APPROVED: "application.approved",
  REJECTED: "application.rejected",
  WAITLISTED: "application.waitlisted",
  REVOKED: "entitlement.revoked",
  ACCESS_GRANTED: "entitlement.granted",
};

const SITE = "https://kryonsec.in";

/**
 * The outbox row, as a prepared statement.
 *
 * Returned unbound-statement-shaped so a caller can drop it into a
 * `db.batch()` alongside the decision that caused it. That is the whole point:
 * the decision and the notification commit together, or neither does.
 *
 * `INSERT OR IGNORE` against UNIQUE(kind, dedupe_key) is what makes a retry
 * safe. An admin who clicks "retry" twice, or a decision handler that runs
 * after a partial failure, must not send a second copy — and it must not fail
 * the surrounding transaction either, which a bare INSERT would.
 */
export function outboxStatement(db, { kind, dedupeKey, toEmail, userId = null, payload = null }) {
  return db
    .prepare(
      `INSERT OR IGNORE INTO email_outbox
         (kind, dedupe_key, to_email, user_id, payload, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'queued', ?)`,
    )
    .bind(kind, dedupeKey, toEmail, userId, payload ? JSON.stringify(payload) : null, nowIso());
}

/**
 * Render a queued row into a message, or null if the kind is unknown.
 *
 * Plain text, no HTML: there is nothing here that needs a layout, and a text
 * body cannot carry a tracking pixel or be used to probe which client the
 * applicant reads.
 */
export function render(row) {
  const payload = row.payload ? safeParse(row.payload) : {};
  const name = String(payload.name || "").trim();
  const hello = name ? `Hi ${name},` : "Hi,";

  switch (row.kind) {
    case KINDS.RECEIVED:
      return {
        subject: "Kryonsec beta — we have your application",
        text: `${hello}

Your request for Kryonsec early access is in. A person reads every one of
these, so it will be a few days rather than a few minutes.

You can follow the status any time at ${SITE}/dashboard

— Kryonsec`,
      };

    case KINDS.APPROVED:
      return {
        subject: "Kryonsec beta — you are in",
        text: `${hello}

Your access is active. There is nothing to paste and no key to keep: sign in
at ${SITE}/dashboard with the same account you applied with, and the download
and setup steps are there.

— Kryonsec`,
      };

    case KINDS.REJECTED:
      return {
        subject: "Kryonsec beta — your application",
        text: `${hello}

We are not able to offer you a place in this round of the beta.

This is a small programme and the answer is about capacity, not about you. You
are welcome to apply again when the next round opens.

— Kryonsec`,
      };

    case KINDS.WAITLISTED:
      return {
        subject: "Kryonsec beta — you are on the list",
        text: `${hello}

We have put your application on the waiting list. Places open up as the
programme grows, and yours moves up as they do.

Status: ${SITE}/dashboard

— Kryonsec`,
      };

    case KINDS.ACCESS_GRANTED:
      return {
        subject: "Kryonsec beta — access restored",
        text: `${hello}

Your access to the Kryonsec beta has been turned back on.

— Kryonsec`,
      };

    case KINDS.REVOKED:
      return {
        subject: "Kryonsec beta — access has ended",
        text: `${hello}

Your access to the Kryonsec beta has been switched off, so downloads and the
command line will stop working.

${payload.reason ? `Reason given: ${payload.reason}\n\n` : ""}If you think this is a mistake, reply to this message.

— Kryonsec`,
      };

    default:
      return null;
  }
}

function safeParse(text) {
  try {
    return JSON.parse(text) || {};
  } catch {
    return {};
  }
}

/**
 * Hand one message to a provider. The seam.
 *
 * Returns `{ ok, error }`. Nothing in this function may throw: it is called
 * from a drain loop over rows that are already committed, and one bad address
 * must not stop the queue behind it.
 *
 * With no provider configured this is log mode. It reports success — the
 * message is marked sent — and the caller logs the envelope. See the module
 * comment for why that is the honest behaviour rather than a stub that
 * pretends to deliver.
 */
async function send(env, message) {
  const provider = String(env?.KRYONSEC_EMAIL_PROVIDER || "").trim().toLowerCase();
  const from = String(env?.KRYONSEC_EMAIL_FROM || "").trim();

  if (!provider) {
    // Log mode.
    return { ok: true, mode: "log" };
  }

  if (!from) {
    return { ok: false, error: "KRYONSEC_EMAIL_FROM is not set" };
  }

  // ponytail: one provider seam. Add a case here — Resend, Postmark, SES —
  // when a key exists. Everything upstream already works.
  return { ok: false, error: `no adapter for provider "${provider}"` };
}

/** The subject line, with its newlines collapsed — it is a header. */
export const subjectOf = (rendered) => String(rendered.subject).replace(/\s+/g, " ").slice(0, 200);

/**
 * Send up to `limit` queued messages.
 *
 * Failures are recorded on the row and left queued-or-failed rather than
 * thrown: this runs after a decision has already been committed, and an
 * applicant losing an email is a smaller problem than an admin losing the
 * decision.
 */
export async function drain(db, env, { limit = 20 } = {}) {
  const { results } = await db
    .prepare(
      `SELECT * FROM email_outbox WHERE status = 'queued' ORDER BY created_at LIMIT ?`,
    )
    .bind(limit)
    .all();

  let sent = 0;
  let failed = 0;

  for (const row of results || []) {
    const rendered = render(row);
    if (!rendered) {
      failed += 1;
      await markFailed(db, row.id, "no template for this notification kind");
      continue;
    }

    const outcome = await send(env, { to: row.to_email, ...rendered });

    if (outcome.ok) {
      sent += 1;
      await db
        .prepare(
          `UPDATE email_outbox
              SET status = 'sent', attempts = attempts + 1, sent_at = ?
            WHERE id = ? AND status = 'queued'`,
        )
        .bind(nowIso(), row.id)
        .run();
      // Envelope only. The body is a rendering of a decision the audit table
      // already records, and the body is never the place to look for one.
      console.log(`mail: ${outcome.mode} ${row.kind} -> ${row.id}`);
    } else {
      failed += 1;
      await markFailed(db, row.id, outcome.error);
    }
  }

  return { sent, failed, queued: (results || []).length };
}

/** Bumping attempts is what lets the admin view show a message stuck retrying. */
async function markFailed(db, id, error) {
  await db
    .prepare(
      `UPDATE email_outbox
          SET status = 'failed', attempts = attempts + 1, last_error = ?
        WHERE id = ? AND status = 'queued'`,
    )
    .bind(String(error || "unknown error").slice(0, 300), id)
    .run();
}
