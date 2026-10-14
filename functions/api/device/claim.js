/**
 * POST /api/device/claim   (an ordinary HTML form post, not JSON)
 *
 * Step 2 of the connect flow: the member submitted the code and their email.
 * This binds the key that /api/device/start recorded to a person, and records
 * the machine, which is what makes the admin view able to answer "who is using
 * this, and on how many machines".
 *
 * Anything that goes wrong redirects back to /connect with a reason code, so
 * the form markup lives only in connect.js and a member can simply retry.
 *
 * The claim is a single guarded UPDATE ... WHERE claimed_at IS NULL. Two
 * submissions racing — a double click, or two tabs — cannot both win, because
 * only one of them changes a row.
 *
 * Environment: KRYONSEC_DB (D1).
 */

import {
  CODE_TTL_MIN,
  cleanCode,
  cleanEmail,
  cleanText,
  esc,
  isoAgo,
  nowIso,
  page,
} from "../_shared.js";

function back(origin, code, reason) {
  const params = new URLSearchParams();
  if (code) params.set("code", code);
  params.set("e", reason);
  // 303 so the browser follows with a GET — a refresh must not repost.
  return Response.redirect(`${origin}/connect?${params}`, 303);
}

export async function onRequestPost({ request, env }) {
  const db = env.KRYONSEC_DB;
  const origin = new URL(request.url).origin;
  if (!db) return back(origin, "", "notconf");

  let form;
  try {
    form = await request.formData();
  } catch {
    return back(origin, "", "code");
  }

  const code = cleanCode(form.get("code"));
  if (!code) return back(origin, "", "code");

  const email = cleanEmail(form.get("email"));
  if (!email) return back(origin, code, "email");
  const name = cleanText(form.get("name"), 80);

  const row = await db
    .prepare(
      `SELECT code, key, device_id, os, arch, version, created_at, claimed_at
         FROM device_codes WHERE code = ?`,
    )
    .bind(code)
    .first();

  if (!row) return back(origin, code, "unknown");
  if (row.claimed_at) return back(origin, code, "used");
  if (row.created_at < isoAgo(CODE_TTL_MIN)) return back(origin, code, "expired");

  const now = nowIso();
  const claim = await db
    .prepare(
      `UPDATE device_codes SET claimed_at = ?, email = ?, name = ?
        WHERE code = ? AND claimed_at IS NULL`,
    )
    .bind(now, email, name, code)
    .run();
  if (!claim.meta || claim.meta.changes !== 1) return back(origin, code, "used");

  // The member record: first connect creates it, a later connect on a second
  // machine just refreshes it. One key, one member.
  await db
    .prepare(
      `INSERT INTO members (key, email, name, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         email = excluded.email, name = excluded.name, updated_at = excluded.updated_at`,
    )
    .bind(row.key, email, name, now, now)
    .run();

  // The machine. Reconnecting the same device updates it rather than adding a
  // duplicate row, so a member who reinstalls does not look like two machines.
  if (row.device_id) {
    await db
      .prepare(
        `INSERT INTO devices (id, key, os, arch, version, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           key = excluded.key, os = excluded.os, arch = excluded.arch,
           version = excluded.version, last_seen = excluded.last_seen`,
      )
      .bind(row.device_id, row.key, row.os || "", row.arch || "", row.version || "", now, now)
      .run();
  }

  return page(
    "Machine connected",
    `                <div class="section-bar"><span>KR / CONNECT</span><span>DONE</span></div>
                <h2 id="connected-title">MACHINE<br><em>CONNECTED.</em></h2>
                <p class="form-note">Registered to <b>${esc(email)}</b>.</p>
                <p class="form-note">Go back to your terminal — Kryonsec is already waiting and will pick this up on its own. You can close this tab.</p>`,
  );
}
