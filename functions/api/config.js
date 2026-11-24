export function onRequestGet() {
  return Response.json({ ready: false, provider: "github", policyVersion: "2026-11-22" }, { headers: { "Cache-Control": "no-store" } });
}
