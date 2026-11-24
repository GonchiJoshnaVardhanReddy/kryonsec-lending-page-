import { configuredProviders } from '../_oauth.js';
import { currentSession } from '../_auth.js';
export async function onRequestGet({ request, env }) {
  const providers = env.KRYONSEC_DB ? configuredProviders(env) : [];
  const session = env.KRYONSEC_DB ? await currentSession(env.KRYONSEC_DB, request) : null;
  return Response.json({ ready: providers.length > 0, providers, signedIn: Boolean(session) }, {
    headers: { 'Cache-Control': 'no-store', 'Vary': 'Cookie', 'X-Content-Type-Options': 'nosniff' }
  });
}
