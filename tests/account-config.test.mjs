import test from 'node:test';
import assert from 'node:assert/strict';
import { onRequestGet } from '../functions/api/config.js';
import { testD1 } from './helpers/d1.mjs';
import { createSession, SESSION_COOKIE } from '../functions/_auth.js';
const request = new Request('https://kryonsec.in/api/config');
test('account providers require database and complete credentials', async () => {
  const env = {KRYONSEC_GITHUB_CLIENT_ID:'id', KRYONSEC_GITHUB_CLIENT_SECRET:'secret'};
  assert.deepEqual((await (await onRequestGet({request,env})).json()).providers, []);
  env.KRYONSEC_DB = testD1();
  env.KRYONSEC_GOOGLE_CLIENT_ID = 'google-id';
  let response = await onRequestGet({request,env});
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.deepEqual(await response.json(), {ready:true,providers:['github'],signedIn:false});
  env.KRYONSEC_GOOGLE_CLIENT_SECRET = 'google-secret';
  assert.deepEqual((await (await onRequestGet({request,env})).json()).providers, ['google','github']);
});
test('account config recognizes a real session without exposing account or credential data', async () => {
  const db = testD1();
  const now = new Date().toISOString();
  await db.prepare("INSERT INTO users (id,email,email_verified,name,created_at,updated_at) VALUES ('u_1','a@example.com',1,'A',?,?)").bind(now,now).run();
  const token = await createSession(db,'u_1');
  const req = new Request(request, {headers:{Cookie:`${SESSION_COOKIE}=${token}`}});
  const data = await (await onRequestGet({request:req,env:{KRYONSEC_DB:db}})).json();
  assert.deepEqual(data,{ready:false,providers:[],signedIn:true});
});
