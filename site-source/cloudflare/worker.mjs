export const POLICY_VERSION='2026-11-22';
const enc=new TextEncoder();
export const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(s))),x=>x.toString(16).padStart(2,'0')).join('');
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
const now=()=>Math.floor(Date.now()/1000);
const cookie=(name,value,age)=>`${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const cookies=r=>Object.fromEntries((r.headers.get('cookie')||'').split(';').map(x=>x.trim().split('=')));
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
const redirect=(url,c)=>new Response(null,{status:303,headers:{Location:url,...(c?{'Set-Cookie':c}:{})}});
export function securityHeaders(response){const h=new Headers(response.headers);h.set('Cache-Control','no-store');h.set('X-Content-Type-Options','nosniff');h.set('Referrer-Policy','no-referrer');h.set('X-Frame-Options','DENY');h.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');h.set('Strict-Transport-Security','max-age=31536000');h.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");return new Response(response.body,{status:response.status,headers:h});}
export async function session(req,env){const token=cookies(req)['__Host-kryo'];if(!/^[a-f0-9]{64}$/.test(token||''))return null;const row=await env.DB.prepare('SELECT users.id, users.login, users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>?').bind(await hash(token),now()).first();return row?{...row,token}:null;}
export async function csrfOK(req,user){if(req.headers.get('origin')!==new URL(req.url).origin)return false;return req.headers.get('x-csrf-token')===await hash(user.token+':csrf');}
async function limited(env,key,max){const bucket=Math.floor(now()/600);const k=await hash(key+':'+bucket);const row=await env.DB.prepare('INSERT INTO rate_limits(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count').bind(k,now()+1200).first();return row.count>max;}
async function readBody(req){if(Number(req.headers.get('content-length'))>8192)throw new Error('BODY_LIMIT');if(!req.headers.get('content-type')?.startsWith('application/json'))throw new Error('CONTENT_TYPE');const reader=req.body?.getReader();if(!reader)throw new Error('BODY');let chunks=[],total=0;while(true){const {value,done}=await reader.read();if(done)break;total+=value.length;if(total>8192){await reader.cancel();throw new Error('BODY_LIMIT');}chunks.push(value);}const bytes=new Uint8Array(total);let pos=0;for(const c of chunks){bytes.set(c,pos);pos+=c.length;}return JSON.parse(new TextDecoder().decode(bytes));}
const validText=(v,min,max)=>typeof v==='string'&&v.trim().length>=min&&v.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v);
export async function handle(req,env){const url=new URL(req.url),path=url.pathname;
 if(!path.startsWith('/api/')&&!path.startsWith('/auth/'))return null;
 if(env.APP_ORIGIN&&url.origin!==env.APP_ORIGIN)return json({error:'Unexpected host.'},400);
 const ready=!!(env.DB&&env.GITHUB_CLIENT_ID&&env.GITHUB_CLIENT_SECRET&&env.APP_ORIGIN&&env.ADMIN_GITHUB_ID&&env.POLICIES_READY==='true');
 if(path==='/api/config'&&req.method==='GET')return json({ready,provider:'github',policyVersion:POLICY_VERSION});
 if(!ready)return json({error:'Beta accounts are not open yet. OAuth and policy setup must be completed first.'},503);
 if(path==='/auth/github'&&req.method==='GET'){
  if(await limited(env,'oauth:'+ (req.headers.get('CF-Connecting-IP')||'unknown'),20))return json({error:'Too many sign-in attempts. Try again in ten minutes.'},429);
  const state=random(),verifier=random();await env.DB.prepare('INSERT INTO oauth_states VALUES(?,?,?)').bind(await hash(state),verifier,now()+600).run();
  const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(verifier)));const challenge=btoa(String.fromCharCode(...bytes)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const target=new URL('https://github.com/login/oauth/authorize');target.search=new URLSearchParams({client_id:env.GITHUB_CLIENT_ID,redirect_uri:env.APP_ORIGIN+'/auth/callback',scope:'read:user user:email',state,code_challenge:challenge,code_challenge_method:'S256'}).toString();
  return redirect(target.toString(),cookie('__Host-kryo-oauth',state,600));
 }
 if(path==='/auth/callback'&&req.method==='GET'){
  const state=url.searchParams.get('state'),code=url.searchParams.get('code');if(!state||!/^[a-f0-9]{64}$/.test(state)||state!==cookies(req)['__Host-kryo-oauth']||!code||code.length>512)return json({error:'Sign-in could not be verified. Start again.'},400);
  const grant=await env.DB.prepare('DELETE FROM oauth_states WHERE state_hash=? AND expires>? RETURNING verifier').bind(await hash(state),now()).first();if(!grant)return json({error:'Sign-in expired or already used. Start again.'},400);
  const exchange=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code,redirect_uri:env.APP_ORIGIN+'/auth/callback',code_verifier:grant.verifier}),signal:AbortSignal.timeout(10000)});
  if(!exchange.ok)return json({error:'GitHub sign-in is temporarily unavailable.'},502);const tokenData=await exchange.json();if(!tokenData.access_token)return json({error:'GitHub did not authorize sign-in. Please try again.'},400);
  const headers={Authorization:'Bearer '+tokenData.access_token,Accept:'application/vnd.github+json','User-Agent':'KryonSec-beta'};
  const [pr,er]=await Promise.all([fetch('https://api.github.com/user',{headers,signal:AbortSignal.timeout(10000)}),fetch('https://api.github.com/user/emails',{headers,signal:AbortSignal.timeout(10000)})]);if(!pr.ok||!er.ok)return json({error:'Could not verify your GitHub identity.'},502);
  const profile=await pr.json(),emails=await er.json();const email=Array.isArray(emails)?emails.find(e=>e.primary&&e.verified)?.email:null;
  if(!email||!Number.isSafeInteger(profile.id)||!profile.login)return json({error:'A verified primary GitHub email is required.'},403);
  const id=String(profile.id),token=random();
  const prior=cookies(req)['__Host-kryo'];
  await env.DB.batch([env.DB.prepare('INSERT INTO users VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET login=excluded.login,email=excluded.email').bind(id,profile.login,email,now()),env.DB.prepare('INSERT INTO sessions VALUES(?,?,?)').bind(await hash(token),id,now()+86400),env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(prior||''))]);
  const response=redirect('/account.html',cookie('__Host-kryo',token,86400));response.headers.append('Set-Cookie',cookie('__Host-kryo-oauth','',0));return response;
 }
 const user=await session(req,env);if(!user)return json({error:'Sign in to continue.'},401);
 const admin=user.id===String(env.ADMIN_GITHUB_ID);
 if(path==='/api/me'&&req.method==='GET'){const application=await env.DB.prepare('SELECT name,role,goal,status,terms_version,privacy_version,accepted,updated FROM applications WHERE user_id=?').bind(user.id).first();return json({user:{login:user.login,email:user.email},admin,application,csrf:await hash(user.token+':csrf')});}
 if(path==='/api/admin/applications'&&req.method==='GET'){if(!admin)return json({error:'Founder access required.'},403);const rows=await env.DB.prepare('SELECT a.*,u.login,u.email FROM applications a JOIN users u ON u.id=a.user_id ORDER BY a.updated DESC LIMIT 100').all();return json({applications:rows.results});}
 if(req.method!=='POST')return json({error:'Not found.'},404);
 if(!await csrfOK(req,user))return json({error:'Request verification failed. Refresh and try again.'},403);
 if(await limited(env,'write:'+user.id,30))return json({error:'Too many requests. Try again in ten minutes.'},429);
 if(path==='/api/logout'){await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(user.token)).run();const r=json({ok:true});r.headers.set('Set-Cookie',cookie('__Host-kryo','',0));return r;}
 let data;try{data=await readBody(req);}catch{return json({error:'Invalid request body.'},400);}
 if(path==='/api/apply'){
  if(!validText(data.name,2,100)||!validText(data.role,2,120)||!validText(data.goal,20,2000)||data.terms!==true||data.privacy!==true||data.version!==POLICY_VERSION)return json({error:'Complete all fields and accept the current beta guidelines and privacy notice.'},400);
  const result=await env.DB.prepare("INSERT OR IGNORE INTO applications VALUES(?,?,?,?,'pending',?,?,?,?)").bind(user.id,data.name.trim(),data.role.trim(),data.goal.trim(),POLICY_VERSION,POLICY_VERSION,now(),now()).run();if(!result.meta.changes)return json({error:'You already have an application. Check its status.'},409);return json({ok:true,status:'pending'},201);
 }
 if(path==='/api/admin/decision'){
  if(!admin)return json({error:'Founder access required.'},403);
  if(!/^\d{1,25}$/.test(data.userId||'')||!['approved','declined','revoked'].includes(data.status)||!['pending','approved','declined','revoked'].includes(data.previous))return json({error:'Invalid review decision.'},400);
  // Audit is inserted only if the guarded update changed a row. D1 batch is transactional.
  const result=await env.DB.batch([env.DB.prepare('UPDATE applications SET status=?,updated=? WHERE user_id=? AND status=?').bind(data.status,now(),data.userId,data.previous),env.DB.prepare('INSERT INTO audit(actor,subject,action,created) SELECT ?,?,?,? WHERE changes()=1').bind(user.id,data.userId,data.status,now())]);
  return result[0].meta.changes?json({ok:true}):json({error:'Application changed. Refresh before reviewing.'},409);
 }
 if(path==='/api/access'){
  const application=await env.DB.prepare('SELECT status FROM applications WHERE user_id=?').bind(user.id).first();if(application?.status!=='approved')return json({error:'Approved beta membership is required.'},403);
  // Intentionally no public install URL or transferable license. CLI integration is a separate release task.
  return json({approved:true,downloadReady:false,message:'Your application is approved. RahaSec will arrange the authorized testing scope and installation. CLI access is not enabled by this website alone.'});
 }
 return json({error:'Not found.'},404);
}
export default {async fetch(request,env){try{const r=await handle(request,env);return securityHeaders(r||new Response('Not found',{status:404}));}catch{return securityHeaders(json({error:'The service could not complete that request. Please try again later.'},500));}},async scheduled(event,env){const t=now();await env.DB.batch([env.DB.prepare('DELETE FROM oauth_states WHERE expires<?').bind(t),env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(t),env.DB.prepare('DELETE FROM rate_limits WHERE expires<?').bind(t)]);}};
