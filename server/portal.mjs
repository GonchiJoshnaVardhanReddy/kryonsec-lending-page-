export const POLICY='2026-11-25';
export const OWNER_GITHUB_ID='170815623';
export const COOKIE='__Host-kryonsec-v2';
const FLOW_COOKIE='__Host-kryonsec-oauth-v2';
const ORIGIN='https://kryonsec.in';
const now=()=>Math.floor(Date.now()/1000);
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
export const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),b=>b.toString(16).padStart(2,'0')).join('');
const cookie=(name,value,age)=>`${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;
const cookies=req=>Object.fromEntries((req.headers.get('Cookie')||'').split(';').map(s=>s.trim().split('=')));
const json=(v,status=200)=>Response.json(v,{status});
const redirect=(url)=>new Response(null,{status:303,headers:{Location:url}});
export function secure(response){const h=new Headers(response.headers);h.set('Cache-Control','no-store');h.set('X-Content-Type-Options','nosniff');h.set('Referrer-Policy','no-referrer');h.set('X-Frame-Options','DENY');h.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');h.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");return new Response(response.body,{status:response.status,headers:h});}
const config={github:{authorize:'https://github.com/login/oauth/authorize',token:'https://github.com/login/oauth/access_token',scope:'read:user user:email'},google:{authorize:'https://accounts.google.com/o/oauth2/v2/auth',token:'https://oauth2.googleapis.com/token',scope:'openid email profile'}};
export function available(env){return Object.keys(config).filter(p=>env.KRYONSEC_DB&&env[`KRYONSEC_${p.toUpperCase()}_CLIENT_ID`]&&env[`KRYONSEC_${p.toUpperCase()}_CLIENT_SECRET`]);}
export const isAdmin=user=>user?.provider==='github'&&user.subject===OWNER_GITHUB_ID;
export async function session(req,env){const token=cookies(req)[COOKIE];if(!/^[a-f0-9]{64}$/.test(token||''))return null;const user=await env.KRYONSEC_DB.prepare('SELECT u.* FROM portal_sessions s JOIN portal_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?').bind(await hash(token),now()).first();return user?{...user,token}:null;}
async function limited(db,key,max){const k=await hash(key+':'+Math.floor(now()/600));const row=await db.prepare('INSERT INTO portal_limits(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count').bind(k,now()+1200).first();return row.count>max;}
async function body(req){if(!req.headers.get('content-type')?.startsWith('application/json'))throw Error('Use JSON.');if(Number(req.headers.get('content-length'))>16000)throw Error('Request too large.');const reader=req.body?.getReader();if(!reader)throw Error('Request body is required.');let size=0,parts=[];for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16000){await reader.cancel();throw Error('Request too large.');}parts.push(value);}const out=new Uint8Array(size);let n=0;for(const p of parts){out.set(p,n);n+=p.length;}const data=JSON.parse(new TextDecoder().decode(out));if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Invalid request.');return data;}
export function validate(data){
 const errors={},answer={};
 const fields={full_name:[2,100],location:[2,100],role:[2,100],organization:[0,140],experience:[2,80],security_background:[20,1500],use_case:[40,2500],goals:[20,1500],environment:[20,1500],os:[2,80],tools:[0,1000],team_size:[1,60],availability:[1,80],feedback:[2,80],discovery:[0,200],additional:[0,1500]};
 for(const [k,[min,max]] of Object.entries(fields)){const v=data[k];if(typeof v!=='string'||v.trim().length<min||v.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v)){errors[k]=`Enter ${min}–${max} characters.`;}else answer[k]=v.trim();}
 for(const k of ['linkedin','github','portfolio']){let v=data[k];if(typeof v!=='string'||v.length>500){errors[k]='Enter a valid HTTPS profile URL.';continue;}v=v.trim();answer[k]=v;if(!v)continue;try{const u=new URL(v);if(u.protocol!=='https:'||u.username||u.password||u.port)throw Error();if(k==='linkedin'&&(!['linkedin.com','www.linkedin.com'].includes(u.hostname)||!u.pathname.startsWith('/in/')))throw Error();if(k==='github'&&(u.hostname!=='github.com'||!/^\/[a-zA-Z0-9-]+\/?$/.test(u.pathname)))throw Error();}catch{errors[k]='Use a valid HTTPS '+(k==='portfolio'?'portfolio URL.':`${k} profile URL.`);}}
 if(!answer.linkedin&&!answer.github)errors.github='Add your GitHub or LinkedIn profile.';
 if(data.authorization!==true)errors.authorization='Confirm you will only test with authorization.';
 if(data.privacy!==true)errors.privacy='Acknowledge the privacy notice.';
 if(data.beta_terms!==true)errors.beta_terms='Acknowledge the beta guidelines.';
 if(data.policy_version!==POLICY)errors.policy_version='The guidelines changed. Refresh before submitting.';
 return {errors,answer};
}
async function external(url,init){const r=await fetch(url,{...init,signal:AbortSignal.timeout(12000)});if(!r.ok)throw Error('Provider request failed.');return r.json();}
export async function identity(env,provider,code,verifier){const p=config[provider],prefix=`KRYONSEC_${provider.toUpperCase()}`;
 const token=await external(p.token,{method:'POST',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:env[prefix+'_CLIENT_ID'],client_secret:env[prefix+'_CLIENT_SECRET'],code,code_verifier:verifier,redirect_uri:ORIGIN+`/api/auth/${provider}/callback`,grant_type:'authorization_code'})});
 if(!token.access_token)throw Error('No provider token.');const headers={Authorization:'Bearer '+token.access_token,Accept:'application/json','User-Agent':'Kryonsec-beta'};
 if(provider==='google'){const u=await external('https://openidconnect.googleapis.com/v1/userinfo',{headers});if(typeof u.sub!=='string'||!u.sub||u.email_verified!==true||!u.email)throw Error('A verified email is required.');return {subject:u.sub,email:u.email,name:u.name||'',profile_url:''};}
 const u=await external('https://api.github.com/user',{headers});const emails=await external('https://api.github.com/user/emails',{headers});const e=Array.isArray(emails)?emails.find(e=>e.primary&&e.verified):null;if(!Number.isSafeInteger(u.id)||!e?.email)throw Error('A verified primary email is required.');return {subject:String(u.id),email:e.email,name:u.name||u.login,profile_url:'https://github.com/'+u.login};
}
const publicApplication=a=>a?{id:a.id,status:a.status,answers:JSON.parse(a.answers),submitted:a.submitted,updated:a.updated,version:a.version,decision_message:a.decision_message}:null;
export async function route(req,env){
 const url=new URL(req.url),path=url.pathname,db=env.KRYONSEC_DB;
 if(path==='/api/portal/config'&&req.method==='GET')return json({providers:available(env),policy_version:POLICY});
 if(!db)return json({error:'Accounts are temporarily unavailable.'},503);
 if(url.origin!==ORIGIN)return json({error:'Use kryonsec.in to access your account.'},400);
 const auth=path.match(/^\/api\/auth\/(github|google)\/(start|callback)$/);
 if(auth){if(req.method!=='GET')return json({error:'Method not allowed.'},405);const [,provider,action]=auth;
  if(!available(env).includes(provider))return redirect('/account?error=provider_unavailable');
  if(action==='start'){
   if(await limited(db,'oauth:'+(req.headers.get('CF-Connecting-IP')||'unknown'),30))return json({error:'Too many sign-in attempts. Try again in ten minutes.'},429);
   await db.batch([db.prepare('DELETE FROM portal_oauth WHERE expires<?').bind(now()),db.prepare('DELETE FROM portal_sessions WHERE expires<?').bind(now()),db.prepare('DELETE FROM portal_limits WHERE expires<?').bind(now())]);
   const state=random(),verifier=random();await db.prepare('INSERT INTO portal_oauth VALUES(?,?,?,?)').bind(await hash(state),provider,verifier,now()+600).run();
   const challenge=btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
   const target=new URL(config[provider].authorize);target.search=new URLSearchParams({client_id:env[`KRYONSEC_${provider.toUpperCase()}_CLIENT_ID`],redirect_uri:ORIGIN+`/api/auth/${provider}/callback`,scope:config[provider].scope,response_type:'code',state,code_challenge:challenge,code_challenge_method:'S256',...(provider==='google'?{prompt:'select_account'}:{})});const r=redirect(target.href);r.headers.append('Set-Cookie',cookie(FLOW_COOKIE,state,600));return r;
  }
  const fail=reason=>{const r=redirect('/account?error='+reason);r.headers.append('Set-Cookie',cookie(FLOW_COOKIE,'',0));return r;};
  const state=url.searchParams.get('state');if(!/^[a-f0-9]{64}$/.test(state||'')||cookies(req)[FLOW_COOKIE]!==state)return fail('expired');
  const grant=await db.prepare('DELETE FROM portal_oauth WHERE state_hash=? AND provider=? AND expires>? RETURNING verifier').bind(await hash(state),provider,now()).first();if(!grant)return fail('expired');
  if(url.searchParams.has('error'))return fail('cancelled');const code=url.searchParams.get('code');if(!code||code.length>2048)return fail('incomplete');
  let who;try{who=await identity(env,provider,code,grant.verifier);}catch{return fail('provider_failed');}
  const id=provider+':'+who.subject,token=random();
  await db.batch([db.prepare('INSERT INTO portal_users VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,name=excluded.name,profile_url=excluded.profile_url,updated=excluded.updated').bind(id,provider,who.subject,who.email,who.name,who.profile_url,now(),now()),db.prepare('INSERT INTO portal_sessions VALUES(?,?,?)').bind(await hash(token),id,now()+86400),db.prepare('DELETE FROM portal_sessions WHERE token_hash=?').bind(await hash(cookies(req)[COOKIE]||''))]);
  const r=redirect(isAdmin({provider,subject:who.subject})?'/admin':'/dashboard');r.headers.append('Set-Cookie',cookie(COOKIE,token,86400));r.headers.append('Set-Cookie',cookie(FLOW_COOKIE,'',0));return r;
 }
 const user=await session(req,env);if(!user)return json({error:'Sign in to continue.'},401);
 if(req.method==='POST'&&(req.headers.get('Origin')!==ORIGIN||req.headers.get('X-CSRF-Token')!==await hash(user.token+':csrf')))return json({error:'Refresh the page before trying again.'},403);
 if(path==='/api/portal/me'&&req.method==='GET'){const a=await db.prepare('SELECT * FROM portal_applications WHERE user_id=?').bind(user.id).first();return json({user:{name:user.name,email:user.email,provider:user.provider,profile_url:user.profile_url},admin:isAdmin(user),csrf:await hash(user.token+':csrf'),application:publicApplication(a),policy_version:POLICY});}
 if(path==='/api/portal/logout'&&req.method==='POST'){await db.prepare('DELETE FROM portal_sessions WHERE token_hash=?').bind(await hash(user.token)).run();const r=json({ok:true});r.headers.append('Set-Cookie',cookie(COOKIE,'',0));return r;}
 if(path==='/api/portal/apply'&&req.method==='POST'){
  if(await limited(db,'apply:'+user.id,10))return json({error:'Too many submissions. Try again later.'},429);
  let data;try{data=await body(req);}catch{return json({error:'Invalid or oversized application.'},400);}const {errors,answer}=validate(data);if(Object.keys(errors).length)return json({error:'Please check the highlighted fields.',fields:errors},400);
  const existing=await db.prepare('SELECT id,status,version FROM portal_applications WHERE user_id=?').bind(user.id).first();
  if(existing){if(existing.status!=='needs_changes')return json({error:'You already have an application. Check your dashboard.'},409);if(data.version!==existing.version)return json({error:'Your application changed. Refresh and try again.'},409);
   const r=await db.prepare("UPDATE portal_applications SET answers=?,status='pending',policy_version=?,accepted=?,updated=?,version=version+1,decision_message='',admin_note='',reviewed_by=NULL,reviewed=NULL WHERE id=? AND version=? AND status='needs_changes' RETURNING id").bind(JSON.stringify(answer),POLICY,now(),now(),existing.id,data.version).first();if(!r)return json({error:'Your application changed. Refresh and try again.'},409);
  }else{try{await db.prepare("INSERT INTO portal_applications(id,user_id,status,answers,policy_version,accepted,submitted,updated) VALUES(?,?,'pending',?,?,?,?,?)").bind(random(),user.id,JSON.stringify(answer),POLICY,now(),now(),now()).run();}catch(e){if(String(e).includes('UNIQUE'))return json({error:'An application already exists.'},409);throw e;}}
  return json({ok:true},201);
 }
 if(path.startsWith('/api/portal/admin/')){
  if(!isAdmin(user))return json({error:'Administrator access required.'},403);
  if(path==='/api/portal/admin/applications'&&req.method==='GET'){
   const filter=url.searchParams.get('status')||'all';if(!['all','pending','approved','rejected','needs_changes','revoked'].includes(filter))return json({error:'Invalid status.'},400);const page=Math.max(1,Math.min(10000,parseInt(url.searchParams.get('page'))||1));const where=filter==='all'?'':'WHERE a.status=?';const args=filter==='all'?[]:[filter];
   const result=await db.prepare(`SELECT a.*,u.email,u.provider FROM portal_applications a JOIN portal_users u ON u.id=a.user_id ${where} ORDER BY a.submitted DESC,a.id LIMIT 30 OFFSET ?`).bind(...args,(page-1)*30).all();
   const counts=await db.prepare('SELECT status,count(*) AS count FROM portal_applications GROUP BY status').all();
   return json({applications:result.results.map(a=>({...publicApplication(a),email:a.email,provider:a.provider,admin_note:a.admin_note,reviewed:a.reviewed})),counts:counts.results,page});
  }
  if(path==='/api/portal/admin/decision'&&req.method==='POST'){
   let d;try{d=await body(req);}catch{return json({error:'Invalid request.'},400);}
   if(typeof d.id!=='string'||!/^[a-f0-9]{64}$/.test(d.id)||!Number.isSafeInteger(d.version)||!['approved','rejected','needs_changes','revoked'].includes(d.status)||typeof d.message!=='string'||d.message.length>2000||typeof d.note!=='string'||d.note.length>2000)return json({error:'Invalid review decision.'},400);
   if(['rejected','needs_changes','revoked'].includes(d.status)&&d.message.trim().length<10)return json({error:'Please explain this decision to the applicant (at least 10 characters).'},400);
   const old=await db.prepare('SELECT status FROM portal_applications WHERE id=?').bind(d.id).first();if(!old)return json({error:'Application not found.'},404);
   const allowed={pending:['approved','rejected','needs_changes'],approved:['revoked'],needs_changes:['approved','rejected'],rejected:['needs_changes','approved'],revoked:['approved','rejected']};if(!allowed[old.status].includes(d.status))return json({error:'This transition is not available.'},409);
   const changed=await db.prepare('UPDATE portal_applications SET status=?,decision_message=?,admin_note=?,reviewed_by=?,reviewed=?,updated=?,version=version+1 WHERE id=? AND version=? AND status=? RETURNING id').bind(d.status,d.message.trim(),d.note.trim(),user.id,now(),now(),d.id,d.version,old.status).first();if(!changed)return json({error:'Another review changed this application. Refresh the list.'},409);return json({ok:true});
  }
  if(path==='/api/portal/admin/audit'&&req.method==='GET'){const id=url.searchParams.get('id')||'';const r=await db.prepare('SELECT action,from_status,to_status,created FROM portal_audit WHERE application_id=? ORDER BY id DESC LIMIT 50').bind(id).all();return json({events:r.results});}
 }
 return json({error:'Not found.'},404);
}
export async function handle(req,env){try{return secure(await route(req,env));}catch{return secure(json({error:'The account service is temporarily unavailable. Please try again.'},503));}}
