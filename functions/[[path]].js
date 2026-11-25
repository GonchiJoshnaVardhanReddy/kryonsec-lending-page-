import {handle,secure} from '../server/portal.mjs';
export async function onRequest(context){
 const p=new URL(context.request.url).pathname;
 if(p.startsWith('/beta/card/')||p.startsWith('/api/portal/')||/^\/api\/auth\/(github|google)\/(start|callback)$/.test(p))return handle(context.request,context.env);
 if(['/account','/account.html','/signin','/apply','/dashboard','/admin','/feedback','/feedback.html'].includes(p)){
  if(!['GET','HEAD'].includes(context.request.method))return secure(new Response('Method not allowed',{status:405}));
  const u=new URL('/portal.html',context.request.url);return secure(await context.env.ASSETS.fetch(new Request(u,{method:context.request.method})));
 }
 if(p.startsWith('/api/')||p.startsWith('/auth/')||['/install.sh','/install.ps1','/connect','/beta/device','/logout'].includes(p))return secure(Response.json({error:'This legacy service has been retired. Visit /account to apply for the new beta.'},{status:410}));
 if(p.startsWith('/server/')||p.startsWith('/tests/')||p.startsWith('/migrations/'))return new Response('Not found',{status:404});
 return context.next();
}
