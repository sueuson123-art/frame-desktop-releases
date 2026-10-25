const encoder=new TextEncoder();
const now=()=>Math.floor(Date.now()/1000);
const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(s)))).map(n=>n.toString(16).padStart(2,'0')).join('');
const random=()=>b64(crypto.getRandomValues(new Uint8Array(32)));
function reply(value,status=200){return Response.json(value,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}})}
function same(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0}
async function sign(payload,env){
 const pkcs8=Uint8Array.from(atob(env.SIGNING_KEY),c=>c.charCodeAt(0));
 const key=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},false,['sign']);
 const data=b64(encoder.encode(JSON.stringify(payload)));
 return {payload:data,signature:b64(await crypto.subtle.sign('Ed25519',key,encoder.encode(data))),keyId:'frame-2026-01'};
}
async function body(request){
 if(!request.headers.get('content-type')?.startsWith('application/json'))throw Error('json-required');
 if(Number(request.headers.get('content-length')||0)>12000)throw Error('request-too-large');
 if(!request.body)throw Error('json-required');
 const reader=request.body.getReader(),parts=[];let length=0;
 for(;;){const {value,done}=await reader.read();if(done)break;length+=value.byteLength;if(length>12000){await reader.cancel();throw Error('request-too-large')}parts.push(value)}
 const bytes=new Uint8Array(length);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.byteLength}
 const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 if(!result||typeof result!=='object'||Array.isArray(result))throw Error('json-object-required');return result;
}
function validEmail(s){return typeof s==='string'&&s.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)}
function validDevice(s){return typeof s==='string'&&/^[a-f0-9]{64}$/.test(s)}
async function lease(row,deviceId,env){return sign({type:'license',licenseId:row.id,deviceId,plan:'standard',issuedAt:now(),expiresAt:Math.min(row.expires_at,now()+86400)},env)}
async function limit(request,env){
 const key=await hash('frame-license:'+request.headers.get('CF-Connecting-IP'));
 const bucket=Math.floor(now()/60);
 await env.DB.prepare('DELETE FROM rate_limits WHERE key IN (SELECT key FROM rate_limits WHERE bucket<? LIMIT 100)').bind(bucket-60).run();
 await env.DB.prepare('INSERT INTO rate_limits(key,bucket,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN bucket=excluded.bucket THEN count+1 ELSE 1 END,bucket=excluded.bucket').bind(key,bucket).run();
 const row=await env.DB.prepare('SELECT count FROM rate_limits WHERE key=?').bind(key).first();
 return row.count<=20;
}
export default {
 async fetch(request,env){
  const url=new URL(request.url),path=url.pathname;
  if(path==='/health'&&request.method==='GET'){
   let databaseReady=false,signingReady=false;
   if(env.DB)try{const rows=await env.DB.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name IN ('licenses','activations','settings','rate_limits')").first();databaseReady=rows?.n===4}catch{}
   if(env.SIGNING_KEY)try{await sign({type:'health'},env);signingReady=true}catch{}
   return reply({service:'FRAME authorization and updates',databaseReady,signingReady,licenseReady:Boolean(databaseReady&&signingReady&&env.ADMIN_TOKEN),updateReady:Boolean(databaseReady&&signingReady),paymentsReady:false});
  }
  if(!env.DB||!env.SIGNING_KEY)return reply({error:'service-not-configured'},503);
  try {
   if(path==='/v1/updates'&&request.method==='GET'){
    const row=await env.DB.prepare("SELECT value FROM settings WHERE key='latest-release'").first();
    return row?reply(JSON.parse(row.value)):reply({status:'no-release-published'});
   }
   if(path==='/v1/license/activate'&&request.method==='POST'){
    if(!await limit(request,env))return reply({error:'too-many-requests'},429);
    const b=await body(request);
    if(!validEmail(b.email)||!validDevice(b.deviceId)||typeof b.code!=='string'||b.code.length<20||b.code.length>150)return reply({error:'invalid-activation'},400);
    const codeHash=await hash(b.code.trim()),email=b.email.trim().toLowerCase();
    const row=await env.DB.prepare("SELECT * FROM licenses WHERE code_hash=? AND email=? AND status='active' AND expires_at>?").bind(codeHash,email,now()).first();
    if(!row)return reply({error:'license-not-valid'},403);
    const refresh=random(),refreshHash=await hash(refresh),stamp=now();
    // The seat test and insert share one SQLite statement; concurrent activations cannot oversubscribe.
    await env.DB.prepare("INSERT INTO activations(license_id,device_id,refresh_hash,updated_at) SELECT id,?,?,? FROM licenses WHERE id=? AND status='active' AND expires_at>? AND ((SELECT COUNT(*) FROM activations WHERE license_id=?)<seats OR EXISTS(SELECT 1 FROM activations WHERE license_id=? AND device_id=?)) ON CONFLICT(license_id,device_id) DO UPDATE SET refresh_hash=excluded.refresh_hash,updated_at=excluded.updated_at")
      .bind(b.deviceId,refreshHash,stamp,row.id,stamp,row.id,row.id,b.deviceId).run();
    const saved=await env.DB.prepare('SELECT refresh_hash FROM activations WHERE license_id=? AND device_id=?').bind(row.id,b.deviceId).first();
    if(!saved||saved.refresh_hash!==refreshHash)return reply({error:'device-limit-reached'},409);
    const current=await env.DB.prepare("SELECT * FROM licenses WHERE id=? AND status='active' AND expires_at>?").bind(row.id,now()).first();
    if(!current)return reply({error:'license-not-valid'},403);
    return reply({lease:await lease(current,b.deviceId,env),refreshToken:refresh,serverTime:now()});
   }
   if(path==='/v1/license/refresh'&&request.method==='POST'){
    if(!await limit(request,env))return reply({error:'too-many-requests'},429);
    const b=await body(request);
    if(!validDevice(b.deviceId)||typeof b.refreshToken!=='string'||b.refreshToken.length>150)return reply({error:'invalid-session'},400);
    const row=await env.DB.prepare("SELECT l.* FROM licenses l JOIN activations a ON a.license_id=l.id WHERE a.device_id=? AND a.refresh_hash=? AND l.status='active' AND l.expires_at>?").bind(b.deviceId,await hash(b.refreshToken),now()).first();
    if(!row)return reply({error:'license-not-valid'},403);
    return reply({lease:await lease(row,b.deviceId,env),serverTime:now()});
   }
   if(path.startsWith('/admin/')){
    if(!env.ADMIN_TOKEN||!same(request.headers.get('Authorization'),'Bearer '+env.ADMIN_TOKEN))return reply({error:'unauthorized'},401);
    if(path==='/admin/licenses'&&request.method==='POST'){
     const b=await body(request);
     if(!validEmail(b.email)||!Number.isSafeInteger(b.expiresAt)||b.expiresAt<=now()||!Number.isInteger(b.seats)||b.seats<1||b.seats>10)return reply({error:'invalid-license-settings'},400);
     const id=crypto.randomUUID(),code='FRAME-'+random();
     await env.DB.prepare('INSERT INTO licenses(id,email,code_hash,expires_at,seats,status,created_at) VALUES(?,?,?,?,?,?,?)').bind(id,b.email.trim().toLowerCase(),await hash(code),b.expiresAt,b.seats,'active',now()).run();
     return reply({id,code,expiresAt:b.expiresAt,seats:b.seats},201);
    }
    if(path==='/admin/revoke'&&request.method==='POST'){
     const b=await body(request);if(typeof b.id!=='string'||b.id.length>100)return reply({error:'invalid-license-id'},400);
     await env.DB.prepare("UPDATE licenses SET status='revoked' WHERE id=?").bind(b.id).run();return reply({saved:true});
    }
    if(path==='/admin/releases'&&request.method==='POST'){
     const b=await body(request);let download;
     try{download=new URL(b.url)}catch{return reply({error:'invalid-release-url'},400)}
     if(!/^\d+\.\d+\.\d+$/.test(b.version)||!/^https:\/\/github\.com\/sueuson123-art\/frame-desktop-releases\/releases\/download\//.test(download.href)||!/^[a-f0-9]{64}$/.test(b.sha256)||!Number.isSafeInteger(b.bytes)||b.bytes<1||b.bytes>2147483648)return reply({error:'invalid-release'},400);
     const signed=await sign({type:'update',version:b.version,url:download.href,sha256:b.sha256,bytes:b.bytes,notes:String(b.notes||'').slice(0,3000),issuedAt:now()},env);
     await env.DB.prepare("INSERT INTO settings(key,value) VALUES('latest-release',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(JSON.stringify(signed)).run();return reply({saved:true});
    }
   }
   return reply({error:'not-found'},404);
  } catch {return reply({error:'request-not-completed'},400)}
 }
};
