#!/usr/bin/env node
'use strict';
/* Again ERP server - zero dependencies. Run: node server.js */
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib'),os=require('os');

const PORT=+process.env.PORT||3000,HOST=process.env.HOST||'0.0.0.0';
const ROOT=__dirname,DATA=process.env.DATA_DIR||path.join(ROOT,'data'),BAK=path.join(DATA,'backups'),PUB=path.join(ROOT,'public');
const ROT_MS=+process.env.ROT_MS||20000,MAXBODY=30*1024*1024,SESSION_MS=30*864e5;
const ROLES=['admin','accountant','supervisor','employee','warehouse','worker','engineer','sales','delivery'];
const DEP0={sales:['sales'],warehouse:['wh'],accountant:['ac'],supervisor:['ops'],worker:['ops'],delivery:['ops'],engineer:['ops']};
const PWC='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789',UNC='abcdefghjkmnpqrstuvwxyz23456789';
fs.mkdirSync(BAK,{recursive:true});

/* ---------- storage ---------- */
const readJ=(f,d)=>{try{return JSON.parse(fs.readFileSync(f,'utf8'))}catch(e){return d}};
const writeAtomic=(f,obj)=>{const t=f+'.tmp';fs.writeFileSync(t,JSON.stringify(obj));fs.renameSync(t,f)};
const F_STATE=path.join(DATA,'state.json'),F_AUTH=path.join(DATA,'auth.json');
let db=readJ(F_STATE,null)||{ver:0,state:null};
let auth=readJ(F_AUTH,null)||{creds:{},sessions:{}};
let pT=null,aT=null;
function persist(){clearTimeout(pT);pT=setTimeout(persistNow,400)}
function persistAuth(){clearTimeout(aT);aT=setTimeout(persistAuthNow,400)}
function persistAuthNow(){clearTimeout(aT);try{writeAtomic(F_AUTH,auth)}catch(e){console.error('auth write error:',e.message)}}
function persistNow(){
  clearTimeout(pT);
  try{
    if(fs.existsSync(F_STATE))fs.copyFileSync(F_STATE,F_STATE+'.prev');
    writeAtomic(F_STATE,db);dailyBackup();
  }catch(e){console.error('state write error:',e.message)}
}
let bT=null;
function writeBackup(){
  const d=new Date().toISOString().slice(0,10),f=path.join(BAK,'backup-'+d+'.json');
  try{
    fs.writeFileSync(f,JSON.stringify({db,auth}));
    const X=process.env.EXTRA_BACKUP_DIR;
    if(X){try{fs.mkdirSync(X,{recursive:true});fs.copyFileSync(f,path.join(X,path.basename(f)));
      const xs=fs.readdirSync(X).filter(x=>/^backup-\d{4}-\d{2}-\d{2}\.json$/.test(x)).sort();xs.slice(0,Math.max(0,xs.length-60)).forEach(x=>fs.unlinkSync(path.join(X,x)))}
      catch(e){console.error('extra backup error:',e.message)}}
    const all=fs.readdirSync(BAK).filter(x=>/^backup-\d{4}-\d{2}-\d{2}\.json$/.test(x)).sort();
    all.slice(0,Math.max(0,all.length-30)).forEach(x=>fs.unlinkSync(path.join(BAK,x)));
  }catch(e){console.error('backup error:',e.message)}
}
/* today's backup is refreshed at most every 10 minutes, and always once more after the last change */
function dailyBackup(){
  const f=path.join(BAK,'backup-'+new Date().toISOString().slice(0,10)+'.json');
  const age=fs.existsSync(f)?Date.now()-fs.statSync(f).mtimeMs:Infinity;
  if(age>600000){writeBackup();return}
  if(!bT){bT=setTimeout(()=>{bT=null;writeBackup()},Math.max(1000,600000-age+1000));bT.unref&&bT.unref()}
}
db.kv=db.kv||{};
const bump=keys=>{db.ver++;(keys||[]).forEach(k=>{db.kv[k]=db.ver});persist()};

/* ---------- crypto helpers ---------- */
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const rndStr=(n,cs)=>{let o='';const b=crypto.randomBytes(n*2);for(let i=0;i<n;i++)o+=cs[b.readUInt16BE(i*2)%cs.length];return o};
const scrypt=(pw,salt)=>new Promise((res,rej)=>crypto.scrypt(pw,salt,32,{N:16384,r:8,p:1},(e,k)=>e?rej(e):res(k.toString('hex'))));
const eq=(a,b)=>{const x=Buffer.from(a,'hex'),y=Buffer.from(b,'hex');return x.length===y.length&&crypto.timingSafeEqual(x,y)};
async function setPw(id,pw){const s=crypto.randomBytes(16).toString('hex');auth.creds[id]={s,h:await scrypt(pw,s)};killSessions(id);persistAuth()}
function killSessions(id){for(const k of Object.keys(auth.sessions))if(auth.sessions[k].uid==id)delete auth.sessions[k];persistAuth()}
const newUn=()=>{let u;do{u='ag-'+rndStr(6,UNC)}while(db.state.usr.some(x=>x.un===u));return u};

/* ---------- first run ---------- */
async function firstRun(){
  if(db.state&&db.state.usr&&db.state.usr.length)return;
  const un='ag-'+rndStr(6,UNC),pw=rndStr(12,PWC);
  db.state={usr:[{id:1,n:'المدير العام',un,roles:['admin'],on:1,av:1,dp:[]}],seq:{z:1}};db.ver=1;
  await setPw(1,pw);persistNow();persistAuthNow();
  const msg='بيانات دخول المدير العام (احفظها ثم احذف هذا الملف)\r\nاسم المستخدم: '+un+'\r\nكلمة المرور: '+pw+'\r\n';
  fs.writeFileSync(path.join(DATA,'FIRST-ADMIN.txt'),'\ufeff'+msg);
  console.log('\n==================== FIRST RUN ====================');
  console.log(' Admin username :',un);console.log(' Admin password :',pw);
  console.log(' (also saved in data/FIRST-ADMIN.txt - delete it after you save the password)');
  console.log('===================================================\n');
}

/* ---------- task rotation (runs on the server) ---------- */
const pool=(S,dp,rl)=>(S.usr||[]).filter(u=>u.on&&u.av!==0&&(u.dp||[]).includes(dp)&&(!rl||u.roles.includes(rl)));
const nextU=(S,dp,cur,rl)=>{const L=pool(S,dp,rl);if(!L.length)return cur;const k=L.findIndex(x=>x.id==cur);return L[(k+1)%L.length].id};
function rot(S){
  const now=Date.now(),lim=(S.tl||30)*60000;let ch=0;
  (S.tsk||[]).forEach(t=>{
    if(!t.dp||t.st!='open')return;const L=pool(S,t.dp,t.rl);if(!L.length)return;
    if(!L.some(x=>x.id==t.u)){t.u=nextU(S,t.dp,t.u,t.rl);t.at=now;t.h.push({u:t.u,at:now,ev:'إسناد'});ch=1;return}
    let g=0;while(now-t.at>=lim&&g++<60){const to=nextU(S,t.dp,t.u,t.rl);if(to==t.u){t.at=now;break}t.at+=lim;t.h.push({u:to,at:t.at,ev:'تناوب'});t.u=to;ch=1}
  });
  return ch;
}

/* ---------- http helpers ---------- */
const MIME={'.html':'text/html; charset=utf-8'};
const SEC={'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Cache-Control':'no-store',
  'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"};
function send(req,res,code,obj,extra){
  const body=Buffer.from(typeof obj==='string'?obj:JSON.stringify(obj));
  const h={'Content-Type':typeof obj==='string'?'text/html; charset=utf-8':'application/json; charset=utf-8',...SEC,...(extra||{})};
  if(body.length>2048&&/\bgzip\b/.test(req.headers['accept-encoding']||'')){const z=zlib.gzipSync(body);h['Content-Encoding']='gzip';h['Content-Length']=z.length;res.writeHead(code,h);return res.end(z)}
  h['Content-Length']=body.length;res.writeHead(code,h);res.end(body);
}
function readBody(req){return new Promise((res,rej)=>{let n=0;const c=[];req.on('data',d=>{n+=d.length;if(n>MAXBODY){rej(new Error('too large'));req.destroy()}else c.push(d)});req.on('end',()=>{try{res(c.length?JSON.parse(Buffer.concat(c).toString('utf8')):{})}catch(e){rej(new Error('bad json'))}});req.on('error',rej)})}
const isLoop=a=>a==='127.0.0.1'||a==='::1'||a==='::ffff:127.0.0.1';
const clientIp=req=>{const a=req.socket.remoteAddress||'';return isLoop(a)&&req.headers['cf-connecting-ip']?String(req.headers['cf-connecting-ip']):a};
const isHttps=req=>req.socket.encrypted||String(req.headers['x-forwarded-proto']||'').split(',')[0].trim()==='https';
const cookieHdr=(tok,req,clear)=>'sid='+(clear?'':tok)+'; HttpOnly; SameSite=Lax; Path=/; Max-Age='+(clear?0:Math.floor(SESSION_MS/1000))+(isHttps(req)?'; Secure':'');
function sessionOf(req){
  const m=/(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(!m)return null;
  const k=sha(m[1]),s=auth.sessions[k];if(!s)return null;
  if(s.exp<Date.now()){delete auth.sessions[k];persistAuth();return null}
  const u=(db.state.usr||[]).find(x=>x.id==s.uid&&x.on);return u?{u,k}:null;
}
const fails=new Map();

/* ---------- الصلاحيات (على السيرفر) ---------- */
/* المدير العام (admin) يقدر دايماً. أي مفتاح غير مذكور في WRITE مسموح لأي مستخدم مسجّل. عدّل هنا لو احتجت. */
const READ_ONLY_FOR={tre:['accountant'],vou:['accountant'],rf:['accountant'],ob:['accountant'],wk:['accountant','supervisor']};
const WRITE={
  tre:['accountant'],vou:['accountant'],rf:['accountant'],ob:['accountant'],wk:['accountant','supervisor'],
  cust:['accountant','supervisor','sales'],fs:['accountant','supervisor','sales'],
  inv:['accountant','supervisor','warehouse','sales','engineer'],
  sup:['accountant','supervisor','warehouse'],cnt:['supervisor','warehouse'],
  tl:['supervisor'],rm:['supervisor'],es:['supervisor'],st:['supervisor'],
  otp:[],pm:[],cr:[],cp:[]
};
const isAdm=r=>r.includes('admin');
const canRead=(r,k)=>isAdm(r)||!READ_ONLY_FOR[k]||r.some(x=>READ_ONLY_FOR[k].includes(x));
const canWrite=(r,k)=>isAdm(r)||!WRITE[k]||r.some(x=>WRITE[k].includes(x));
/* البيانات المخفية بتوصل كقيمة فاضية من نفس النوع، عشان الواجهة ما تتكسرش */
const viewFor=(S,roles)=>{
  if(isAdm(roles))return S;const o={...S};
  for(const k of Object.keys(READ_ONLY_FOR))if(k in o&&!canRead(roles,k)){const v=o[k];o[k]=Array.isArray(v)?[]:typeof v==='number'?0:(v&&typeof v==='object')?{}:v}
  return o;
};
/* حماية الخزينة: السند لا يُعدَّل ولا يُحذف، وأي تغيير في الخزينة لازم يكون معه سند بنفس المبلغ */
function ledgerCheck(me,st,set){
  if(!('vou' in set)&&!('tre' in set))return null;
  const oldV=Array.isArray(st.vou)?st.vou:[],newV='vou' in set?set.vou:oldV;
  const oldT=Number(st.tre)||0,newT='tre' in set?Number(set.tre):oldT;
  if(!Array.isArray(newV)||!Number.isFinite(newT))return 'بيانات الخزينة غير صالحة';
  if(isAdm(me.roles)&&newV.length===0&&Math.abs(newT)<0.005)return null;   /* إعادة ضبط كاملة من المدير */
  const oldBy=new Map(oldV.map(v=>[v.id,JSON.stringify(v)])),seen=new Set();let net=0;
  for(const v of newV){
    if(!v||typeof v!=='object')return 'سند غير صالح';
    if(seen.has(v.id))return 'سند مكرر';seen.add(v.id);
    if(oldBy.has(v.id)){if(oldBy.get(v.id)!==JSON.stringify(v))return 'السندات لا تُعدَّل';continue}
    const a=Number(v.a);if((v.t!=='قبض'&&v.t!=='صرف')||!Number.isFinite(a)||a<=0)return 'سند غير صالح';
    net+=v.t==='قبض'?a:-a;
  }
  for(const id of oldBy.keys())if(!seen.has(id))return 'السندات لا تُحذف';
  if(Math.abs((newT-oldT)-net)>0.005)return 'تغيير الخزينة لازم يكون معه سند بنفس المبلغ';
  if(newT<-0.005)return 'رصيد الخزينة لا يمكن أن يكون سالباً';
  return null;
}

/* ---------- user table protection ---------- */
const skey=o=>JSON.stringify(o,Object.keys(o).sort());
function checkUsr(nu,me,old){
  if(!Array.isArray(nu)||nu.length>500)return {code:400,msg:'بيانات المستخدمين غير صالحة'};
  const oldBy=new Map(old.map(u=>[u.id,u]));
  for(const u of nu){if(!u||typeof u.id!=='number'||!oldBy.has(u.id))return {code:403,msg:'لا يمكن إضافة مستخدمين بهذه الطريقة'}}
  if(new Set(nu.map(u=>u.id)).size!==nu.length)return {code:400,msg:'تكرار في المستخدمين'};
  if(!me.roles.includes('admin')){
    if(nu.length!==old.length)return {code:403,msg:'غير مسموح'};
    const canAv=me.roles.includes('supervisor');for(const u of nu){const o=oldBy.get(u.id),a={...u},b={...o};if(u.id===me.id||canAv){delete a.av;delete b.av}if(skey(a)!==skey(b))return {code:403,msg:'غير مسموح بتعديل بيانات المستخدمين'}}
    return null;
  }
  const seen=new Set();
  for(const u of nu){
    if(!/^[a-z0-9._-]{3,30}$/.test(String(u.un||'')))return {code:400,msg:'اسم مستخدم غير صالح'};
    if(seen.has(u.un))return {code:400,msg:'اسم المستخدم مكرر'};seen.add(u.un);
    if(!Array.isArray(u.roles)||u.roles.some(r=>!ROLES.includes(r)))return {code:400,msg:'صلاحيات غير صالحة'};
    if(typeof u.n!=='string'||!u.n.trim()||u.n.length>80)return {code:400,msg:'اسم غير صالح'};
  }
  if(!nu.some(u=>u.on&&u.roles.includes('admin')))return {code:400,msg:'يجب بقاء مدير عام مفعّل واحد على الأقل'};
  return null;
}
const cleanUsr=a=>a.map(u=>({id:u.id,n:u.n,un:u.un,roles:u.roles,on:u.on?1:0,av:u.av===0?0:1,dp:Array.isArray(u.dp)?u.dp.filter(x=>typeof x==='string').slice(0,10):[]}));

/* ---------- API ---------- */
async function api(req,res,pathname,url){
  if(req.method==='POST'){
    const o=req.headers.origin;if(o){try{if(new URL(o).host!==req.headers.host)return send(req,res,403,{error:'origin'})}catch(e){return send(req,res,403,{error:'origin'})}}
  }
  let body={};if(req.method==='POST'){try{body=await readBody(req)}catch(e){return send(req,res,400,{error:'طلب غير صالح'})}}
  if(pathname==='/api/login'&&req.method==='POST'){
    const ip=clientIp(req),un=String(body.un||'').trim().toLowerCase(),pw=String(body.pw||''),k=ip+'|'+un,now=Date.now();
    const f=fails.get(k)||{n:0,until:0},g=fails.get('ip:'+ip)||{n:0,until:0};
    if(f.until>now||g.until>now)return send(req,res,429,{error:'محاولات كثيرة. انتظر ثم حاول مرة أخرى.'});
    const u=db.state.usr.find(x=>x.un===un&&x.on),c=u&&auth.creds[u.id];
    const h=await scrypt(pw.slice(0,200),c?c.s:'00'.repeat(16));const ok=!!c&&eq(h,c.h);
    if(!ok){f.n++;if(f.n>=5){f.until=now+30000;f.n=0}fails.set(k,f);g.n++;if(g.n>=40){g.until=now+300000;g.n=0}fails.set('ip:'+ip,g);return send(req,res,401,{error:'اسم المستخدم أو كلمة المرور غير صحيحة.'})}
    fails.delete(k);const tok=crypto.randomBytes(32).toString('hex');auth.sessions[sha(tok)]={uid:u.id,exp:now+SESSION_MS};persistAuth();
    return send(req,res,200,{ok:true,uid:u.id},{'Set-Cookie':cookieHdr(tok,req)});
  }
  const ses=sessionOf(req);
  if(pathname==='/api/logout'&&req.method==='POST'){if(ses){delete auth.sessions[ses.k];persistAuth()}return send(req,res,200,{ok:true},{'Set-Cookie':cookieHdr('',req,true)})}
  if(!ses)return send(req,res,401,{error:'سجّل الدخول أولاً'});
  const me=ses.u,st=db.state;
  if(pathname==='/api/me')return send(req,res,200,{uid:me.id});
  if(pathname==='/api/ver')return send(req,res,200,{ver:db.ver});
  if(pathname==='/api/state'){const since=+url.searchParams.get('since')||0;return since===db.ver?send(req,res,200,{same:true,ver:db.ver}):send(req,res,200,{ver:db.ver,state:viewFor(st,me.roles)})}
  if(pathname==='/api/sync'&&req.method==='POST'){
    if(typeof body.base!=='number'||!body.set||typeof body.set!=='object'||Array.isArray(body.set))return send(req,res,400,{error:'طلب غير صالح'});
    if(!Number.isInteger(body.base)||body.base<0||body.base>db.ver)return send(req,res,400,{error:'طلب غير صالح'});
    const keys=Object.keys(body.set);if(keys.length>100)return send(req,res,400,{error:'طلب كبير'});
    for(const k of keys)if(!/^[A-Za-z0-9_]{1,30}$/.test(k)||['__proto__','constructor','prototype','init'].includes(k))return send(req,res,400,{error:'مفتاح غير صالح'});
    const noW=keys.filter(k=>!canWrite(me.roles,k));
    if(noW.length)return send(req,res,403,{error:'غير مصرح لك بهذا الإجراء.'});
    const clash=keys.filter(k=>(db.kv[k]||0)>body.base);
    if(clash.length)return send(req,res,409,{ver:db.ver,error:'conflict',keys:clash});
    if(!clash.length){const le=ledgerCheck(me,st,body.set);if(le)return send(req,res,422,{error:'مرفوض: '+le})}
    if(keys.includes('usr')){
      const err=checkUsr(body.set.usr,me,st.usr);if(err)return send(req,res,err.code,{error:err.msg});
      const keep=new Set(body.set.usr.map(u=>u.id));
      for(const u of st.usr)if(!keep.has(u.id)){delete auth.creds[u.id];killSessions(u.id)}
      body.set.usr=me.roles.includes('admin')?cleanUsr(body.set.usr):st.usr;
    }
    for(const k of keys)st[k]=body.set[k];
    bump(keys);return send(req,res,200,{ver:db.ver});
  }
  if(pathname==='/api/track'&&req.method==='POST'){
    if(!me.roles.some(r=>['admin','supervisor','delivery'].includes(r)))return send(req,res,403,{error:'غير مسموح'});
    const d=(st.del||[]).find(x=>x.id==body.id),p=body.p||{};
    if(!d||![p.t,p.la,p.lo,p.ac].every(Number.isFinite))return send(req,res,400,{error:'بيانات غير صالحة'});
    d.trk=d.trk||[];d.trk.push({t:p.t,la:p.la,lo:p.lo,ac:p.ac});if(d.trk.length>500)d.trk.shift();
    const prev=db.ver;bump(['del']);return send(req,res,200,{ver:db.ver,prev});
  }
  if(pathname.startsWith('/api/admin/')){
    if(!me.roles.includes('admin'))return send(req,res,403,{error:'للمدير العام فقط'});
    if(pathname==='/api/admin/backup'){return send(req,res,200,JSON.stringify({db,auth:{creds:'(not included)'}}),{'Content-Type':'application/json; charset=utf-8','Content-Disposition':'attachment; filename="again-backup-'+new Date().toISOString().slice(0,10)+'.json"'})}
    if(pathname==='/api/admin/user-create'&&req.method==='POST'){
      const n=String(body.n||'').trim(),role=String(body.role||'');
      if(!n||n.length>80||!ROLES.includes(role))return send(req,res,400,{error:'اسم أو صلاحية غير صالحة'});
      const id=Math.max(0,...st.usr.map(x=>x.id),st.seq&&st.seq.z||0)+1,un=newUn(),pw=rndStr(10,PWC);
      st.seq=st.seq||{};st.seq.z=id;st.usr.push({id,n,un,roles:[role],on:1,av:1,dp:[...new Set(DEP0[role]||[])]});
      await setPw(id,pw);bump(['usr','seq']);return send(req,res,200,{id,n,un,pw});
    }
    if(pathname==='/api/admin/user-pw'&&req.method==='POST'){
      const u=st.usr.find(x=>x.id==body.id);if(!u)return send(req,res,404,{error:'مستخدم غير موجود'});
      let pw=body.pw!=null?String(body.pw):'',gen=false;
      if(!pw){pw=rndStr(10,PWC);gen=true}else if(pw.length<8||pw.length>128)return send(req,res,400,{error:'كلمة المرور من 8 إلى 128 حرفاً'});
      await setPw(u.id,pw);return send(req,res,200,gen?{ok:true,pw}:{ok:true});
    }
  }
  return send(req,res,404,{error:'not found'});
}

/* ---------- static + server ---------- */
let idx={t:0,buf:null};
function indexHtml(){
  const f=path.join(PUB,'index.html'),m=fs.statSync(f).mtimeMs;
  if(idx.t!==m){idx={t:m,buf:fs.readFileSync(f,'utf8')}}return idx.buf;
}
const server=http.createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,'http://x'),p=url.pathname;
    if(p.startsWith('/api/'))return await api(req,res,p,url);
    if(p==='/healthz')return send(req,res,200,{ok:true});
    if(p==='/'||p==='/index.html'){if(req.method!=='GET'&&req.method!=='HEAD')return send(req,res,405,{error:'method'});return send(req,res,200,indexHtml())}
    return send(req,res,404,{error:'not found'});
  }catch(e){console.error('request error:',e);try{send(req,res,500,{error:'server error'})}catch(_){}}
});

async function main(){
  await firstRun();
  const t=setInterval(()=>{try{if(db.state&&rot(db.state)){bump(['tsk'])}}catch(e){console.error('rot error:',e.message)}},ROT_MS);t.unref&&t.unref();
  server.on('error',e=>{console.error(e.code==='EADDRINUSE'?'Port '+PORT+' is already in use. Close the other program or set PORT=3001.':e.message);process.exit(1)});
  server.listen(PORT,HOST,()=>{
    console.log('Again ERP server is running.');
    console.log('  On this computer : http://localhost:'+PORT);
    const ips=Object.values(os.networkInterfaces()).flat().filter(i=>i&&i.family==='IPv4'&&!i.internal).map(i=>i.address);
    ips.forEach(a=>console.log('  On your network  : http://'+a+':'+PORT));
    console.log('  Data folder      : '+DATA);console.log('  Press Ctrl+C to stop.\n');
  });
  const stop=()=>{persistNow();persistAuthNow();writeBackup();process.exit(0)};
  process.on('SIGINT',stop);process.on('SIGTERM',stop);
}
if(require.main===module){
  process.on('uncaughtException',e=>{console.error('FATAL:',e);try{persistNow();persistAuthNow()}catch(_){}process.exit(1)});
  process.on('unhandledRejection',e=>console.error('unhandled:',e));
  main();
}
module.exports={rot,checkUsr,main,server};
