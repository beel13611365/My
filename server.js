const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const http = require('http');
const httpProxy = require('http-proxy');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const proxy = httpProxy.createProxyServer({ ws: true, xfwd: true, changeOrigin: true });
const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONFIG_DIR = process.env.CONFIG_DIR || path.join(DATA_DIR, 'core');
fs.mkdirSync(DATA_DIR, {recursive:true}); fs.mkdirSync(CONFIG_DIR, {recursive:true});
const DB = path.join(DATA_DIR, 'panel.json');
// Bootstrap credentials automatically on first boot and persist them in the mounted data volume.
const BOOTSTRAP_FILE = path.join(DATA_DIR, 'bootstrap-credentials.json');
let bootstrap = {};
try { bootstrap = JSON.parse(fs.readFileSync(BOOTSTRAP_FILE, 'utf8')); } catch {}
const generatedFirstBoot = !bootstrap.sessionSecret || !bootstrap.adminPassword;
bootstrap.adminUser = process.env.ADMIN_USER || bootstrap.adminUser || 'admin';
bootstrap.adminPassword = process.env.ADMIN_PASSWORD || bootstrap.adminPassword || 'admin1323';
bootstrap.sessionSecret = process.env.SESSION_SECRET || bootstrap.sessionSecret || crypto.randomBytes(48).toString('base64url');
fs.writeFileSync(BOOTSTRAP_FILE, JSON.stringify(bootstrap, null, 2), {mode: 0o600});
try { fs.chmodSync(BOOTSTRAP_FILE, 0o600); } catch {}
const SECRET = bootstrap.sessionSecret, ADMIN_USER = bootstrap.adminUser, ADMIN_PASSWORD = bootstrap.adminPassword;
if (generatedFirstBoot) {
  console.log('================ NEXORA FIRST-BOOT LOGIN ================');
  console.log(`Admin username: ${ADMIN_USER}`);
  console.log(`Admin password: ${ADMIN_PASSWORD}`);
  console.log(`Credentials saved to: ${BOOTSTRAP_FILE}`);
  console.log('IMPORTANT: Change the default password after first login. Credentials persist while /data persists.');
  console.log('=========================================================');
}
const DEFAULTS = {settings:{domain:'',port:443,tls:true,path:'/connect',trojanPath:'/trojan',core:'xray'},users:[]};
function load(){try{return {...DEFAULTS,...JSON.parse(fs.readFileSync(DB,'utf8'))}}catch{return structuredClone(DEFAULTS)}}
let state=load(), coreProc=null, coreStatus='starting', coreError='', lastConfigSignature='';
function save(){const tmp=DB+'.tmp';fs.writeFileSync(tmp,JSON.stringify(state,null,2),{mode:0o600});fs.renameSync(tmp,DB)}
app.disable('x-powered-by'); app.set('trust proxy', 1);
app.use(express.json({limit:'32kb'})); app.use(express.urlencoded({extended:false,limit:'32kb'}));
app.use(session({name:'nexora.sid',secret:SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE!=='false',maxAge:8*60*60*1000}}));
app.use(express.static(path.join(__dirname,'public')));
function auth(req,res,next){if(req.session&&req.session.ok)return next();return res.status(401).json({error:'لطفاً ابتدا وارد پنل شوید.'})}
function clean(s,max=120){return String(s||'').trim().slice(0,max)}
function validDomain(d){return /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(d)}
function active(u){return u.enabled&&(!u.expiresAt||Date.parse(u.expiresAt)>Date.now())}
function xrayConfig(){const us=state.users.filter(active),s=state.settings;return {log:{loglevel:'warning'},inbounds:[{tag:'vless-ws',listen:'127.0.0.1',port:10000,protocol:'vless',settings:{clients:us.map(u=>({id:u.uuid,email:u.id})),decryption:'none'},streamSettings:{network:'ws',wsSettings:{path:s.path}}},{tag:'trojan-ws',listen:'127.0.0.1',port:10001,protocol:'trojan',settings:{clients:us.map(u=>({password:u.trojanPassword,email:u.id}))},streamSettings:{network:'ws',wsSettings:{path:s.trojanPath}}}],outbounds:[{protocol:'freedom',tag:'direct'}]}}
function singboxConfig(){const us=state.users.filter(active),s=state.settings;return {log:{level:'warn'},inbounds:[{type:'vless',tag:'vless-ws',listen:'127.0.0.1',listen_port:10000,users:us.map(u=>({name:u.id,uuid:u.uuid})),transport:{type:'ws',path:s.path}},{type:'trojan',tag:'trojan-ws',listen:'127.0.0.1',listen_port:10001,users:us.map(u=>({name:u.id,password:u.trojanPassword})),transport:{type:'ws',path:s.trojanPath}}],outbounds:[{type:'direct',tag:'direct'}]}}
function stopCore(){if(coreProc){const p=coreProc;coreProc=null;try{p.kill('SIGKILL')}catch{}}}
function writeCoreConfig(){const selected=state.settings.core==='sing-box'?'sing-box':'xray';const cfg=selected==='xray'?xrayConfig():singboxConfig();const file=path.join(CONFIG_DIR,selected==='xray'?'xray.json':'sing-box.json');fs.writeFileSync(file,JSON.stringify(cfg,null,2),{mode:0o600});return {selected,file,signature:crypto.createHash('sha256').update(JSON.stringify(cfg)).digest('hex')}}
function restartCore(force=false){let info;try{info=writeCoreConfig()}catch(e){coreStatus='error';coreError=e.message;return}
 if(!force&&info.signature===lastConfigSignature&&coreProc&&!coreProc.killed)return;
 lastConfigSignature=info.signature;stopCore();coreError='';coreStatus='starting';
 const bin=info.selected==='xray'?(process.env.XRAY_BIN||'/usr/local/bin/xray'):(process.env.SINGBOX_BIN||'/usr/local/bin/sing-box');
 const args=info.selected==='xray'?['run','-config',info.file]:['run','-c',info.file];
 coreProc=spawn(bin,args,{stdio:['ignore','pipe','pipe']});const child=coreProc;
 child.stdout.on('data',d=>console.log(`[${info.selected}] ${String(d).trim()}`));child.stderr.on('data',d=>{const m=String(d).trim();if(m){console.error(`[${info.selected}] ${m}`);coreError=m.slice(-1000)}});
 child.on('spawn',()=>{if(coreProc===child)coreStatus='running'});child.on('error',e=>{if(coreProc===child){coreStatus='error';coreError=`اجرای ${info.selected} ناموفق بود: ${e.message}`;console.error(coreError)}});child.on('exit',(code,signal)=>{if(coreProc===child){coreStatus='stopped';coreError=code?`هسته با کد ${code} متوقف شد`:coreError}});
}
app.get('/api/session',(req,res)=>res.json({loggedIn:!!req.session.ok}));
app.post('/api/login',(req,res)=>{const u=clean(req.body.username,100),p=String(req.body.password||'');const a=crypto.timingSafeEqual(Buffer.from(u.padEnd(256,'\0').slice(0,256)),Buffer.from(ADMIN_USER.padEnd(256,'\0').slice(0,256)));const b=crypto.timingSafeEqual(Buffer.from(p.padEnd(512,'\0').slice(0,512)),Buffer.from(ADMIN_PASSWORD.padEnd(512,'\0').slice(0,512)));if(!a||!b)return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است.'});req.session.regenerate(err=>{if(err)return res.status(500).json({error:'خطای نشست'});req.session.ok=true;res.json({ok:true})})});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/state',auth,(req,res)=>res.json({settings:state.settings,core:{status:coreStatus,error:coreError,selected:state.settings.core},users:state.users.map(u=>({...u}))}));
app.post('/api/settings',auth,(req,res)=>{const domain=clean(req.body.domain,253).toLowerCase(),port=Number(req.body.port||443),route=clean(req.body.path||'/connect',100),tpath=clean(req.body.trojanPath||'/trojan',100),core=req.body.core==='sing-box'?'sing-box':'xray';if(!validDomain(domain))return res.status(400).json({error:'دامنه معتبر وارد کنید؛ برای نمونه service.lucity.app'});if(!Number.isInteger(port)||port!==443)return res.status(400).json({error:'در استقرار پشت دامنه HTTPS در Lucity، پورت عمومی باید 443 باشد.'});if(!route.startsWith('/')||route.includes(' ')||route.length<2||!tpath.startsWith('/')||tpath.includes(' ')||tpath===route)return res.status(400).json({error:'مسیرهای WebSocket باید معتبر و متفاوت باشند.'});state.settings={domain,port,tls:true,path:route,trojanPath:tpath,core};save();restartCore(true);res.json({ok:true})});
app.post('/api/users',auth,(req,res)=>{const name=clean(req.body.name,64),days=Number(req.body.days||0);if(!name)return res.status(400).json({error:'نام کاربر الزامی است.'});if(!Number.isInteger(days)||days<0||days>3650)return res.status(400).json({error:'اعتبار نامعتبر است.'});const user={id:uuidv4(),name,uuid:uuidv4(),trojanPassword:crypto.randomBytes(24).toString('base64url'),createdAt:new Date().toISOString(),expiresAt:days?new Date(Date.now()+days*86400000).toISOString():null,enabled:true};state.users.unshift(user);save();restartCore(true);res.json({ok:true,user})});
app.patch('/api/users/:id',auth,(req,res)=>{const u=state.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'کاربر پیدا نشد.'});if(typeof req.body.enabled==='boolean')u.enabled=req.body.enabled;save();restartCore(true);res.json({ok:true})});
app.delete('/api/users/:id',auth,(req,res)=>{const n=state.users.length;state.users=state.users.filter(u=>u.id!==req.params.id);if(n===state.users.length)return res.status(404).json({error:'کاربر پیدا نشد.'});save();restartCore(true);res.json({ok:true})});
function linksFor(u){const s=state.settings,host=s.domain,enc=encodeURIComponent;const common=`security=tls&type=ws&host=${enc(host)}&sni=${enc(host)}`;const vless=`vless://${u.uuid}@${host}:443?encryption=none&${common}&path=${enc(s.path)}#${enc(u.name+'-VLESS')}`;const trojan=`trojan://${enc(u.trojanPassword)}@${host}:443?${common}&path=${enc(s.trojanPath)}#${enc(u.name+'-Trojan')}`;return {vless,trojan}}
app.get('/api/link/:id',auth,(req,res)=>{const u=state.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'کاربر پیدا نشد.'});if(!state.settings.domain)return res.status(400).json({error:'ابتدا دامنه عمومی Lucity را در تنظیمات وارد کنید.'});res.json({links:linksFor(u)})});
app.get('/api/export/:id',auth,(req,res)=>{const u=state.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'کاربر پیدا نشد.'});const s=state.settings;if(!s.domain)return res.status(400).json({error:'ابتدا دامنه را تنظیم کنید.'});const cfg={log:{level:'info'},inbounds:[{type:'mixed',tag:'mixed-in',listen:'127.0.0.1',listen_port:2080}],outbounds:[{type:'vless',tag:'vless',server:s.domain,server_port:443,uuid:u.uuid,transport:{type:'ws',path:s.path,headers:{Host:s.domain}},tls:{enabled:true,server_name:s.domain}},{type:'trojan',tag:'trojan',server:s.domain,server_port:443,password:u.trojanPassword,transport:{type:'ws',path:s.trojanPath,headers:{Host:s.domain}},tls:{enabled:true,server_name:s.domain}},{type:'direct',tag:'direct'}],route:{final:'direct'}};res.setHeader('Content-Disposition','attachment; filename="sing-box-client-config.json"');res.json(cfg)});
app.get('/api/health',(_req,res)=>res.json({ok:true,core:coreStatus,selected:state.settings.core,error:coreError||undefined}));
app.get('/health',(_req,res)=>res.status(coreStatus==='running'?200:503).json({ok:coreStatus==='running',core:coreStatus,selected:state.settings.core,error:coreError||undefined}));
server.on('upgrade',(req,socket,head)=>{const p=(req.url||'').split('?')[0];let target=null;if(p===state.settings.path)target='http://127.0.0.1:10000';else if(p===state.settings.trojanPath)target='http://127.0.0.1:10001';if(!target){socket.destroy();return}proxy.ws(req,socket,head,{target,timeout:30000});});
proxy.on('error',(err,req,socket)=>{if(socket&&!socket.destroyed)socket.destroy();console.error('WebSocket proxy:',err.message)});
server.listen(PORT,'0.0.0.0',()=>{console.log(`Nexora listening on ${PORT}`);restartCore(true)});
setInterval(()=>{const sig=crypto.createHash('sha256').update(JSON.stringify((state.users||[]).map(u=>[u.id,active(u)]))).digest('hex');if(sig!==expirySignature){expirySignature=sig;restartCore(true)}},30000).unref();
let expirySignature='';
process.on('SIGTERM',()=>{stopCore();server.close(()=>process.exit(0))});process.on('SIGINT',()=>{stopCore();server.close(()=>process.exit(0))});
