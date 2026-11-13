import { neon } from '@neondatabase/serverless';
const encoder=new TextEncoder();
const json=(x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json;charset=utf-8','cache-control':'no-store'}});
async function sha(x){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(x)))).map(b=>b.toString(16).padStart(2,'0')).join('')}
function b64(bytes){return btoa(String.fromCharCode(...bytes))}
function unb64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
async function hashPassword(pass,salt=crypto.getRandomValues(new Uint8Array(16))){let key=await crypto.subtle.importKey('raw',encoder.encode(pass),'PBKDF2',false,['deriveBits']);let bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:210000,hash:'SHA-256'},key,256);return b64(salt)+':'+b64(new Uint8Array(bits))}
async function verify(pass,stored){if(!stored)return false;let [s]=stored.split(':');return await hashPassword(pass,unb64(s))===stored}
async function auth(req,db){let t=(req.headers.get('authorization')||'').replace(/^Bearer /,'');if(!t)return null;return await db.prepare('SELECT s.id,s.full_name,s.username,s.role,s.can_manage FROM sessions x JOIN staff s ON s.id=x.staff_id WHERE x.token_hash=? AND x.expires_at>datetime(\'now\') AND s.active=TRUE').bind(await sha(t)).first()}
function fail(msg,status=400){return json({error:msg},status)}
const types=['MANUAL_DEPOSIT','ACCEPT_DEPOSIT','WITHDRAW','GANTI_REKENING','PERMAINAN'];
export async function onRequest({request,env}){try{
if(!env.DATABASE_URL)return fail('DATABASE_URL Neon belum diatur pada Cloudflare Pages',503);
const sql=neon(env.DATABASE_URL);
// Health check: confirms that the Pages Function can reach Neon without exposing secrets.
const healthPath=new URL(request.url).pathname.replace(/\/$/,'');
if(healthPath==='/api/health' && request.method==='GET'){
  try { await sql('SELECT 1 AS ok'); return json({ok:true,database:'connected'}); }
  catch(error){ console.error('Neon health check failed',{code:error?.code,message:error?.message}); return json({ok:false,database:'unavailable'},503); }
}
const db={prepare(query){let params=[];return {bind(...values){params=values;return this},async first(){const rows=await sql(convertSql(query),params);return rows[0]||null},async all(){return {results:await sql(convertSql(query),params)}},async run(){const q=convertSql(query);const rows=await sql(q,params);return {meta:{changes:rows.length||0,last_row_id:rows[0]?.id||null}}}}}};
function convertSql(q){let n=0;return q.replace(/\?/g,()=>'$'+(++n)).replace(/datetime\('now'\)/g,'NOW()').replace(/ COLLATE NOCASE/g,'');}
const url=new URL(request.url),route=url.pathname.replace(/^\/api\/?/,'').replace(/\/$/,'');const method=request.method;
let body={};if(['POST','PATCH','PUT'].includes(method)){try{body=await request.json()}catch{return fail('JSON tidak valid')}}
if(route==='login'&&method==='POST'){
const user=await db.prepare('SELECT * FROM staff WHERE lower(username)=lower(?) AND active=TRUE').bind(String(body.username||'').trim()).first();if(!user||!(await verify(String(body.password||''),user.password_hash)))return fail('Username atau password salah',401);
const token=b64(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+','-').replaceAll('/','_');await db.prepare("INSERT INTO sessions(token_hash,staff_id,expires_at) VALUES(?,?,NOW() + INTERVAL '7 days') RETURNING token_hash").bind(await sha(token),user.id).run();return json({token,staff:{id:user.id,full_name:user.full_name,role:user.role,can_manage:user.can_manage}})}
if(route==='register'&&method==='POST'){
const name=String(body.full_name||'').trim(),username=String(body.username||'').trim(),pass=String(body.password||'');if(!name||!/^\w{3,30}$/.test(username)||pass.length<8)return fail('Isi nama, username 3-30 karakter, dan password minimal 8 karakter');
const wl=await db.prepare('SELECT id,password_hash,active FROM staff WHERE lower(full_name)=lower(?)').bind(name).first();if(!wl||!wl.active||wl.password_hash)return fail('Nama belum di-whitelist atau sudah digunakan',403);
try{await db.prepare('UPDATE staff SET username=?,password_hash=? WHERE id=? AND password_hash IS NULL RETURNING id').bind(username,await hashPassword(pass),wl.id).run();return json({ok:true})}catch{return fail('Username sudah dipakai')}}
const staff=await auth(request,db);if(!staff)return fail('Silakan login',401);
if(route==='me'&&method==='GET')return json({staff});
if(route==='logout'&&method==='POST'){const t=(request.headers.get('authorization')||'').slice(7);await db.prepare('DELETE FROM sessions WHERE token_hash=? RETURNING token_hash').bind(await sha(t)).run();return json({ok:true})}
if(route==='staff'&&method==='GET'){if(!staff.can_manage)return fail('Tidak diizinkan',403);return json({items:(await db.prepare('SELECT id,full_name,username,role,active,can_manage,created_at FROM staff ORDER BY id DESC').all()).results})}
if(route==='staff'&&method==='POST'){if(!staff.can_manage)return fail('Tidak diizinkan',403);let name=String(body.full_name||'').trim(),role=String(body.role||'');if(!name||!['CS LINE','KAPTEN KASIR','CS LC','KASIR'].includes(role))return fail('Nama/role tidak valid');try{await db.prepare('INSERT INTO staff(full_name,role,can_manage) VALUES(?,?,?) RETURNING id').bind(name,role,['CS LINE','KAPTEN KASIR'].includes(role)).run();return json({ok:true})}catch{return fail('Nama sudah ada')}}
if(route==='events'&&method==='GET'){
const after=Math.max(0,Number.parseInt(url.searchParams.get('after')||'0',10)||0);
// Cursor terbaru untuk inisialisasi tanpa membanjiri notifikasi lama.
const latest=await db.prepare('SELECT COALESCE(MAX(id),0) AS id FROM audit').first();
const rows=await db.prepare(`SELECT a.id,a.action,a.report_id,a.created_at,a.staff_id,s.full_name AS actor_name,r.type,r.subtype,r.user_id FROM audit a JOIN staff s ON s.id=a.staff_id LEFT JOIN reports r ON r.id=a.report_id WHERE a.id>? ORDER BY a.id ASC LIMIT 100`).bind(after).all();
return json({latest_id:latest.id,items:rows.results});
}
if(route==='reports'&&method==='GET'){let result=await db.prepare('SELECT r.*,a.full_name AS creator_name,b.full_name AS done_name FROM reports r JOIN staff a ON a.id=r.created_by LEFT JOIN staff b ON b.id=r.done_by ORDER BY r.id DESC LIMIT 500').all();return json({items:result.results})}
if(route==='reports'&&method==='POST'){
let type=String(body.type||''),subtype=String(body.subtype||''),user=String(body.user_id||'').trim(),proof=String(body.proof||'').trim(),nominal=body.nominal===''||body.nominal==null?null:Number(String(body.nominal).replace(/[^\d]/g,'')),details=body.details||{};
if(!types.includes(type))return fail('Jenis laporan tidak valid');if(!user&&type!=='PERMAINAN')return fail('User ID wajib diisi');if(type==='PERMAINAN'&&!['PL','SITUS'].includes(subtype))return fail('Pilih jenis permainan');if(type==='PERMAINAN'&&subtype==='PL'&&!user)return fail('User ID wajib');if(type==='PERMAINAN'&&subtype==='SITUS'&&!String(details.provider||'').trim())return fail('Provider wajib');if(type==='GANTI_REKENING'&&(!details.old_account||!details.new_account))return fail('Rekening lama dan baru wajib');if(type==='WITHDRAW'&&(!nominal||!details.withdraw_date||!details.order_id||!proof))return fail('Lengkapi data withdraw');if(['MANUAL_DEPOSIT','ACCEPT_DEPOSIT'].includes(type)&&(!nominal||!proof))return fail('Nominal dan bukti wajib');if(type==='PERMAINAN'&&!String(details.description||'').trim())return fail('Keterangan kendala wajib');
let r=await db.prepare('INSERT INTO reports(type,subtype,user_id,nominal,proof,details,created_by) VALUES(?,?,?,?,?,?::jsonb,?) RETURNING id').bind(type,subtype||null,user||null,nominal,proof,JSON.stringify(details),staff.id).run();await db.prepare('INSERT INTO audit(staff_id,action,report_id) VALUES(?,?,?) RETURNING id').bind(staff.id,'CREATE',r.meta.last_row_id).run();return json({ok:true,id:r.meta.last_row_id})}
let m=route.match(/^reports\/(\d+)\/done$/);if(m&&method==='POST'){let id=Number(m[1]);let report=await db.prepare('SELECT * FROM reports WHERE id=?').bind(id).first();if(!report)return fail('Laporan tidak ditemukan',404);if(report.created_by===staff.id)return fail('Tidak boleh DONE laporan sendiri',403);if(report.status==='DONE')return fail('Laporan sudah DONE');let note=String(body.note||'').trim();if(['WITHDRAW','PERMAINAN'].includes(report.type)&&!note)return fail('Keterangan penyelesaian wajib');let result=await db.prepare("UPDATE reports SET status='DONE',done_by=?,done_note=?,done_at=CURRENT_TIMESTAMP WHERE id=? AND status='WAITING' RETURNING id").bind(staff.id,note,id).run();if(!result.meta.changes)return fail('Status sudah berubah',409);await db.prepare('INSERT INTO audit(staff_id,action,report_id) VALUES(?,?,?)').bind(staff.id,'DONE',id).run();return json({ok:true})}
return fail('Endpoint tidak ditemukan',404)
}catch(e){console.error('WDBOS API failure', {route:new URL(request.url).pathname,method:request.method,error:e?.message,code:e?.code,stack:e?.stack});return fail('Kesalahan server',500)}}
