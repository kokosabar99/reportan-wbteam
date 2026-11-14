import { neon } from '@neondatabase/serverless';
const encoder=new TextEncoder();
const json=(x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json;charset=utf-8','cache-control':'no-store'}});
async function sha(x){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(x)))).map(b=>b.toString(16).padStart(2,'0')).join('')}
function b64(bytes){return btoa(String.fromCharCode(...bytes))}
function unb64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
async function hashPassword(pass,salt=crypto.getRandomValues(new Uint8Array(16))){
  const saltBytes=Uint8Array.from(salt);
  const key=await crypto.subtle.importKey('raw',encoder.encode(pass),{name:'PBKDF2'},false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:saltBytes,iterations:100000,hash:'SHA-256'},key,256);
  return b64(saltBytes)+':'+b64(new Uint8Array(bits));
}
async function verify(pass,stored){
  if(typeof stored!=='string'||!pass)return false;
  const parts=stored.split(':');
  if(parts.length!==2)return false;
  try{
    const salt=unb64(parts[0]),expected=unb64(parts[1]);
    if(salt.length!==16||expected.length!==32)return false;
    const actual=await hashPassword(pass,salt);
    const a=encoder.encode(actual),b=encoder.encode(stored);
    if(a.length!==b.length)return false;
    let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];
    return diff===0;
  }catch(error){console.error('Password verification failed',{name:error?.name,message:error?.message});return false}
}
async function auth(req,db){let t=(req.headers.get('authorization')||'').replace(/^Bearer /,'');if(!t)return null;return await db.prepare('SELECT s.id,s.full_name,s.username,s.role,s.can_manage FROM sessions x JOIN staff s ON s.id=x.staff_id WHERE x.token_hash=? AND x.expires_at>datetime(\'now\') AND s.active=TRUE').bind(await sha(t)).first()}
function fail(msg,status=400){return json({error:msg},status)}
const types=['MANUAL_DEPOSIT','ACCEPT_DEPOSIT','WITHDRAW','GANTI_REKENING','PERMAINAN'];
export async function onRequest({request,env}){try{
if(!env.DATABASE_URL)return fail('DATABASE_URL Neon belum diatur pada Cloudflare Pages',503);
const sql=neon(env.DATABASE_URL);
// Health check: confirms that the Pages Function can reach the configured production Neon database without exposing secrets.
const healthPath=new URL(request.url).pathname.replace(/\/$/,'');
if(healthPath==='/api/health' && request.method==='GET'){
  try { await sql`SELECT 1 AS ok`; return json({ok:true,database:'connected'}); }
  catch(error){ console.error('Neon health check failed',{code:error?.code,message:error?.message}); return json({ok:false,database:'unavailable'},503); }
}
if(healthPath==='/api/crypto-check' && request.method==='GET'){
  const checks={};
  try{const k=await crypto.subtle.importKey('raw',encoder.encode('test'),{name:'PBKDF2'},false,['deriveBits']);checks.importKey='ok';
    try{await crypto.subtle.deriveBits({name:'PBKDF2',salt:new Uint8Array(16),iterations:1,hash:'SHA-256'},k,256);checks.deriveBits='ok'}
    catch(e){checks.deriveBits=e?.name||'error'}
  }catch(e){checks.importKey=e?.name||'error'}
  return json({checks});
}
const db={prepare(query){let params=[];return {bind(...values){params=values;return this},async first(){const rows=await sql.query(convertSql(query),params);return rows[0]||null},async all(){return {results:await sql.query(convertSql(query),params)}},async run(){const q=convertSql(query);const rows=await sql.query(q,params);return {meta:{changes:rows.length||0,last_row_id:rows[0]?.id||null}}}}}};
function convertSql(q){let n=0;return q.replace(/\?/g,()=>'$'+(++n)).replace(/datetime\('now'\)/g,'NOW()').replace(/ COLLATE NOCASE/g,'');}
const url=new URL(request.url),route=url.pathname.replace(/^\/api\/?/,'').replace(/\/$/,'');const method=request.method;
let body={};if(['POST','PATCH','PUT'].includes(method)){try{body=await request.json()}catch{return fail('JSON tidak valid')}}
if(route==='login'&&method==='POST'){
const loginName=String(body.username||'').trim(),loginPassword=String(body.password||'');
const user=await db.prepare('SELECT id,full_name,username,role,can_manage,password_hash FROM staff WHERE lower(username)=lower(?) AND active=TRUE').bind(loginName).first();
if(!user){console.warn('Login rejected',{reason:'user_not_found_or_inactive'});return fail('Username atau password salah',401)}
const passwordOk=await verify(loginPassword,user.password_hash);
if(!passwordOk){console.warn('Login rejected',{reason:'password_mismatch_or_legacy_hash',hashFormat:typeof user.password_hash==='string'&&user.password_hash.includes(':')?'salt:hash':'other',hashLength:user.password_hash?.length||0});return fail('Username atau password salah',401)}
const token=b64(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+','-').replaceAll('/','_');await db.prepare("INSERT INTO sessions(token_hash,staff_id,expires_at) VALUES(?,?,NOW() + INTERVAL '7 days') RETURNING token_hash").bind(await sha(token),user.id).run();return json({token,staff:{id:user.id,full_name:user.full_name,role:user.role,can_manage:user.can_manage}})}
if(route==='register'&&method==='POST'){
const name=String(body.full_name||'').trim(),username=String(body.username||'').trim(),pass=String(body.password||'');if(!name||!/^\w{3,30}$/.test(username)||pass.length<8)return fail('Isi nama, username 3-30 karakter, dan password minimal 8 karakter');
const wl=await db.prepare('SELECT id,password_hash,active FROM staff WHERE lower(full_name)=lower(?)').bind(name).first();if(!wl||!wl.active||wl.password_hash)return fail('Nama belum di-whitelist atau sudah digunakan',403);
try{const result=await db.prepare('UPDATE staff SET username=?,password_hash=? WHERE id=? AND password_hash IS NULL RETURNING id').bind(username,await hashPassword(pass),wl.id).run();if(!result.meta.changes)return fail('Staff sudah terdaftar',409);return json({ok:true})}catch{return fail('Username sudah dipakai')}}
const staff=await auth(request,db);if(!staff)return fail('Silakan login',401);
if(route==='me'&&method==='GET')return json({staff});
if(route==='logout'&&method==='POST'){const t=(request.headers.get('authorization')||'').slice(7);await db.prepare('DELETE FROM sessions WHERE token_hash=? RETURNING token_hash').bind(await sha(t)).run();return json({ok:true})}
if(route==='staff'&&method==='GET'){if(!staff.can_manage)return fail('Tidak diizinkan',403);return json({items:(await db.prepare('SELECT id,full_name,username,role,active,can_manage,created_at FROM staff ORDER BY id DESC').all()).results})}
if(route==='staff'&&method==='POST'){if(!staff.can_manage)return fail('Tidak diizinkan',403);let name=String(body.full_name||'').trim(),role=String(body.role||'');if(!name||!['CS LINE','KAPTEN KASIR','CS LC','KASIR'].includes(role))return fail('Nama/role tidak valid');try{await db.prepare('INSERT INTO staff(full_name,role,can_manage) VALUES(?,?,?) RETURNING id').bind(name,role,['CS LINE','KAPTEN KASIR'].includes(role)).run();return json({ok:true})}catch{return fail('Nama sudah ada')}}
if(route==='password'&&method==='POST'){
 const current=String(body.current_password||''),next=String(body.new_password||'');
 if(next.length<8||next.length>128)return fail('Password baru harus 8-128 karakter');
 const row=await db.prepare('SELECT password_hash FROM staff WHERE id=? AND active=TRUE').bind(staff.id).first();
 if(!row||!(await verify(current,row.password_hash)))return fail('Password lama salah',403);
 await db.prepare('UPDATE staff SET password_hash=? WHERE id=? RETURNING id').bind(await hashPassword(next),staff.id).run();
 await db.prepare('DELETE FROM sessions WHERE staff_id=? AND token_hash<>? RETURNING token_hash').bind(staff.id,await sha((request.headers.get('authorization')||'').replace(/^Bearer /,''))).run();
 return json({ok:true});
}
if(route==='reports/purge'&&method==='POST'){
 if(!['KAPTEN KASIR','CS LINE'].includes(staff.role))return fail('Hanya Kapten Kasir dan CS Line',403);
 const from=String(body.from||''),to=String(body.to||''),type=String(body.type||'');
 if(!/^\d{4}-\d{2}-\d{2}$/.test(from)||!/^\d{4}-\d{2}-\d{2}$/.test(to)||from>to)return fail('Rentang tanggal tidak valid');
 if(type&&!types.includes(type))return fail('Kategori tidak valid');
 if(body.confirm!=='HAPUS PERMANEN')return fail('Konfirmasi penghapusan tidak sesuai');
 const filterType=type?' AND type=$3':'';
 const args=type?[from,to,type]:[from,to];
 // Audit references must be cleared before deleting their reports.
 await sql.query(`DELETE FROM audit WHERE report_id IN (SELECT id FROM reports WHERE created_at >= $1::date AND created_at < ($2::date + INTERVAL '1 day')${filterType})`,args);
 const deleted=await sql.query(`DELETE FROM reports WHERE created_at >= $1::date AND created_at < ($2::date + INTERVAL '1 day')${filterType} RETURNING id`,args);
 await db.prepare('INSERT INTO audit(staff_id,action,report_id) VALUES(?,?,NULL) RETURNING id').bind(staff.id,'PURGE '+from+'..'+to+(type?' '+type:'')).run();
 return json({ok:true,deleted:deleted.length});
}
if(route==='events'&&method==='GET'){
const after=Math.max(0,Number.parseInt(url.searchParams.get('after')||'0',10)||0);
// Cursor terbaru untuk inisialisasi tanpa membanjiri notifikasi lama.
const latest=await db.prepare('SELECT COALESCE(MAX(id),0) AS id FROM audit').first();
const rows=await db.prepare(`SELECT a.id,a.action,a.report_id,a.created_at,a.staff_id,s.full_name AS actor_name,r.type,r.subtype,r.user_id FROM audit a JOIN staff s ON s.id=a.staff_id LEFT JOIN reports r ON r.id=a.report_id WHERE a.id>? ORDER BY a.id ASC LIMIT 100`).bind(after).all();
return json({latest_id:latest.id,items:rows.results});
}
const reportMatch=route.match(/^reports\\/(\\d+)$/);
if(reportMatch&&(method==='PATCH'||method==='DELETE')){
 const id=Number(reportMatch[1]);const found=await sql.query('SELECT id,created_by,type,details FROM reports WHERE id=$1',[id]);if(!found.length)return fail('Laporan tidak ditemukan',404);
 if(Number(found[0].created_by)!==Number(staff.id)&&!['KAPTEN KASIR','CS LINE'].includes(staff.role))return fail('Tidak diizinkan mengubah laporan staff lain',403);
 if(method==='DELETE'){await sql.query('DELETE FROM audit WHERE report_id=$1',[id]);await sql.query('DELETE FROM reports WHERE id=$1',[id]);return json({ok:true})}
 const user=String(body.user_id||'').trim(),description=String(body.description||'').trim();if(!user&&found[0].type!=='PERMAINAN')return fail('User ID wajib');
 const details=typeof found[0].details==='object'&&found[0].details?found[0].details:{};
 details.description=description;
 await sql.query('UPDATE reports SET user_id=$1,details=$2::jsonb WHERE id=$3',[user||null,JSON.stringify(details),id]);
 return json({ok:true});
}
if(route==='reports'&&method==='GET'){
 const from=url.searchParams.get('from'),to=url.searchParams.get('to'),type=url.searchParams.get('type');
 if((from&&!/^\d{4}-\d{2}-\d{2}$/.test(from))||(to&&!/^\d{4}-\d{2}-\d{2}$/.test(to))||(type&&!types.includes(type)))return fail('Filter tidak valid');
 const conditions=[],params=[];
 if(from){params.push(from);conditions.push('r.created_at >= $'+params.length+'::date')}
 if(to){params.push(to);conditions.push("r.created_at < ($"+params.length+"::date + INTERVAL '1 day')")}
 if(type){params.push(type);conditions.push('r.type=$'+params.length)}
 const query='SELECT r.*,a.full_name AS creator_name,b.full_name AS done_name FROM reports r JOIN staff a ON a.id=r.created_by LEFT JOIN staff b ON b.id=r.done_by'+(conditions.length?' WHERE '+conditions.join(' AND '):'')+" ORDER BY CASE WHEN r.status='WAITING' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 10000";
 return json({items:await sql.query(query,params)});
}
if(route==='reports'&&method==='POST'){
let type=String(body.type||''),subtype=String(body.subtype||''),user=String(body.user_id||'').trim(),proof=String(body.proof||'').trim(),nominal=body.nominal===''||body.nominal==null?null:Number(String(body.nominal).replace(/[^\d]/g,'')),details=body.details||{};
if(!types.includes(type))return fail('Jenis laporan tidak valid');if(!user&&type!=='PERMAINAN')return fail('User ID wajib diisi');if(type==='PERMAINAN'&&!['PL','SITUS'].includes(subtype))return fail('Pilih jenis permainan');if(type==='PERMAINAN'&&subtype==='PL'&&!user)return fail('User ID wajib');if(type==='PERMAINAN'&&subtype==='SITUS'&&!String(details.provider||'').trim())return fail('Provider wajib');if(type==='GANTI_REKENING'&&(!details.old_account||!details.new_account))return fail('Rekening lama dan baru wajib');if(type==='WITHDRAW'&&(!nominal||!details.withdraw_date||!details.order_id||!proof))return fail('Lengkapi data withdraw');if(['MANUAL_DEPOSIT','ACCEPT_DEPOSIT'].includes(type)&&(!nominal||!proof))return fail('Nominal dan bukti wajib');if(type==='PERMAINAN'&&!String(details.description||'').trim())return fail('Keterangan kendala wajib');
let r=await db.prepare('INSERT INTO reports(type,subtype,user_id,nominal,proof,details,created_by) VALUES(?,?,?,?,?,?::jsonb,?) RETURNING id').bind(type,subtype||null,user||null,nominal,proof,JSON.stringify(details),staff.id).run();await db.prepare('INSERT INTO audit(staff_id,action,report_id) VALUES(?,?,?) RETURNING id').bind(staff.id,'CREATE',r.meta.last_row_id).run();return json({ok:true,id:r.meta.last_row_id})}
let m=route.match(/^reports\/(\d+)\/done$/);if(m&&method==='POST'){let id=Number(m[1]);let report=await db.prepare('SELECT * FROM reports WHERE id=?').bind(id).first();if(!report)return fail('Laporan tidak ditemukan',404);if(report.created_by===staff.id)return fail('Tidak boleh DONE laporan sendiri',403);if(report.status==='DONE')return fail('Laporan sudah DONE');let note=String(body.note||'').trim();if(['WITHDRAW','PERMAINAN'].includes(report.type)&&!note)return fail('Keterangan penyelesaian wajib');let result=await db.prepare("UPDATE reports SET status='DONE',done_by=?,done_note=?,done_at=CURRENT_TIMESTAMP WHERE id=? AND status='WAITING' RETURNING id").bind(staff.id,note,id).run();if(!result.meta.changes)return fail('Status sudah berubah',409);await db.prepare('INSERT INTO audit(staff_id,action,report_id) VALUES(?,?,?)').bind(staff.id,'DONE',id).run();return json({ok:true})}
return fail('Endpoint tidak ditemukan',404)
}catch(e){console.error('WDBOS API failure', {route:new URL(request.url).pathname,method:request.method,error:e?.message,code:e?.code,stack:e?.stack});return fail('Kesalahan server',500)}}
