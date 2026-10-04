// api/index.js — الخادم: يحفظ البيانات في Upstash Redis. لا يوجد هنا أي أمر حذف للبيانات.
const crypto = require('crypto');

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

async function r(...cmd) {
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await res.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
async function all(key) {
  const a = (await r('HGETALL', key)) || [];
  const vals = Array.isArray(a) ? a.filter((_, i) => i % 2 === 1) : Object.values(a);
  return vals.map((v) => JSON.parse(v));
}

const r2 = (n) => Math.round(n * 100) / 100;
const dayFmt = new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo', year: 'numeric', month: '2-digit', day: '2-digit' });
const timeFmt = new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Cairo', hour: '2-digit', minute: '2-digit', hour12: false });
const ymOf = (ts) => dayFmt.format(ts).slice(0, 7);

// ---------- كلمة السر والجلسات ----------
const hashPass = (p, salt) => crypto.scryptSync(String(p), salt, 32).toString('hex');
async function setPass(p, nx) {
  const salt = crypto.randomBytes(16).toString('hex');
  const val = salt + ':' + hashPass(p, salt);
  return nx ? r('SET', 'ph:pass', val, 'NX') : r('SET', 'ph:pass', val);
}
async function checkPass(p) {
  const v = await r('GET', 'ph:pass');
  if (!v) return false;
  const [salt, h] = v.split(':');
  return crypto.timingSafeEqual(Buffer.from(hashPass(p, salt), 'hex'), Buffer.from(h, 'hex'));
}
async function newToken() {
  const t = crypto.randomBytes(24).toString('hex');
  await r('SET', 'ph:tok:' + t, '1', 'EX', '43200'); // 12 ساعة
  return t;
}
async function limit(key, max, secs) {
  const n = await r('INCR', key);
  if (n === 1) await r('EXPIRE', key, String(secs));
  return n <= max;
}

// ---------- الحضور ----------
async function findEmp(code) {
  code = String(code || '').trim().toUpperCase();
  if (!code) return null;
  return (await all('ph:emp')).find((e) => e.code === code && e.active) || null;
}
async function summary(e) {
  const m = ymOf(Date.now());
  const [atts, wds] = await Promise.all([all('ph:att'), all('ph:wd')]);
  let hrs = 0, w = 0;
  for (const a of atts) if (a.emp === e.id && a.out && ymOf(a.in) === m) hrs += a.hours;
  for (const x of wds) if (x.emp === e.id && x.date.slice(0, 7) === m) w += x.amount;
  hrs = r2(hrs);
  const g = e.basis > 0 ? r2((hrs * e.rate) / e.basis) : 0; // (الساعات × سعر الساعة) ÷ أيام الأساس
  return { name: e.name, month: m, hours: hrs, gross: g, wd: r2(w), left: r2(g - w) };
}
async function clock(code, kind) {
  const e = await findEmp(code);
  if (!e) return { err: 'الكود غير صحيح' };
  const now = Date.now();
  let msg;
  if (kind === 'in') {
    const id = await r('INCR', 'ph:seq');
    const ok = await r('HSETNX', 'ph:open', String(e.id), String(id));
    if (!ok) return { err: 'لديك حضور مفتوح بالفعل — سجّل الانصراف أولاً' };
    await r('HSET', 'ph:att', String(id), JSON.stringify({ id, emp: e.id, in: now, out: null, hours: 0 }));
    msg = 'تم تسجيل حضور ' + e.name + ' الساعة ' + timeFmt.format(now);
  } else if (kind === 'out') {
    const id = await r('HGET', 'ph:open', String(e.id));
    if (!id) return { err: 'لا يوجد حضور مفتوح لتسجيل انصرافه' };
    const raw = await r('HGET', 'ph:att', String(id));
    if (!raw) { await r('HDEL', 'ph:open', String(e.id)); return { err: 'لا يوجد حضور مفتوح لتسجيل انصرافه' }; }
    const a = JSON.parse(raw);
    a.out = now; a.hours = r2((now - a.in) / 3600000);
    await r('HSET', 'ph:att', String(id), JSON.stringify(a));
    await r('HDEL', 'ph:open', String(e.id)); // فهرس الحضور المفتوح فقط، وليس بيانات
    msg = 'تم تسجيل انصراف ' + e.name + ' — المدة ' + a.hours + ' ساعة';
  } else return { err: 'طلب غير صالح' };
  return { msg, info: await summary(e) };
}

// ---------- الموجه ----------
async function route(b, req) {
  const a = b.a;
  const ip = String(req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();

  if (a === 'status') return { hasPass: !!(await r('GET', 'ph:pass')) };

  if (a === 'setup') {
    if (String(b.pass || '').length < 6) return { err: 'كلمة السر 6 أحرف على الأقل' };
    if (!(await setPass(b.pass, true))) return { err: 'كلمة السر محددة بالفعل' };
    return { token: await newToken() };
  }
  if (a === 'login') {
    if (!(await limit('ph:fail:' + ip, 10, 600))) return { err: 'محاولات كثيرة، حاول بعد 10 دقائق' };
    if (!(await checkPass(b.pass))) return { err: 'كلمة السر غير صحيحة' };
    await r('DEL', 'ph:fail:' + ip); // عداد المحاولات فقط
    return { token: await newToken() };
  }
  if (a === 'info' || a === 'clock') {
    if (!(await limit('ph:rl:' + ip, 150, 600))) return { err: 'محاولات كثيرة، حاول بعد قليل' };
    if (a === 'clock') return clock(b.code, b.kind);
    const e = await findEmp(b.code);
    return e ? summary(e) : {};
  }

  // ----- من هنا للمالك فقط -----
  if (!/^[a-f0-9]{48}$/.test(b.t || '') || !(await r('EXISTS', 'ph:tok:' + b.t))) return { status: 401, err: 'غير مصرح' };

  if (a === 'load') {
    const [employees, attendance, withdrawals] = await Promise.all([all('ph:emp'), all('ph:att'), all('ph:wd')]);
    return { employees, attendance, withdrawals };
  }
  if (a === 'changepass') {
    if (!(await checkPass(b.old))) return { err: 'كلمة السر الحالية غير صحيحة' };
    if (String(b.pass || '').length < 6) return { err: 'كلمة السر الجديدة 6 أحرف على الأقل' };
    await setPass(b.pass, false);
    return { ok: true };
  }
  if (a === 'empSave') {
    const code = String(b.code || '').replace(/\s/g, '').toUpperCase(), name = String(b.name || '').trim();
    const rate = Number(b.rate), basis = parseInt(b.basis, 10);
    if (!code || !name || !(rate > 0) || !(basis > 0)) return { err: 'بيانات ناقصة' };
    const emps = await all('ph:emp');
    if (emps.some((e) => e.code === code && e.id !== b.id)) return { err: 'الكود مستخدم لموظف آخر' };
    let e;
    if (b.id) { e = emps.find((x) => x.id === b.id); if (!e) return { err: 'الموظف غير موجود' }; }
    else e = { id: await r('INCR', 'ph:seq'), active: true };
    Object.assign(e, { code, name, phone: String(b.phone || '').trim(), rate, basis, notes: String(b.notes || '').trim() });
    await r('HSET', 'ph:emp', String(e.id), JSON.stringify(e));
    return { ok: true };
  }
  if (a === 'empToggle') {
    const raw = await r('HGET', 'ph:emp', String(b.id));
    if (!raw) return { err: 'الموظف غير موجود' };
    const e = JSON.parse(raw); e.active = !e.active;
    await r('HSET', 'ph:emp', String(e.id), JSON.stringify(e));
    return { ok: true };
  }
  if (a === 'attSave') {
    const emp = Number(b.emp), inTs = Number(b.inTs), outTs = b.outTs ? Number(b.outTs) : null;
    if (!(await r('HEXISTS', 'ph:emp', String(emp)))) return { err: 'الموظف غير موجود' };
    if (!(inTs > 0) || (outTs && outTs <= inTs)) return { err: 'الأوقات غير صحيحة' };
    let rec;
    if (b.id) {
      const raw = await r('HGET', 'ph:att', String(b.id));
      if (!raw) return { err: 'السجل غير موجود' };
      rec = JSON.parse(raw);
      if (String(await r('HGET', 'ph:open', String(rec.emp))) === String(rec.id)) await r('HDEL', 'ph:open', String(rec.emp));
    } else rec = { id: await r('INCR', 'ph:seq') };
    Object.assign(rec, { emp, in: inTs, out: outTs, hours: outTs ? r2((outTs - inTs) / 3600000) : 0 });
    await r('HSET', 'ph:att', String(rec.id), JSON.stringify(rec));
    if (!outTs) await r('HSET', 'ph:open', String(emp), String(rec.id));
    return { ok: true };
  }
  if (a === 'wdSave') {
    const emp = Number(b.emp), amount = Number(b.amount), date = String(b.date || '');
    if (!(await r('HEXISTS', 'ph:emp', String(emp)))) return { err: 'الموظف غير موجود' };
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !amount) return { err: 'أدخل التاريخ والمبلغ' };
    let w;
    if (b.id) {
      const raw = await r('HGET', 'ph:wd', String(b.id));
      if (!raw) return { err: 'المسحوب غير موجود' };
      w = JSON.parse(raw);
    } else w = { id: await r('INCR', 'ph:seq'), emp };
    Object.assign(w, { date, amount, note: String(b.note || '').trim() });
    await r('HSET', 'ph:wd', String(w.id), JSON.stringify(w));
    return { ok: true };
  }
  return { err: 'طلب غير معروف' };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ err: 'method' });
  if (!REDIS_URL || !REDIS_TOKEN) return res.status(500).json({ err: 'قاعدة البيانات غير مربوطة بالمشروع (Upstash Redis)' });
  try {
    const b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const out = await route(b, req);
    if (out && out.status) return res.status(out.status).json({ err: out.err });
    return res.status(200).json(out);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ err: 'خطأ في الخادم' });
  }
};
