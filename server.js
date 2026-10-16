const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ALLOWED_ORIGIN || '';
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL تنظیم نشده است'); process.exit(1); }

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
pool.on('error', (e) => console.error('db error', e.message));
const q = async (text, params) => (await pool.query(text, params)).rows;

const SCHEMA = `
create table if not exists users (id serial primary key, username text not null, salt text not null, pass_hash text not null, created_at timestamptz not null default now());
create unique index if not exists users_name on users (lower(username));
create table if not exists sessions (token text primary key, user_id int not null references users(id) on delete cascade, created_at timestamptz not null default now());
create table if not exists chats (id serial primary key, kind text not null check (kind in ('dm','group','channel')), name text, owner_id int references users(id), is_public boolean not null default false, created_at timestamptz not null default now());
create unique index if not exists chats_public_name on chats (lower(name)) where is_public;
create table if not exists members (chat_id int not null references chats(id) on delete cascade, user_id int not null references users(id) on delete cascade, role text not null default 'member', primary key (chat_id, user_id));
create table if not exists messages (id bigserial primary key, chat_id int not null references chats(id) on delete cascade, user_id int not null references users(id), text text not null, created_at timestamptz not null default now());
create index if not exists messages_chat on messages (chat_id, id desc);
`;

const NAME_RE = /^[\w\u0600-\u06FF]{3,20}$/;
const online = new Map(); // userId -> Set<ws>
const send = (ws, o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
const sendUsers = (ids, o) => { for (const id of ids) for (const w of online.get(id) || []) send(w, o); };
const hash = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k.toString('hex')))));
const err = (ws, text) => send(ws, { type: 'error', text });

async function chatsFor(uid) {
  const rows = await q(`
    select c.id, c.kind, c.name, mm.role,
      (select u.username from members m2 join users u on u.id = m2.user_id where m2.chat_id = c.id and m2.user_id <> $1 limit 1) as other,
      (select text from messages where chat_id = c.id order by id desc limit 1) as last,
      (select max(id) from messages where chat_id = c.id) as lastid
    from members mm join chats c on c.id = mm.chat_id
    where mm.user_id = $1 order by lastid desc nulls last, c.id desc`, [uid]);
  return rows.map((r) => ({ id: r.id, kind: r.kind, name: r.name, role: r.role, other: r.other, last: r.last }));
}
async function pushChats(ids) {
  for (const id of ids) if (online.has(id)) { const chats = await chatsFor(id); sendUsers([id], { type: 'chats', chats }); }
}
const membership = async (cid, uid) =>
  (await q('select m.role, c.kind, c.is_public from members m join chats c on c.id = m.chat_id where m.chat_id = $1 and m.user_id = $2', [cid, uid]))[0];
const memberIds = async (cid) => (await q('select user_id from members where chat_id = $1', [cid])).map((r) => r.user_id);

async function auth(ws, m) {
  let user;
  if (m.type === 'resume') {
    const r = await q('select u.id, u.username from sessions s join users u on u.id = s.user_id where s.token = $1', [String(m.token || '')]);
    if (!r[0]) return send(ws, { type: 'auth-failed' });
    user = r[0];
    ws.token = String(m.token);
  } else {
    const name = String(m.username || '').trim(), pw = String(m.password || '');
    if (m.type === 'register') {
      if (!NAME_RE.test(name)) return err(ws, 'نام کاربری باید ۳ تا ۲۰ کاراکتر (حرف، عدد یا _) باشد');
      if (pw.length < 6 || pw.length > 100) return err(ws, 'رمز عبور حداقل ۶ کاراکتر باشد');
      const salt = crypto.randomBytes(16).toString('hex');
      try {
        user = (await q('insert into users (username, salt, pass_hash) values ($1, $2, $3) returning id, username', [name, salt, await hash(pw, salt)]))[0];
      } catch (e) { if (e.code === '23505') return err(ws, 'این نام کاربری قبلاً گرفته شده است'); throw e; }
    } else {
      const r = (await q('select id, username, salt, pass_hash from users where lower(username) = lower($1)', [name]))[0];
      const ok = r && crypto.timingSafeEqual(Buffer.from(await hash(pw, r.salt), 'hex'), Buffer.from(r.pass_hash, 'hex'));
      if (!ok) return err(ws, 'نام کاربری یا رمز عبور اشتباه است');
      user = { id: r.id, username: r.username };
    }
    ws.token = crypto.randomBytes(32).toString('hex');
    await q('insert into sessions (token, user_id) values ($1, $2)', [ws.token, user.id]);
  }
  ws.user = user;
  if (!online.has(user.id)) online.set(user.id, new Set());
  online.get(user.id).add(ws);
  send(ws, { type: 'auth', token: ws.token, username: user.username });
  await pushChats([user.id]);
}

async function handle(ws, m) {
  if (['register', 'login', 'resume'].includes(m.type)) return auth(ws, m);
  if (!ws.user) return send(ws, { type: 'auth-failed' });
  const uid = ws.user.id;
  const cid = parseInt(m.chatId, 10);

  switch (m.type) {
    case 'chats': return pushChats([uid]);

    case 'logout':
      if (ws.token) await q('delete from sessions where token = $1', [ws.token]);
      return;

    case 'open': {
      if (!Number.isInteger(cid) || !(await membership(cid, uid))) return;
      const rows = await q(`select m.id, u.username as "user", m.text, extract(epoch from m.created_at) * 1000 as t
        from messages m join users u on u.id = m.user_id where m.chat_id = $1 order by m.id desc limit 50`, [cid]);
      const msgs = rows.reverse().map((r) => ({ id: Number(r.id), user: r.user, text: r.text, t: Number(r.t) }));
      return send(ws, { type: 'history', chatId: cid, msgs });
    }

    case 'members': {
      if (!Number.isInteger(cid) || !(await membership(cid, uid))) return;
      const members = await q('select u.username, m.role from members m join users u on u.id = m.user_id where m.chat_id = $1 order by m.role, u.username', [cid]);
      return send(ws, { type: 'members', chatId: cid, members });
    }

    case 'send': {
      const text = String(m.text || '').trim().slice(0, 2000);
      const mem = Number.isInteger(cid) && (await membership(cid, uid));
      if (!text || !mem) return;
      if (mem.kind === 'channel' && !['owner', 'admin'].includes(mem.role)) return err(ws, 'فقط مدیر کانال می‌تواند پیام بگذارد');
      const r = (await q('insert into messages (chat_id, user_id, text) values ($1, $2, $3) returning id, extract(epoch from created_at) * 1000 as t', [cid, uid, text]))[0];
      const msg = { type: 'msg', chatId: cid, id: Number(r.id), user: ws.user.username, text, t: Number(r.t) };
      return sendUsers(await memberIds(cid), msg);
    }

    case 'create': {
      const kind = m.kind === 'channel' ? 'channel' : 'group';
      const name = String(m.name || '').trim().slice(0, 40);
      if (name.length < 2) return err(ws, 'نام باید حداقل ۲ کاراکتر باشد');
      let chat;
      try {
        chat = (await q('insert into chats (kind, name, owner_id, is_public) values ($1, $2, $3, $4) returning id', [kind, name, uid, !!m.isPublic]))[0];
      } catch (e) { if (e.code === '23505') return err(ws, 'این نام عمومی قبلاً گرفته شده است'); throw e; }
      await q("insert into members (chat_id, user_id, role) values ($1, $2, 'owner')", [chat.id, uid]);
      await pushChats([uid]);
      return send(ws, { type: 'opened', chatId: chat.id });
    }

    case 'find': {
      const term = String(m.q || '').trim().slice(0, 40).replace(/[%_]/g, '');
      if (term.length < 2) return send(ws, { type: 'found', users: [], chats: [] });
      const users = await q('select username from users where username ilike $1 and id <> $2 order by username limit 10', [term + '%', uid]);
      const chats = await q("select id, kind, name from chats where is_public and name ilike $1 order by name limit 10", ['%' + term + '%']);
      return send(ws, { type: 'found', users, chats });
    }

    case 'join': {
      const c = (await q('select id, kind from chats where id = $1 and is_public and kind <> $2', [cid, 'dm']))[0];
      if (!c) return err(ws, 'این گفتگو پیدا نشد');
      await q('insert into members (chat_id, user_id) values ($1, $2) on conflict do nothing', [cid, uid]);
      await pushChats([uid]);
      return send(ws, { type: 'opened', chatId: cid });
    }

    case 'dm': {
      const other = (await q('select id from users where lower(username) = lower($1) and id <> $2', [String(m.username || ''), uid]))[0];
      if (!other) return err(ws, 'کاربر پیدا نشد');
      let c = (await q(`select c.id from chats c join members a on a.chat_id = c.id and a.user_id = $1
        join members b on b.chat_id = c.id and b.user_id = $2 where c.kind = 'dm' limit 1`, [uid, other.id]))[0];
      if (!c) {
        c = (await q("insert into chats (kind, owner_id) values ('dm', $1) returning id", [uid]))[0];
        await q('insert into members (chat_id, user_id) values ($1, $2), ($1, $3)', [c.id, uid, other.id]);
        await pushChats([uid, other.id]);
      }
      return send(ws, { type: 'opened', chatId: c.id });
    }

    case 'add': {
      const mem = Number.isInteger(cid) && (await membership(cid, uid));
      if (!mem || mem.kind === 'dm' || !['owner', 'admin'].includes(mem.role)) return err(ws, 'اجازه‌ی افزودن عضو ندارید');
      const u = (await q('select id from users where lower(username) = lower($1)', [String(m.username || '')]))[0];
      if (!u) return err(ws, 'کاربر پیدا نشد');
      await q('insert into members (chat_id, user_id) values ($1, $2) on conflict do nothing', [cid, u.id]);
      await pushChats([u.id]);
      return send(ws, { type: 'info', text: 'عضو اضافه شد' });
    }
  }
}

const server = http.createServer((req, res) => { res.writeHead(200); res.end('messenger server ok'); });
const wss = new WebSocketServer({
  server, maxPayload: 16 * 1024,
  verifyClient: (i) => !ORIGIN || i.origin === ORIGIN || (i.origin || '').startsWith('http://localhost'),
});

wss.on('connection', (ws) => {
  ws.isAlive = true; ws.hits = [];
  ws.on('pong', () => (ws.isAlive = true));
  ws.on('message', async (data) => {
    let m; try { m = JSON.parse(data.toString()); } catch { return; }
    const now = Date.now();
    ws.hits = ws.hits.filter((t) => now - t < 10000); ws.hits.push(now);
    if (ws.hits.length > 30) return err(ws, 'آهسته‌تر، تعداد درخواست‌ها زیاد است');
    try { await handle(ws, m); } catch (e) { console.error(e); err(ws, 'خطای سرور'); }
  });
  ws.on('close', () => { if (ws.user) { const s = online.get(ws.user.id); if (s) { s.delete(ws); if (!s.size) online.delete(ws.user.id); } } });
  ws.on('error', () => {});
});
setInterval(() => { for (const ws of wss.clients) { if (!ws.isAlive) { ws.terminate(); continue; } ws.isAlive = false; ws.ping(); } }, 25000);

pool.query(SCHEMA).then(() => server.listen(PORT, () => console.log('listening on', PORT)))
  .catch((e) => { console.error('اتصال به دیتابیس ناموفق بود:', e.message); process.exit(1); });
