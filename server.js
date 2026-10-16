const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ALLOWED_ORIGIN || '';
const ADMIN = process.env.ADMIN_PASSWORD || '';
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
alter table users add column if not exists last_seen timestamptz;
alter table users add column if not exists banned boolean not null default false;
alter table members add column if not exists last_read bigint not null default 0;
alter table messages add column if not exists reply_to bigint;
alter table messages add column if not exists edited boolean not null default false;
alter table users add column if not exists is_admin boolean not null default false;
alter table users add column if not exists is_bot boolean not null default false;
create table if not exists bots (user_id int primary key references users(id) on delete cascade, owner_id int not null references users(id) on delete cascade, token_hash text not null);
create unique index if not exists bots_token on bots (token_hash);
create table if not exists reports (id serial primary key, msg_id bigint not null references messages(id) on delete cascade, reporter_id int not null references users(id) on delete cascade, created_at timestamptz not null default now(), unique (msg_id, reporter_id));
`;

const NAME_RE = /^[\w\u0600-\u06FF]{3,20}$/;
const ADMINS = (process.env.ADMIN_USERNAMES || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
const botIds = new Set(), botQueues = new Map(); let upd = 0;
const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
function queueBot(botId, o) { const a = botQueues.get(botId) || []; a.push({ update_id: ++upd, ...o }); if (a.length > 200) a.shift(); botQueues.set(botId, a); }
const online = new Map(); // userId -> Set<ws>
const send = (ws, o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
const sendUsers = (ids, o) => { for (const id of ids) for (const w of online.get(id) || []) send(w, o); };
const err = (ws, text) => send(ws, { type: 'error', text });
const hash = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k.toString('hex')))));
const kickSockets = (id, type) => { for (const w of [...(online.get(id) || [])]) { send(w, { type }); w.close(); } };

async function chatsFor(uid) {
  const rows = await q(`
    select c.id, c.kind, c.name, mm.role,
      (select u.username from members m2 join users u on u.id = m2.user_id where m2.chat_id = c.id and m2.user_id <> $1 limit 1) as other,
      (select u.id from members m2 join users u on u.id = m2.user_id where m2.chat_id = c.id and m2.user_id <> $1 limit 1) as other_id,
      (select extract(epoch from u.last_seen) * 1000 from members m2 join users u on u.id = m2.user_id where m2.chat_id = c.id and m2.user_id <> $1 limit 1) as other_seen,
      (select m3.last_read from members m3 where m3.chat_id = c.id and m3.user_id <> $1 limit 1) as other_read,
      (select text from messages where chat_id = c.id order by id desc limit 1) as last,
      (select max(id) from messages where chat_id = c.id) as lastid,
      (select count(*) from messages x where x.chat_id = c.id and x.id > mm.last_read and x.user_id <> $1) as unread
    from members mm join chats c on c.id = mm.chat_id
    where mm.user_id = $1 order by lastid desc nulls last, c.id desc`, [uid]);
  return rows.map((r) => ({
    id: r.id, kind: r.kind, name: r.name, role: r.role, other: r.other,
    otherOnline: r.kind === 'dm' && online.has(r.other_id), otherSeen: Number(r.other_seen) || 0,
    otherRead: Number(r.other_read) || 0, last: r.last, unread: Number(r.unread),
  }));
}
async function pushChats(ids) {
  for (const id of ids) if (online.has(id)) sendUsers([id], { type: 'chats', chats: await chatsFor(id) });
}
const membership = async (cid, uid) =>
  (await q('select m.role, c.kind from members m join chats c on c.id = m.chat_id where m.chat_id = $1 and m.user_id = $2', [cid, uid]))[0];
const memberIds = async (cid) => (await q('select user_id from members where chat_id = $1', [cid])).map((r) => r.user_id);
const target = async (cid, username) =>
  (await q('select u.id, mm.role from users u join members mm on mm.user_id = u.id and mm.chat_id = $2 where lower(u.username) = lower($1)', [String(username || ''), cid]))[0];

async function presenceChange(user, isOnline) {
  const ids = (await q(`select distinct m2.user_id as id from members m1
    join chats c on c.id = m1.chat_id and c.kind = 'dm'
    join members m2 on m2.chat_id = c.id and m2.user_id <> $1 where m1.user_id = $1`, [user.id])).map((r) => r.id);
  sendUsers(ids, { type: 'presence', user: user.username, online: isOnline, seen: Date.now() });
}

async function auth(ws, m) {
  let user;
  if (m.type === 'resume') {
    const r = (await q('select u.id, u.username, u.banned, u.is_admin from sessions s join users u on u.id = s.user_id where s.token = $1', [String(m.token || '')]))[0];
    if (!r || r.banned) return send(ws, { type: 'auth-failed' });
    user = { id: r.id, username: r.username, isAdmin: r.is_admin };
    ws.token = String(m.token);
  } else {
    const name = String(m.username || '').trim(), pw = String(m.password || '');
    if (m.type === 'register') {
      if (!NAME_RE.test(name)) return err(ws, 'نام کاربری باید ۳ تا ۲۰ کاراکتر (حرف، عدد یا _) باشد');
      if (pw.length < 6 || pw.length > 100) return err(ws, 'رمز عبور حداقل ۶ کاراکتر باشد');
      if (/bot$/i.test(name)) return err(ws, 'نام‌های پایان‌یافته با bot مخصوص ربات‌هاست');
      const salt = crypto.randomBytes(16).toString('hex');
      try {
        user = (await q('insert into users (username, salt, pass_hash) values ($1, $2, $3) returning id, username', [name, salt, await hash(pw, salt)]))[0];
      } catch (e) { if (e.code === '23505') return err(ws, 'این نام کاربری قبلاً گرفته شده است'); throw e; }
    } else {
      const r = (await q('select id, username, salt, pass_hash, banned, is_admin from users where lower(username) = lower($1)', [name]))[0];
      const ok = r && crypto.timingSafeEqual(Buffer.from(await hash(pw, r.salt), 'hex'), Buffer.from(r.pass_hash, 'hex'));
      if (!ok) return err(ws, 'نام کاربری یا رمز عبور اشتباه است');
      if (r.banned) return err(ws, 'حساب شما مسدود شده است');
      user = { id: r.id, username: r.username, isAdmin: r.is_admin };
    }
    ws.token = crypto.randomBytes(32).toString('hex');
    await q('insert into sessions (token, user_id) values ($1, $2)', [ws.token, user.id]);
  }
  if (!user.isAdmin && ADMINS.includes(user.username.toLowerCase())) { // ادمین‌های اولیه از متغیر ADMIN_USERNAMES
    await q('update users set is_admin = true where id = $1', [user.id]);
    user.isAdmin = true;
  }
  ws.user = user;
  if (!online.has(user.id)) online.set(user.id, new Set());
  const first = online.get(user.id).size === 0;
  online.get(user.id).add(ws);
  send(ws, { type: 'auth', token: ws.token, username: user.username, isAdmin: !!user.isAdmin });
  await pushChats([user.id]);
  if (first) presenceChange(user, true).catch(() => {});
}

async function handle(ws, m) {
  if (['register', 'login', 'resume'].includes(m.type)) return auth(ws, m);
  if (!ws.user) return send(ws, { type: 'auth-failed' });
  const uid = ws.user.id, cid = parseInt(m.chatId, 10), okId = Number.isInteger(cid);
  if (String(m.type).startsWith('a:') && !ws.user.isAdmin) return err(ws, 'دسترسی ندارید');

  switch (m.type) {
    case 'report': { // با گزارش، متن همان پیام برای ادمین قابل مشاهده می‌شود
      const mid = parseInt(m.msgId, 10);
      const ok = Number.isInteger(mid) && (await q('select 1 from messages m join members x on x.chat_id = m.chat_id and x.user_id = $2 where m.id = $1', [mid, uid]))[0];
      if (!ok) return;
      await q('insert into reports (msg_id, reporter_id) values ($1, $2) on conflict do nothing', [mid, uid]);
      return send(ws, { type: 'info', text: 'گزارش شما برای ادمین ارسال شد' });
    }

    /* ----- ربات‌ها ----- */
    case 'newbot': {
      const name = String(m.name || '').trim();
      if (!NAME_RE.test(name) || !/bot$/i.test(name)) return err(ws, 'نام ربات باید ۳ تا ۲۰ کاراکتر باشد و به bot ختم شود');
      if (Number((await q('select count(*) c from bots where owner_id = $1', [uid]))[0].c) >= 10) return err(ws, 'حداکثر ۱۰ ربات می‌توانید بسازید');
      const token = crypto.randomBytes(24).toString('hex');
      try {
        const u = (await q('insert into users (username, salt, pass_hash, is_bot) values ($1, $2, $3, true) returning id', [name, crypto.randomBytes(16).toString('hex'), crypto.randomBytes(64).toString('hex')]))[0];
        await q('insert into bots (user_id, owner_id, token_hash) values ($1, $2, $3)', [u.id, uid, sha(token)]);
        botIds.add(u.id);
      } catch (e) { if (e.code === '23505') return err(ws, 'این نام قبلاً گرفته شده است'); throw e; }
      return send(ws, { type: 'botcreated', name, token });
    }
    case 'mybots':
      return send(ws, { type: 'mybots', bots: await q('select u.id, u.username from bots b join users u on u.id = b.user_id where b.owner_id = $1 order by u.id', [uid]) });
    case 'delbot': {
      const id = parseInt(m.id, 10);
      if (!Number.isInteger(id) || !(await q('select 1 from bots where user_id = $1 and owner_id = $2', [id, uid]))[0]) return;
      await q('delete from messages where user_id = $1', [id]);
      await q('delete from users where id = $1', [id]);
      botIds.delete(id); botQueues.delete(id);
      return send(ws, { type: 'mybots', bots: await q('select u.id, u.username from bots b join users u on u.id = b.user_id where b.owner_id = $1 order by u.id', [uid]) });
    }

    /* ----- کاربر ادمین: فقط گفتگوهای عمومی و پیام‌های گزارش‌شده قابل مشاهده است ----- */
    case 'a:stats': {
      const r = (await q("select (select count(*) from users where not is_bot) u, (select count(*) from chats where kind <> 'dm') g, (select count(*) from messages) m, (select count(*) from reports) r, (select count(*) from bots) b"))[0];
      return send(ws, { type: 'a:stats', stats: { users: +r.u, groups: +r.g, msgs: +r.m, reports: +r.r, bots: +r.b, online: online.size } });
    }
    case 'a:users': {
      const rows = await q('select id, username, is_admin as "isAdmin", banned from users where not is_bot order by id desc limit 200');
      return send(ws, { type: 'a:users', users: rows.map((x) => ({ ...x, online: online.has(x.id) })) });
    }
    case 'a:ban': {
      const id = parseInt(m.userId, 10);
      if (!Number.isInteger(id) || id === uid) return;
      await q('update users set banned = $2 where id = $1', [id, !!m.banned]);
      if (m.banned) { await q('delete from sessions where user_id = $1', [id]); kickSockets(id, 'banned'); }
      return send(ws, { type: 'info', text: m.banned ? 'کاربر مسدود شد' : 'مسدودی برداشته شد' });
    }
    case 'a:admin': {
      const id = parseInt(m.userId, 10);
      if (!Number.isInteger(id) || id === uid) return;
      await q('update users set is_admin = $2 where id = $1', [id, !!m.admin]);
      return send(ws, { type: 'info', text: 'انجام شد' });
    }
    case 'a:chats': {
      const rows = await q("select c.id, c.kind, c.name, c.is_public, (select count(*) from members where chat_id = c.id) as n, (select username from users where id = c.owner_id) as owner from chats c where c.kind <> 'dm' order by c.id desc limit 200");
      return send(ws, { type: 'a:chats', chats: rows.map((x) => ({ ...x, n: Number(x.n) })) });
    }
    case 'a:view': {
      const c = okId && (await q("select id from chats where id = $1 and is_public and kind <> 'dm'", [cid]))[0];
      if (!c) return err(ws, 'فقط گفتگوهای عمومی برای ادمین قابل مشاهده است');
      const rows = await q('select m.id, u.username as "user", m.text from messages m join users u on u.id = m.user_id where m.chat_id = $1 order by m.id desc limit 100', [cid]);
      return send(ws, { type: 'a:view', chatId: cid, msgs: rows.reverse().map((x) => ({ id: Number(x.id), user: x.user, text: x.text })) });
    }
    case 'a:delmsg': {
      const id = parseInt(m.id, 10);
      if (!Number.isInteger(id)) return;
      const r = await q("delete from messages where id = $1 and chat_id in (select id from chats where kind <> 'dm') returning chat_id", [id]);
      if (r[0]) { const ids = await memberIds(r[0].chat_id); sendUsers(ids, { type: 'deleted', chatId: r[0].chat_id, id }); await pushChats(ids); }
      return send(ws, { type: 'info', text: 'پیام حذف شد' });
    }
    case 'a:delchat': {
      if (!okId) return;
      const ids = await memberIds(cid);
      await q("delete from chats where id = $1 and kind <> 'dm'", [cid]);
      sendUsers(ids, { type: 'left', chatId: cid }); await pushChats(ids);
      return send(ws, { type: 'info', text: 'گفتگو حذف شد' });
    }
    case 'a:reports': {
      const rows = await q(`select r.id, m.text, u.username as author, ru.username as reporter, c.name from reports r
        join messages m on m.id = r.msg_id join users u on u.id = m.user_id join users ru on ru.id = r.reporter_id
        join chats c on c.id = m.chat_id order by r.id desc limit 100`);
      return send(ws, { type: 'a:reports', reports: rows });
    }
    case 'a:dismiss': {
      const id = parseInt(m.id, 10);
      if (Number.isInteger(id)) await q('delete from reports where id = $1', [id]);
      return send(ws, { type: 'info', text: 'انجام شد' });
    }
    case 'a:announce': {
      const text = String(m.text || '').trim().slice(0, 300);
      if (text) sendUsers([...online.keys()], { type: 'info', text: '📢 ' + text });
      return;
    }

    case 'chats': return pushChats([uid]);

    case 'logout':
      if (ws.token) await q('delete from sessions where token = $1', [ws.token]);
      return;

    case 'open': {
      if (!okId || !(await membership(cid, uid))) return;
      const before = parseInt(m.before, 10);
      const rows = await q(`select m.id, u.username as "user", m.text, extract(epoch from m.created_at) * 1000 as t, m.edited, u.is_admin as adm,
          r.id as rid, ru.username as ruser, r.text as rtext
        from messages m join users u on u.id = m.user_id
        left join messages r on r.id = m.reply_to left join users ru on ru.id = r.user_id
        where m.chat_id = $1 and ($2::bigint is null or m.id < $2) order by m.id desc limit 40`, [cid, Number.isInteger(before) ? before : null]);
      const msgs = rows.reverse().map((r) => ({
        id: Number(r.id), user: r.user, text: r.text, t: Number(r.t), edited: r.edited, adm: r.adm,
        reply: r.rid ? { id: Number(r.rid), user: r.ruser, text: String(r.rtext).slice(0, 80) } : null,
      }));
      return send(ws, { type: 'history', chatId: cid, msgs, more: rows.length === 40, before: Number.isInteger(before) });
    }

    case 'members': {
      if (!okId || !(await membership(cid, uid))) return;
      const rows = await q('select u.id, u.username, u.is_admin as adm, u.is_bot as bot, m.role from members m join users u on u.id = m.user_id where m.chat_id = $1 order by m.role, u.username', [cid]);
      return send(ws, { type: 'members', chatId: cid, members: rows.map((r) => ({ username: r.username, role: r.role, adm: r.adm, bot: r.bot, online: r.bot || online.has(r.id) })) });
    }

    case 'send': {
      const text = String(m.text || '').trim().slice(0, 2000);
      const mem = okId && (await membership(cid, uid));
      if (!text || !mem) return;
      if (mem.kind === 'channel' && !['owner', 'admin'].includes(mem.role)) return err(ws, 'فقط مدیر کانال می‌تواند پیام بگذارد');
      let reply = null;
      const rt = parseInt(m.replyTo, 10);
      if (Number.isInteger(rt)) {
        const r = (await q('select m.id, u.username as "user", m.text from messages m join users u on u.id = m.user_id where m.id = $1 and m.chat_id = $2', [rt, cid]))[0];
        if (r) reply = { id: Number(r.id), user: r.user, text: String(r.text).slice(0, 80) };
      }
      const r = (await q('insert into messages (chat_id, user_id, text, reply_to) values ($1, $2, $3, $4) returning id, extract(epoch from created_at) * 1000 as t', [cid, uid, text, reply && reply.id]))[0];
      const id = Number(r.id);
      await q('update members set last_read = greatest(last_read, $3) where chat_id = $1 and user_id = $2', [cid, uid, id]);
      const ids = await memberIds(cid);
      sendUsers(ids, { type: 'msg', chatId: cid, id, user: ws.user.username, text, t: Number(r.t), reply, edited: false, tmp: m.tmp, adm: !!ws.user.isAdmin });
      for (const b of ids) if (botIds.has(b) && b !== uid)
        queueBot(b, { message: { message_id: id, chat: { id: cid, type: mem.kind }, from: ws.user.username, text, date: Math.floor(Number(r.t) / 1000), reply_to: reply && reply.id } });
      return;
    }

    case 'typing': {
      if (!okId || !(await membership(cid, uid))) return;
      return sendUsers((await memberIds(cid)).filter((i) => i !== uid), { type: 'typing', chatId: cid, user: ws.user.username });
    }

    case 'read': {
      const up = parseInt(m.upTo, 10);
      if (!okId || !Number.isInteger(up) || !(await membership(cid, uid))) return;
      await q('update members set last_read = greatest(last_read, $3) where chat_id = $1 and user_id = $2', [cid, uid, up]);
      return sendUsers((await memberIds(cid)).filter((i) => i !== uid), { type: 'read', chatId: cid, user: ws.user.username, upTo: up });
    }

    case 'edit': {
      const id = parseInt(m.id, 10), text = String(m.text || '').trim().slice(0, 2000);
      if (!text || !okId || !Number.isInteger(id)) return;
      const r = await q('update messages set text = $1, edited = true where id = $2 and chat_id = $3 and user_id = $4 returning id', [text, id, cid, uid]);
      if (!r[0]) return;
      const ids = await memberIds(cid);
      sendUsers(ids, { type: 'edited', chatId: cid, id, text });
      return pushChats(ids);
    }

    case 'delmsg': {
      const id = parseInt(m.id, 10), mem = okId && (await membership(cid, uid));
      if (!mem || !Number.isInteger(id)) return;
      const mod = mem.kind !== 'dm' && ['owner', 'admin'].includes(mem.role);
      const r = await q('delete from messages where id = $1 and chat_id = $2 and (user_id = $3 or $4::boolean) returning id', [id, cid, uid, mod]);
      if (!r[0]) return;
      const ids = await memberIds(cid);
      sendUsers(ids, { type: 'deleted', chatId: cid, id });
      return pushChats(ids);
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
      const users = await q('select username from users where username ilike $1 and id <> $2 and not banned order by username limit 10', [term + '%', uid]);
      const chats = await q('select id, kind, name from chats where is_public and name ilike $1 order by name limit 10', ['%' + term + '%']);
      return send(ws, { type: 'found', users, chats });
    }

    case 'join': {
      const c = okId && (await q("select id from chats where id = $1 and is_public and kind <> 'dm'", [cid]))[0];
      if (!c) return err(ws, 'این گفتگو پیدا نشد');
      await q('insert into members (chat_id, user_id) values ($1, $2) on conflict do nothing', [cid, uid]);
      await pushChats([uid]);
      return send(ws, { type: 'opened', chatId: cid });
    }

    case 'dm': {
      const other = (await q('select id from users where lower(username) = lower($1) and id <> $2 and not banned', [String(m.username || ''), uid]))[0];
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
      const mem = okId && (await membership(cid, uid));
      if (!mem || mem.kind === 'dm' || !['owner', 'admin'].includes(mem.role)) return err(ws, 'اجازه‌ی افزودن عضو ندارید');
      const u = (await q('select id from users where lower(username) = lower($1) and not banned', [String(m.username || '')]))[0];
      if (!u) return err(ws, 'کاربر پیدا نشد');
      await q('insert into members (chat_id, user_id) values ($1, $2) on conflict do nothing', [cid, u.id]);
      await pushChats([u.id]);
      return send(ws, { type: 'info', text: 'عضو اضافه شد' });
    }

    case 'rmmember': {
      const mem = okId && (await membership(cid, uid));
      if (!mem || mem.kind === 'dm' || !['owner', 'admin'].includes(mem.role)) return err(ws, 'اجازه ندارید');
      const t = await target(cid, m.username);
      if (!t || t.role === 'owner' || t.id === uid || (mem.role === 'admin' && t.role === 'admin')) return err(ws, 'اجازه ندارید');
      await q('delete from members where chat_id = $1 and user_id = $2', [cid, t.id]);
      sendUsers([t.id], { type: 'left', chatId: cid });
      await pushChats([t.id]);
      return send(ws, { type: 'info', text: 'عضو حذف شد' });
    }

    case 'promote': {
      const mem = okId && (await membership(cid, uid));
      if (!mem || mem.kind === 'dm' || mem.role !== 'owner') return err(ws, 'فقط مالک می‌تواند مدیر تعیین کند');
      const t = await target(cid, m.username);
      if (!t || t.role === 'owner') return;
      await q('update members set role = $3 where chat_id = $1 and user_id = $2', [cid, t.id, m.admin ? 'admin' : 'member']);
      await pushChats([t.id]);
      return send(ws, { type: 'info', text: 'انجام شد' });
    }

    case 'leave': {
      const mem = okId && (await membership(cid, uid));
      if (!mem || mem.kind === 'dm') return;
      if (mem.role === 'owner') return err(ws, 'مالک نمی‌تواند خارج شود؛ گفتگو را حذف کنید');
      await q('delete from members where chat_id = $1 and user_id = $2', [cid, uid]);
      send(ws, { type: 'left', chatId: cid });
      return pushChats([uid]);
    }

    case 'delchat': {
      const mem = okId && (await membership(cid, uid));
      if (!mem) return;
      if (mem.kind !== 'dm' && mem.role !== 'owner') return err(ws, 'فقط مالک می‌تواند حذف کند');
      const ids = await memberIds(cid);
      await q('delete from chats where id = $1', [cid]);
      sendUsers(ids, { type: 'left', chatId: cid });
      return pushChats(ids);
    }
  }
}

/* ---------- پنل ادمین (HTTP) ---------- */
async function adminState() {
  const s = (await q('select (select count(*) from users) as users, (select count(*) from chats) as chats, (select count(*) from messages) as msgs, pg_database_size(current_database()) as size'))[0];
  const users = await q('select id, username, extract(epoch from last_seen) * 1000 as seen, banned from users order by id desc limit 500');
  const chats = await q('select c.id, c.kind, c.name, c.is_public, (select count(*) from members where chat_id = c.id) as members, (select count(*) from messages where chat_id = c.id) as msgs from chats c order by c.id desc limit 500');
  return {
    stats: { users: Number(s.users), chats: Number(s.chats), msgs: Number(s.msgs), size: Number(s.size), online: online.size },
    users: users.map((u) => ({ id: u.id, username: u.username, seen: Number(u.seen) || 0, banned: u.banned, online: online.has(u.id) })),
    chats: chats.map((c) => ({ id: c.id, kind: c.kind, name: c.name, pub: c.is_public, members: Number(c.members), msgs: Number(c.msgs) })),
  };
}
async function admin(act, d) {
  const id = parseInt(d.id, 10);
  let view = null;
  if (act === 'ban' && id) { await q('update users set banned = true where id = $1', [id]); await q('delete from sessions where user_id = $1', [id]); kickSockets(id, 'banned'); }
  else if (act === 'unban' && id) await q('update users set banned = false where id = $1', [id]);
  else if (act === 'resetpw' && id && String(d.password || '').length >= 6) {
    const salt = crypto.randomBytes(16).toString('hex');
    await q('update users set salt = $2, pass_hash = $3 where id = $1', [id, salt, await hash(String(d.password), salt)]);
    await q('delete from sessions where user_id = $1', [id]); kickSockets(id, 'auth-failed');
  }
  else if (act === 'deluser' && id) {
    await q('delete from messages where user_id = $1', [id]);
    await q('update chats set owner_id = null where owner_id = $1', [id]);
    await q('delete from users where id = $1', [id]); kickSockets(id, 'banned');
  }
  else if (act === 'delchat' && id) {
    const ids = await memberIds(id);
    await q('delete from chats where id = $1', [id]);
    sendUsers(ids, { type: 'left', chatId: id }); await pushChats(ids);
  }
  else if (act === 'delmsg' && id) {
    const r = await q('delete from messages where id = $1 returning chat_id', [id]);
    if (r[0]) { const ids = await memberIds(r[0].chat_id); sendUsers(ids, { type: 'deleted', chatId: r[0].chat_id, id }); await pushChats(ids); }
  }
  else if (act === 'announce' && d.text) sendUsers([...online.keys()], { type: 'info', text: String(d.text).slice(0, 300) });
  else if (act === 'chat' && id) {
    const rows = await q('select m.id, u.username as "user", m.text from messages m join users u on u.id = m.user_id where m.chat_id = $1 and exists (select 1 from chats c where c.id = $1 and c.is_public and c.kind <> \'dm\') order by m.id desc limit 100', [id]);
    view = { chatId: id, msgs: rows.map((r) => ({ id: Number(r.id), user: r.user, text: r.text })) };
  }
  const st = await adminState();
  if (view) st.view = view;
  return st;
}

async function botApi(req, res, token, method, qs) {
  const json = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  try {
    const b = (await q('select u.id, u.username from bots x join users u on u.id = x.user_id where x.token_hash = $1', [sha(token)]))[0];
    if (!b) return json(401, { ok: false, error: 'invalid token' });
    let body = ''; for await (const c of req) body += c;
    let d = {}; try { d = JSON.parse(body || '{}'); } catch {}
    for (const [k, v] of qs) if (!(k in d)) d[k] = v;
    if (method === 'getMe') return json(200, { ok: true, result: { id: b.id, username: b.username } });
    if (method === 'getUpdates') {
      const off = parseInt(d.offset, 10) || 0, all = botQueues.get(b.id) || [];
      const list = off ? all.filter((u) => u.update_id >= off) : all;
      botQueues.set(b.id, list);
      return json(200, { ok: true, result: list });
    }
    if (method === 'sendMessage') {
      const cid = parseInt(d.chat_id, 10), text = String(d.text || '').trim().slice(0, 2000);
      if (!Number.isInteger(cid) || !text) return json(400, { ok: false, error: 'chat_id and text are required' });
      const mem = await membership(cid, b.id);
      if (!mem) return json(403, { ok: false, error: 'bot is not a member of this chat' });
      if (mem.kind === 'channel' && !['owner', 'admin'].includes(mem.role)) return json(403, { ok: false, error: 'bot must be a channel admin' });
      const r = (await q('insert into messages (chat_id, user_id, text) values ($1, $2, $3) returning id, extract(epoch from created_at) * 1000 as t', [cid, b.id, text]))[0];
      const id = Number(r.id);
      sendUsers(await memberIds(cid), { type: 'msg', chatId: cid, id, user: b.username, text, t: Number(r.t), reply: null, edited: false });
      return json(200, { ok: true, result: { message_id: id } });
    }
    return json(404, { ok: false, error: 'unknown method' });
  } catch (e) { console.error(e); return json(500, { ok: false, error: 'server error' }); }
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'x-admin,content-type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const bm = req.url.match(/^\/bot([0-9a-f]{48})\/(\w+)(?:\?(.*))?$/);
  if (bm) return botApi(req, res, bm[1], bm[2], new URLSearchParams(bm[3] || ''));
  if (!req.url.startsWith('/admin/')) { res.writeHead(200); return res.end('messenger server ok'); }
  if (!ADMIN || req.headers['x-admin'] !== ADMIN) { res.writeHead(401); return res.end('unauthorized'); }
  let body = ''; for await (const c of req) body += c;
  let d = {}; try { d = JSON.parse(body || '{}'); } catch {}
  try {
    const out = await admin(req.url.slice(7), d);
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(out));
  } catch (e) { console.error(e); res.writeHead(500); res.end('error'); }
});

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
    if (ws.hits.length > 40) return err(ws, 'آهسته‌تر، تعداد درخواست‌ها زیاد است');
    try { await handle(ws, m); } catch (e) { console.error(e); err(ws, 'خطای سرور'); }
  });
  ws.on('close', () => {
    const u = ws.user; if (!u) return;
    const s = online.get(u.id);
    if (s) {
      s.delete(ws);
      if (!s.size) {
        online.delete(u.id);
        q('update users set last_seen = now() where id = $1', [u.id]).then(() => presenceChange(u, false)).catch(() => {});
      }
    }
  });
  ws.on('error', () => {});
});
setInterval(() => { for (const ws of wss.clients) { if (!ws.isAlive) { ws.terminate(); continue; } ws.isAlive = false; ws.ping(); } }, 25000);

pool.query(SCHEMA).then(async () => { for (const r of await q('select user_id from bots')) botIds.add(r.user_id); server.listen(PORT, () => console.log('listening on', PORT)); })
  .catch((e) => { console.error('اتصال به دیتابیس ناموفق بود:', e.message); process.exit(1); });
