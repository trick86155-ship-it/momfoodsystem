/* 맘푸드 업무시스템 - 공유 저장 API (Cloudflare Pages Functions + D1)

   필요한 설정 (Cloudflare Pages 프로젝트 > 설정):
     - D1 데이터베이스 바인딩: 변수 이름 DB
     - 환경 변수(암호화): APP_PASSWORD = 접속 비밀번호

   데이터는 "섹션" 단위로 저장된다 (prod / inbound / profile:<프로필id>).
   섹션 내용은 JSON 문자열 그대로 보관하며, 서버에서는 파싱하지 않는다.
   각 섹션은 버전 번호를 가지고, 저장할 때 클라이언트가 알고 있던 버전(base)과
   서버의 현재 버전이 다르면 409를 돌려줘서 다른 사람의 수정 내용을 덮어쓰지 않게 한다. */

const TOKEN_TTL_MS = 6 * 60 * 60 * 1000; // 로그인 유지 6시간
const CHUNK_CHARS = 250000;              // D1 한 행(2MB) 제한을 넘지 않도록 섹션 내용을 나눠 저장
const MAX_BODY_CHARS = 20 * 1000 * 1000;
const PULL_CHUNK_BUDGET = 16;            // 한 번의 pull 응답에 담을 최대 조각 수(대략 4백만 글자)
const KEY_RE = /^[A-Za-z0-9:_-]{1,80}$/;
const LOGIN_FAIL_LIMIT = 10;
const LOGIN_FAIL_WINDOW_MS = 10 * 60 * 1000;

const NO_STORE = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
const encoder = new TextEncoder();

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: NO_STORE });
}
function rawJson(text, status = 200) {
  return new Response(text, { status, headers: NO_STORE });
}

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS sections (
      key TEXT PRIMARY KEY, version INTEGER NOT NULL, chunks INTEGER NOT NULL,
      writer TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS section_chunks (
      key TEXT NOT NULL, idx INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (key, idx))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS login_fails (
      ip TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL)`),
  ]);
  schemaReady = true;
}

/* ---------- 인증 ---------- */
async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function makeToken(env, expiresAt) {
  return expiresAt + '.' + await hmacHex(env.APP_PASSWORD, 'token:' + expiresAt);
}
async function isValidToken(env, token) {
  const dot = token.indexOf('.');
  if (dot < 1) return false;
  const expiresAt = Number(token.slice(0, dot));
  if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) return false;
  return safeEqual(token, await makeToken(env, expiresAt));
}

async function handleLogin(request, env) {
  const db = env.DB;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const fail = await db.prepare('SELECT count, window_start FROM login_fails WHERE ip = ?').bind(ip).first();
  const inWindow = fail && now - fail.window_start < LOGIN_FAIL_WINDOW_MS;
  if (inWindow && fail.count >= LOGIN_FAIL_LIMIT) return json({ error: 'too_many_attempts' }, 429);

  const body = await request.json().catch(() => null);
  const password = body && typeof body.password === 'string' ? body.password : '';
  // 길이가 달라도 비교 시간이 같도록 양쪽 다 HMAC으로 바꾼 뒤 비교
  const ok = safeEqual(await hmacHex(env.APP_PASSWORD, 'login:' + password), await hmacHex(env.APP_PASSWORD, 'login:' + env.APP_PASSWORD));
  if (!ok) {
    if (inWindow) await db.prepare('UPDATE login_fails SET count = count + 1 WHERE ip = ?').bind(ip).run();
    else await db.prepare('INSERT OR REPLACE INTO login_fails (ip, count, window_start) VALUES (?, 1, ?)').bind(ip, now).run();
    return json({ error: 'wrong_password' }, 401);
  }
  if (fail) await db.prepare('DELETE FROM login_fails WHERE ip = ?').bind(ip).run();
  const expiresAt = now + TOKEN_TTL_MS;
  return json({ token: await makeToken(env, expiresAt), expiresAt });
}

/* ---------- 섹션 읽기/쓰기 ---------- */
function splitChunks(text) {
  const chunks = [];
  let pos = 0;
  while (pos < text.length) {
    let end = Math.min(pos + CHUNK_CHARS, text.length);
    // 이모지 같은 서로게이트 쌍의 중간에서 자르지 않도록 한 글자 뒤로 민다
    if (end < text.length) {
      const code = text.charCodeAt(end - 1);
      if (code >= 0xD800 && code <= 0xDBFF) end++;
    }
    chunks.push(text.slice(pos, end));
    pos = end;
  }
  return chunks;
}

const SELECT_SECTION = `SELECT s.version AS version, c.data AS data
  FROM sections s JOIN section_chunks c ON c.key = s.key WHERE s.key = ? ORDER BY c.idx`;

// 클라이언트가 알고 있는 버전 목록(known)을 받아, 달라진 섹션의 내용만 돌려준다
async function handlePull(request, env) {
  const db = env.DB;
  const body = await request.json().catch(() => null);
  const known = (body && typeof body.known === 'object' && body.known) || {};
  const { results: all } = await db.prepare('SELECT key, version, chunks FROM sections ORDER BY created_at, key').all();

  const toSend = [];
  let budget = PULL_CHUNK_BUDGET;
  let more = false;
  for (const row of all) {
    if (known[row.key] === row.version) continue;
    if (toSend.length > 0 && budget < row.chunks) { more = true; continue; }
    toSend.push(row.key);
    budget -= row.chunks;
  }

  const parts = [];
  if (toSend.length > 0) {
    const out = await db.batch(toSend.map(key => db.prepare(SELECT_SECTION).bind(key)));
    toSend.forEach((key, i) => {
      const rows = out[i].results;
      if (!rows || rows.length === 0) return; // 그 사이에 삭제된 섹션 - 다음 pull에서 정리됨
      parts.push(JSON.stringify(key) + ':{"v":' + rows[0].version + ',"data":' + rows.map(r => r.data).join('') + '}');
    });
  }
  const order = JSON.stringify(all.map(r => [r.key, r.version]));
  return rawJson('{"order":' + order + ',"more":' + more + ',"sections":{' + parts.join(',') + '}}');
}

async function handlePut(request, env, url) {
  const db = env.DB;
  const key = url.searchParams.get('key') || '';
  const base = Number(url.searchParams.get('base') || 0);
  if (!KEY_RE.test(key) || !Number.isInteger(base) || base < 0) return json({ error: 'bad_request' }, 400);
  const text = await request.text();
  if (text.length > MAX_BODY_CHARS) return json({ error: 'too_large' }, 413);
  if (!(text.startsWith('{') && text.endsWith('}'))) return json({ error: 'bad_body' }, 400);

  const chunks = splitChunks(text);
  const writer = crypto.randomUUID();
  const now = Date.now();
  // 첫 문장(버전 확인 + 올리기)이 성공했을 때만 뒤의 조각 교체가 실행되도록 writer 값으로 묶는다.
  // batch는 하나의 트랜잭션으로 실행되므로 읽는 쪽에서 반쯤 바뀐 상태를 볼 일이 없다.
  const guard = 'EXISTS (SELECT 1 FROM sections WHERE key = ?1 AND writer = ?2)';
  const stmts = [
    base === 0
      ? db.prepare('INSERT OR IGNORE INTO sections (key, version, chunks, writer, created_at, updated_at) VALUES (?, 1, ?, ?, ?, ?)')
          .bind(key, chunks.length, writer, now, now)
      : db.prepare('UPDATE sections SET version = version + 1, chunks = ?, writer = ?, updated_at = ? WHERE key = ? AND version = ?')
          .bind(chunks.length, writer, now, key, base),
    db.prepare(`DELETE FROM section_chunks WHERE key = ?1 AND ${guard}`).bind(key, writer),
    ...chunks.map((chunk, i) =>
      db.prepare(`INSERT INTO section_chunks (key, idx, data) SELECT ?1, ?3, ?4 WHERE ${guard}`).bind(key, writer, i, chunk)),
  ];
  const res = await db.batch(stmts);
  if (res[0].meta.changes === 1) return json({ v: base + 1 });

  // 버전 불일치: 다른 사람이 먼저 저장했거나 삭제함 -> 현재 서버 내용을 돌려준다
  const { results: rows } = await db.prepare(SELECT_SECTION).bind(key).all();
  if (!rows || rows.length === 0) return json({ deleted: true }, 409);
  return rawJson('{"v":' + rows[0].version + ',"data":' + rows.map(r => r.data).join('') + '}', 409);
}

async function handleDelete(env, url) {
  const key = url.searchParams.get('key') || '';
  if (!KEY_RE.test(key) || !key.startsWith('profile:')) return json({ error: 'bad_request' }, 400);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM section_chunks WHERE key = ?').bind(key),
    env.DB.prepare('DELETE FROM sections WHERE key = ?').bind(key),
  ]);
  return json({ ok: true });
}

export async function onRequest({ request, env }) {
  try {
    if (!env.DB || !env.APP_PASSWORD) {
      return json({ error: 'not_configured', missing: [!env.DB && 'DB', !env.APP_PASSWORD && 'APP_PASSWORD'].filter(Boolean) }, 503);
    }
    await ensureSchema(env.DB);

    const url = new URL(request.url);
    const route = url.pathname.replace(/^\/api\//, '').replace(/\/$/, '');
    const method = request.method;

    if (route === 'login' && method === 'POST') return await handleLogin(request, env);

    const auth = request.headers.get('Authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!token || !(await isValidToken(env, token))) return json({ error: 'unauthorized' }, 401);

    if (route === 'pull' && method === 'POST') return await handlePull(request, env);
    if (route === 'section' && method === 'PUT') return await handlePut(request, env, url);
    if (route === 'section' && method === 'DELETE') return await handleDelete(env, url);
    return json({ error: 'not_found' }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: 'server_error', message: String(err && err.message || err) }, 500);
  }
}
