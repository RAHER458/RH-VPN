const COOKIE = "rhvpn_session";
const SESSION_TTL = 60 * 60 * 12;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(s) {
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
}
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
async function makeSession(secret) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_TTL })));
  return payload + "." + b64url(await hmac(payload, secret));
}
async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.split(";").map(x => x.trim()).find(x => x.startsWith(COOKIE + "="));
  if (!match) return false;
  const value = decodeURIComponent(match.slice(COOKIE.length + 1));
  const [payload, signature] = value.split(".");
  if (!payload || !signature) return false;
  try {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", key, fromB64url(signature), new TextEncoder().encode(payload))) return false;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    return Number.isInteger(data.exp) && data.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64url(bytes);
}
function cookie(value, maxAge) {
  return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
async function api(request, env) {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/api/health") {
    try {
      await env.DB.prepare("SELECT 1").first();
      return json({ ok: true, database: "connected" });
    } catch {
      return json({ ok: false, database: "not_ready" }, 503);
    }
  }
  if (request.method === "POST" && url.pathname === "/api/login") {
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: "Admin secrets are not configured" }, 503);
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
    if (typeof body.password !== "string" || body.password.length > 512 || body.password !== env.ADMIN_PASSWORD) {
      return json({ error: "Неверный пароль" }, 401);
    }
    const token = await makeSession(env.SESSION_SECRET);
    return json({ ok: true }, 200, { "set-cookie": cookie(token, SESSION_TTL) });
  }
  if (request.method === "POST" && url.pathname === "/api/logout") {
    return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
  }
  if (!await validSession(request, env.SESSION_SECRET || "")) return json({ error: "Требуется вход" }, 401);
  if (request.method === "GET" && url.pathname === "/api/subscriptions") {
    const { results } = await env.DB.prepare(
      "SELECT id, label, created_at, expires_at, revoked_at FROM subscriptions ORDER BY created_at DESC LIMIT 200"
    ).all();
    const now = Math.floor(Date.now() / 1000);
    return json({ subscriptions: results.map(x => ({ ...x, status: x.revoked_at ? "revoked" : x.expires_at <= now ? "expired" : "active" })) });
  }
  if (request.method === "POST" && url.pathname === "/api/subscriptions") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
    const parts = ["days", "hours", "minutes", "seconds"].map(k => body[k] === undefined ? 0 : body[k]);
    if (parts.some(v => !Number.isSafeInteger(v) || v < 0)) return json({ error: "Срок должен содержать целые неотрицательные числа" }, 400);
    const duration = parts[0] * 86400 + parts[1] * 3600 + parts[2] * 60 + parts[3];
    if (!Number.isSafeInteger(duration) || duration < 1 || duration > 315360000) return json({ error: "Срок должен быть от 1 секунды до 10 лет" }, 400);
    const token = randomToken();
    const now = Math.floor(Date.now() / 1000);
    const expires = now + duration;
    const id = crypto.randomUUID();
    const label = typeof body.label === "string" ? body.label.trim().slice(0, 80) : "";
    await env.DB.prepare("INSERT INTO subscriptions (id, token_hash, label, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
      .bind(id, await sha256(token), label, now, expires).run();
    return json({ id, token, created_at: now, expires_at: expires, note: "Токен создан. Формат импорта Happ и VPN-сервер ещё не подключены; это пока не рабочая VPN-ссылка." }, 201);
  }
  const revoke = url.pathname.match(/^\/api\/subscriptions\/([0-9a-f-]+)\/revoke$/i);
  if (request.method === "POST" && revoke) {
    await env.DB.prepare("UPDATE subscriptions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
      .bind(Math.floor(Date.now() / 1000), revoke[1]).run();
    return json({ ok: true });
  }
  return json({ error: "Not found" }, 404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await api(request, env); }
      catch (error) { return json({ error: "Internal server error" }, 500); }
    }
    return env.ASSETS.fetch(request);
  }
};