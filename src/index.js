function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "access-control-allow-origin": "*" }
  });
}
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type"
      }});
    }
    if (url.pathname.startsWith("/api/")) {
      try {
        if (request.method === "GET" && url.pathname === "/api/health") {
          await env.DB.prepare("SELECT 1").first();
          return json({ ok: true, database: "connected" });
        }
        if (request.method === "GET" && url.pathname === "/api/subscriptions") {
          const { results } = await env.DB.prepare(
            "SELECT id, label, created_at, expires_at, revoked_at FROM subscriptions ORDER BY created_at DESC LIMIT 200"
          ).all();
          const now = Math.floor(Date.now() / 1000);
          return json({ subscriptions: results.map(x => ({ ...x, status: x.revoked_at ? "revoked" : x.expires_at <= now ? "expired" : "active" })) });
        }
        if (request.method === "POST" && url.pathname === "/api/subscriptions") {
          let body;
          try { body = await request.json(); } catch { return json({ error: "Некорректные данные" }, 400); }
          const parts = ["days", "hours", "minutes", "seconds"].map(k => body[k] === undefined ? 0 : body[k]);
          if (parts.some(v => !Number.isSafeInteger(v) || v < 0)) return json({ error: "Срок должен быть целым неотрицательным числом" }, 400);
          const duration = parts[0] * 86400 + parts[1] * 3600 + parts[2] * 60 + parts[3];
          if (!Number.isSafeInteger(duration) || duration < 1 || duration > 315360000) return json({ error: "Укажи срок от 1 секунды до 10 лет" }, 400);
          const token = randomToken();
          const now = Math.floor(Date.now() / 1000);
          const expires = now + duration;
          const id = crypto.randomUUID();
          const label = typeof body.label === "string" ? body.label.trim().slice(0, 80) : "";
          await env.DB.prepare("INSERT INTO subscriptions (id, token_hash, label, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
            .bind(id, await sha256(token), label, now, expires).run();
          return json({
            id, token, created_at: now, expires_at: expires,
            message: "Токен создан. Формат импорта Happ и VPN-сервер ещё не подключены — это пока не рабочая VPN-подписка."
          }, 201);
        }
        const revoke = url.pathname.match(/^\/api\/subscriptions\/([0-9a-f-]+)\/revoke$/i);
        if (request.method === "POST" && revoke) {
          await env.DB.prepare("UPDATE subscriptions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(Math.floor(Date.now() / 1000), revoke[1]).run();
          return json({ ok: true });
        }
        return json({ error: "Не найдено" }, 404);
      } catch {
        return json({ error: "Ошибка сервера или базы данных" }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};