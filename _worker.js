
const SESSION_COOKIE = "birthday_session";
const SESSION_DURATION = 8 * 60 * 60;

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/birthday_session=([^;]+)/);

  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const timestamp = Number(parts[0]);
  if (!Number.isFinite(timestamp)) return false;

  const now = Math.floor(Date.now() / 1000);

  if (now < timestamp || now - timestamp > SESSION_DURATION) {
    return false;
  }

  const expected = await sign(parts[0], secret);
  return expected === parts[1];
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 10000) throw new Error("Request terlalu besar");

  return await request.json();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const secret = env.BIRTHDAY_PASSWORD;

    if (!secret || !env.DB || !env.ASSETS) {
      return json({ error: "Konfigurasi server belum lengkap." }, 500);
    }

    // LOGIN
    if (path === "/api/login" && method === "POST") {
      try {
        const body = await readBody(request);

        if (
          typeof body.password !== "string" ||
          body.password !== secret
        ) {
          return json({ success: false, error: "Password salah." }, 401);
        }

        const timestamp = String(Math.floor(Date.now() / 1000));
        const signature = await sign(timestamp, secret);
        const token = timestamp + "." + signature;

        return new Response(
          JSON.stringify({ success: true }),
          {
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-store",
              "Set-Cookie":
                `${SESSION_COOKIE}=${token}; Max-Age=${SESSION_DURATION}; Path=/; HttpOnly; Secure; SameSite=Lax`
            }
          }
        );
      } catch {
        return json({ error: "Permintaan login tidak valid." }, 400);
      }
    }

    // LOGOUT
    if (path === "/api/logout" && method === "POST") {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie":
            `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
        }
      });
    }

    // CEK LOGIN
    const authenticated = await validSession(request, secret);

    // HALAMAN LOGIN TETAP PUBLIK
    if (
      path === "/" ||
      path === "/index.html"
    ) {
      return env.ASSETS.fetch(request);
    }

    // SEMUA HALAMAN DAN API LAIN MEMERLUKAN LOGIN
    if (!authenticated) {
      if (path.startsWith("/api/")) {
        return json({ error: "Silakan login terlebih dahulu." }, 401);
      }

      return Response.redirect(new URL("/", request.url), 302);
    }

    // SIMPAN PESAN
    if (path === "/api/messages" && method === "POST") {
      try {
        const body = await readBody(request);
        const message = typeof body.message === "string"
          ? body.message.trim()
          : "";

        if (!message) {
          return json({ error: "Pesan tidak boleh kosong." }, 400);
        }

        if (message.length > 2000) {
          return json({ error: "Pesan maksimal 2000 karakter." }, 400);
        }

        await env.DB.prepare(
          "INSERT INTO messages (message) VALUES (?)"
        ).bind(message).run();

        return json({ success: true });
      } catch {
        return json({ error: "Gagal menyimpan pesan." }, 500);
      }
    }

    // AMBIL PESAN UNTUK INBOX
    if (path === "/api/messages" && method === "GET") {
      try {
        const result = await env.DB.prepare(
          "SELECT id, message, created_at FROM messages ORDER BY id DESC LIMIT 200"
        ).all();

        return json({
          success: true,
          messages: result.results || []
        });
      } catch {
        return json({ error: "Gagal mengambil pesan." }, 500);
      }
    }

    // HALAMAN WEBSITE LAIN
    return env.ASSETS.fetch(request);
  }
};
