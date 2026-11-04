function response(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

async function sign(value, password) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
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
    .replace(/=+$/,"");
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(/(?:^|;\s*)birthday_session=([^;]+)/);
  return match ? match[1] : null;
}

async function validSession(request, password) {
  const token = getCookie(request);
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  try {
    const expiry = atob(parts[0]);

    if (!/^\d+$/.test(expiry) || Number(expiry) < Date.now()) {
      return false;
    }

    return (await sign(parts[0], password)) === parts[1];
  } catch (e) {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // LOGIN
    if (path === "/api/login") {
      if (request.method !== "POST") {
        return response({ success: false }, 405);
      }

      try {
        const body = await request.json();

        if (
          typeof body.password !== "string" ||
          body.password.length > 200
        ) {
          return response({ success: false }, 400);
        }

        if (body.password !== env.BIRTHDAY_PASSWORD) {
          return response({ success: false }, 401);
        }

        const expiry = String(Date.now() + 8 * 60 * 60 * 1000);
        const payload = btoa(expiry);
        const signature = await sign(payload, env.BIRTHDAY_PASSWORD);
        const token = payload + "." + signature;

        return response({ success: true }, 200, {
          "Set-Cookie":
            `birthday_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`
        });
      } catch (e) {
        return response({ success: false }, 400);
      }
    }

    // KIRIM PESAN - BOLEH TANPA LOGIN
    if (path === "/api/messages" && request.method === "POST") {
      try {
        const body = await request.json();

        const sender = typeof body.sender_name === "string"
          ? body.sender_name.trim().slice(0, 60)
          : "Anonymous";

        const message = typeof body.message === "string"
          ? body.message.trim()
          : "";

        if (!message || message.length > 2000) {
          return response({
            success: false,
            error: "Pesan harus diisi dan maksimal 2000 karakter."
          }, 400);
        }

        if (!env.DB) {
          return response({ success: false, error: "Database belum terhubung." }, 503);
        }

        await env.DB.prepare(
          "INSERT INTO messages (sender_name, message) VALUES (?, ?)"
        ).bind(sender || "Anonymous", message).run();

        return response({ success: true });
      } catch (e) {
        return response({ success: false, error: "Gagal menyimpan pesan." }, 500);
      }
    }

    // BACA INBOX - HANYA DENGAN PASSWORD ADMIN
    if (path === "/api/messages" && request.method === "GET") {
      if (!env.INBOX_PASSWORD) {
        return response({ success: false, error: "Password inbox belum diatur." }, 503);
      }

      const adminPassword = request.headers.get("X-Inbox-Password");

      if (adminPassword !== env.INBOX_PASSWORD) {
        return response({ success: false, error: "Password inbox salah." }, 401);
      }

      try {
        const result = await env.DB.prepare(
          "SELECT id, sender_name, message, created_at FROM messages ORDER BY id DESC LIMIT 200"
        ).all();

        return response({
          success: true,
          messages: result.results || []
        });
      } catch (e) {
        return response({ success: false, error: "Gagal membaca pesan." }, 500);
      }
    }

    // HALAMAN LOGIN BOLEH DIBUKA TANPA PASSWORD
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(request);
    }

    // HALAMAN DAN FILE LAINNYA WAJIB LOGIN
    if (!(await validSession(request, env.BIRTHDAY_PASSWORD))) {
      return new Response("Silakan login terlebih dahulu.", {
        status: 401,
        headers: { "Content-Type": "text/plain" }
      });
    }

    return env.ASSETS.fetch(request);
  }
};
