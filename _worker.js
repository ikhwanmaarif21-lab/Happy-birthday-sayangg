
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

  return btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(
    /(?:^|;\s*)birthday_session=([^;]+)/
  );

  return match ? match[1] : null;
}

async function validSession(request, password) {
  const token = getCookie(request);

  if (!token || !password) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  try {
    const expiry = atob(parts[0]);

    if (
      !/^\d+$/.test(expiry) ||
      Number(expiry) < Date.now()
    ) {
      return false;
    }

    const expected = await sign(parts[0], password);

    return expected === parts[1];
  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // LOGIN
    if (path === "/api/login") {
      if (method !== "POST") {
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

        if (
          !env.BIRTHDAY_PASSWORD ||
          body.password !== env.BIRTHDAY_PASSWORD
        ) {
          return response({ success: false }, 401);
        }

        const expiry = String(
          Date.now() + 8 * 60 * 60 * 1000
        );

        const payload = btoa(expiry);
        const signature = await sign(
          payload,
          env.BIRTHDAY_PASSWORD
        );

        const token = payload + "." + signature;

        return response(
          { success: true },
          200,
          {
            "Set-Cookie":
              `birthday_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`
          }
        );
      } catch {
        return response({ success: false }, 400);
      }
    }

    // LOGIN PAGE: PUBLIC
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(request);
    }

    // CHECK SESSION
    const authenticated = await validSession(
      request,
      env.BIRTHDAY_PASSWORD
    );

    if (!authenticated) {
      if (path.startsWith("/api/")) {
        return response(
          { success: false, error: "Unauthorized" },
          401
        );
      }

      return new Response(
        "Silakan login terlebih dahulu.",
        {
          status: 401,
          headers: {
            "Content-Type": "text/plain"
          }
        }
      );
    }

    // SAVE MESSAGE
    if (path === "/api/messages" && method === "POST") {
      try {
        const body = await request.json();

        const message =
          typeof body.message === "string"
            ? body.message.trim()
            : "";

        if (!message) {
          return response({
            success: false,
            error: "Pesan tidak boleh kosong."
          }, 400);
        }

        if (message.length > 2000) {
          return response({
            success: false,
            error: "Pesan maksimal 2000 karakter."
          }, 400);
        }

        await env.DB.prepare(
          "INSERT INTO messages (message) VALUES (?)"
        )
          .bind(message)
          .run();

        return response({
          success: true,
          message: "Pesan berhasil disimpan ❤️"
        });
      } catch (error) {
        return response({
          success: false,
          error: "Gagal menyimpan pesan."
        }, 500);
      }
    }

    // GET MESSAGES
    if (path === "/api/messages" && method === "GET") {
      try {
        const result = await env.DB.prepare(
          "SELECT id, message, created_at FROM messages ORDER BY id DESC LIMIT 200"
        ).all();

        return response({
          success: true,
          messages: result.results || []
        });
      } catch (error) {
        return response({
          success: false,
          error: "Gagal mengambil pesan."
        }, 500);
      }
    }

    // OTHER HTTP METHODS
    if (path === "/api/messages") {
      return response({
        success: false,
        error: "Method not allowed."
      }, 405);
    }

    // PROTECTED STATIC ASSETS
    return env.ASSETS.fetch(request);
  }
};
