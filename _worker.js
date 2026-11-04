
const SESSION_DURATION = 8 * 60 * 60;
const COOKIE_NAME = "birthday_session";

async function createSignature(value, secret) {
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

async function checkSession(request, secret) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(/birthday_session=([^;]+)/);

  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const timestamp = Number(parts[0]);
  const now = Math.floor(Date.now() / 1000);

  if (!Number.isSafeInteger(timestamp)) return false;
  if (timestamp > now || now - timestamp > SESSION_DURATION) return false;

  const expected = await createSignature(parts[0], secret);

  if (expected.length !== parts[1].length) return false;

  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= expected.charCodeAt(i) ^ parts[1].charCodeAt(i);
  }

  return difference === 0;
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

async function readJSON(request) {
  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > 10000) {
    throw new Error("Request too large");
  }

  return request.json();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const password = env.BIRTHDAY_PASSWORD;

    if (!password || !env.DB || !env.ASSETS) {
      return json({
        error: "Server configuration is incomplete."
      }, 500);
    }

    // LOGIN
    if (path === "/api/login" && method === "POST") {
      try {
        const body = await readJSON(request);

        if (
          typeof body.password !== "string" ||
          body.password.length > 200 ||
          body.password !== password
        ) {
          return json({
            success: false,
            error: "Incorrect password."
          }, 401);
        }

        const timestamp = String(
          Math.floor(Date.now() / 1000)
        );

        const signature = await createSignature(
          timestamp,
          password
        );

        const token = timestamp + "." + signature;

        return new Response(
          JSON.stringify({ success: true }),
          {
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-store",
              "Set-Cookie":
                `${COOKIE_NAME}=${token}; Max-Age=${SESSION_DURATION}; Path=/; HttpOnly; Secure; SameSite=Lax`
            }
          }
        );
      } catch {
        return json({
          error: "Invalid login request."
        }, 400);
      }
    }

    // LOGOUT
    if (path === "/api/logout" && method === "POST") {
      return new Response(
        JSON.stringify({ success: true }),
        {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie":
              `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
          }
        }
      );
    }

    // LOGIN PAGE IS PUBLIC
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(request);
    }

    // CHECK LOGIN FOR PRIVATE PAGES AND API
    const authenticated = await checkSession(request, password);

    if (!authenticated) {
      if (path.startsWith("/api/")) {
        return json({
          error: "Please login first."
        }, 401);
      }

      if (
        path === "/surprise.html" ||
        path === "/letter.html" ||
        path === "/inbox.html"
      ) {
        return Response.redirect(
          new URL("/", request.url),
          302
        );
      }
    }

    // SAVE MESSAGE
    if (path === "/api/messages" && method === "POST") {
      if (!authenticated) {
        return json({ error: "Unauthorized." }, 401);
      }

      try {
        const body = await readJSON(request);

        const message =
          typeof body.message === "string"
            ? body.message.trim()
            : "";

        if (!message) {
          return json({
            error: "Message cannot be empty."
          }, 400);
        }

        if (message.length > 2000) {
          return json({
            error: "Maximum message length is 2000 characters."
          }, 400);
        }

        await env.DB.prepare(
          "INSERT INTO messages (message) VALUES (?)"
        ).bind(message).run();

        return json({
          success: true,
          message: "Message saved successfully."
        });
      } catch {
        return json({
          error: "Failed to save message."
        }, 500);
      }
    }

    // GET MESSAGES
    if (path === "/api/messages" && method === "GET") {
      if (!authenticated) {
        return json({ error: "Unauthorized." }, 401);
      }

      try {
        const result = await env.DB.prepare(
          "SELECT id, message, created_at FROM messages ORDER BY id DESC LIMIT 200"
        ).all();

        return json({
          success: true,
          messages: result.results || []
        });
      } catch {
        return json({
          error: "Failed to retrieve messages."
        }, 500);
      }
    }

    // STATIC ASSETS: PHOTOS, MUSIC, ETC.
    return env.ASSETS.fetch(request);
  }
};
