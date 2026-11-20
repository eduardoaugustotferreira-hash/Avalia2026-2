import { route } from "../../../_lib/http.js";
import { DISCORD_ID } from "../../../_lib/resume.js";
import { cookie, createSession, readCookie, STATE_COOKIE } from "../../../_lib/session.js";

function redirectBack(query, sessionCookie) {
  const headers = new Headers({
    "Cache-Control": "no-store",
    Location: "/?" + query,
    "Referrer-Policy": "no-referrer",
  });
  headers.append("Set-Cookie", cookie(STATE_COOKIE, "", 0));
  if (sessionCookie) headers.append("Set-Cookie", sessionCookie);
  return new Response(null, { status: 302, headers });
}

async function fetchUser(env, code, redirectUri) {
  const token = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    }),
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!token.ok) throw new Error("Discord recusou o código.");
  const { access_token: accessToken } = await token.json();
  if (typeof accessToken !== "string" || !accessToken) throw new Error("Token do Discord ausente.");

  const response = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!response.ok) throw new Error("Perfil do Discord indisponível.");
  const { id, global_name: displayName, username, avatar: hash } = await response.json();
  const name = displayName || username;
  if (typeof id !== "string" || !DISCORD_ID.test(id) || typeof name !== "string" || !name.trim() || name.length > 120) {
    throw new Error("Perfil do Discord inválido.");
  }
  const avatar = typeof hash === "string" && /^(?:a_)?[a-f0-9]{32}$/.test(hash)
    ? `https://cdn.discordapp.com/avatars/${id}/${hash}.png`
    : "https://cdn.discordapp.com/embed/avatars/0.png";
  return { id, username: name, avatar };
}

export const onRequest = route({
  async GET({ request, env }) {
    const url = new URL(request.url);
    const state = url.searchParams.get("state");
    if (!state || !/^[0-9a-f]{64}$/.test(state) || state !== readCookie(request, STATE_COOKIE)) {
      return redirectBack("auth_error=invalid_state");
    }

    const code = url.searchParams.get("code");
    if (url.searchParams.has("error") || !code || code.length > 512) {
      return redirectBack("auth_error=discord_denied");
    }
    if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET || !env.DB) {
      return redirectBack("auth_error=unavailable");
    }

    try {
      const user = await fetchUser(env, code, new URL("/api/auth/discord/callback", url.origin).href);
      return redirectBack("login=success", await createSession(request, env, user));
    } catch {
      return redirectBack("auth_error=discord_failed");
    }
  },
});
