import { createChallenge, verifyIdentity, parseTrustAnchors, IdentityError } from "./identity.js";
import { FNMT_CA_PEMS } from "./trust.js";

const anchors = parseTrustAnchors(FNMT_CA_PEMS);

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (request.method !== "POST") return json({ error: "not_found" }, 404);

    try {
      if (pathname === "/api/challenge") {
        const body = (await readJson(request)) ?? {};
        return json({ challenge: await createChallenge(env.CHALLENGE_SECRET, body.bind ?? "") });
      }

      if (pathname === "/api/verify") {
        const { id, tipo } = await verifyIdentity(await readJson(request), {
          secret: env.CHALLENGE_SECRET,
          anchors,
        });
        // Spike: solo devolvemos el DNI enmascarado para comprobar que funciona. No se guarda nada.
        return json({ ok: true, tipo, id: "*".repeat(id.length - 4) + id.slice(-4) });
      }
    } catch (err) {
      if (err instanceof IdentityError) {
        return json({ ok: false, error: err.code, detail: err.detail }, err.code === "config" ? 500 : 400);
      }
      throw err;
    }

    return json({ error: "not_found" }, 404);
  },
};
