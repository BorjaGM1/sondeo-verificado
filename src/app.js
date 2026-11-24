// API del sondeo. Dos mitades que no comparten nada salvo la clave de la encuesta:
//   - /api/issue: sabe quién eres (certificado) y firma a ciegas un token que no puede ver.
//   - /api/vote:  recibe el token ya desciegado; no sabe de quién es.
import { RSABSSA } from "@cloudflare/blindrsa-ts";
import { createChallenge, verifyIdentity, IdentityError, b64ToBytes, bytesToB64url } from "./identity.js";

const enc = new TextEncoder();
const PSS = { name: "RSA-PSS", hash: "SHA-384" };
const TOKEN_BYTES = 64; // 32 de aleatoriedad que añade prepare() + 32 del mensaje

class ApiError extends Error {
  constructor(status, code, extra) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch {
    return {};
  }
}

function decode(value, code) {
  if (typeof value !== "string" || !value) throw new ApiError(400, code);
  try {
    return b64ToBytes(value);
  } catch {
    throw new ApiError(400, code);
  }
}

async function sha256b64url(bytes) {
  return bytesToB64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

async function hmacB64url(secret, text) {
  if (!secret) throw new ApiError(500, "config");
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return bytesToB64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(text))));
}

const publicPoll = ({ id, title, question, options, opensAt, closesAt, embargo, allowNie, minVotes, publicKey }) => ({
  id, title, question, options, opensAt, closesAt, embargo, allowNie, minVotes, publicKey,
});

/**
 * @param {{anchors: any[], polls: any[], rsaRaw?: boolean, now?: () => number}} deps
 */
export function createApp({ anchors, polls, rsaRaw = false, now = Date.now }) {
  const suite = RSABSSA.SHA384.PSS.Randomized({ supportsRSARAW: rsaRaw });
  const byId = new Map(polls.map((p) => [p.id, p]));
  const keyCache = new Map();

  function getPoll(id) {
    const poll = byId.get(id);
    if (!poll) throw new ApiError(404, "poll_not_found");
    return poll;
  }

  function assertOpen(poll) {
    const t = now();
    if (t < Date.parse(poll.opensAt) || t > Date.parse(poll.closesAt)) throw new ApiError(403, "poll_closed");
  }

  // Con pocos votos el anonimato no protege: si solo ha votado una persona conocida, su papeleta
  // es la única. No se publica nada (ni recuento ni tablón) hasta llegar al mínimo.
  async function assertPublishable(poll, env) {
    const t = now();
    const w = poll.embargo.find((e) => t >= Date.parse(e.from) && t <= Date.parse(e.until));
    if (w) throw new ApiError(451, "embargo_loreg", { until: w.until });
    const minVotes = poll.minVotes ?? 100;
    const { n } = await env.DB.prepare("SELECT COUNT(*) AS n FROM ballots WHERE poll_id = ?").bind(poll.id).first();
    if (n < minVotes) throw new ApiError(403, "below_min_votes", { votes: n, minVotes });
  }

  // Las claves tienen que ser exportables: la librería hace la aritmética RSA por su cuenta.
  async function keys(poll, env) {
    if (!keyCache.has(poll.id)) {
      let pkcs8;
      try {
        pkcs8 = JSON.parse(env.POLL_KEYS ?? "{}")[poll.id];
      } catch {
        pkcs8 = undefined;
      }
      if (!pkcs8) throw new ApiError(500, "config");
      keyCache.set(poll.id, {
        publicKey: await crypto.subtle.importKey("spki", b64ToBytes(poll.publicKey), PSS, true, ["verify"]),
        privateKey: await crypto.subtle.importKey("pkcs8", b64ToBytes(pkcs8), PSS, true, ["sign"]),
      });
    }
    return keyCache.get(poll.id);
  }

  async function issue(body, env) {
    const poll = getPoll(body.pollId);
    assertOpen(poll);
    const blindedMsg = decode(body.blindedMsg, "bad_blinded_msg");
    if (blindedMsg.length !== 256) throw new ApiError(400, "bad_blinded_msg");

    const { id, tipo, bind } = await verifyIdentity(body, { secret: env.CHALLENGE_SECRET, anchors, now: now() });
    if (tipo === "NIE" && !poll.allowNie) throw new ApiError(403, "nie_not_allowed");
    // El reto firmado con el certificado incluía hash(blindedMsg): esta firma autoriza exactamente este token.
    if (bind !== (await sha256b64url(blindedMsg))) throw new ApiError(400, "bind_mismatch");

    const { privateKey } = await keys(poll, env);
    const blindSignature = await suite.blindSign(privateKey, blindedMsg);

    // Se firma antes de registrar para no quemar el nullifier si la firma falla. Si dos peticiones
    // del mismo DNI llegan a la vez, solo la que inserta primero recibe la firma.
    const nullifier = await hmacB64url(env.NULLIFIER_SECRET, `${poll.id}:${id}`);
    const { meta } = await env.DB.prepare("INSERT OR IGNORE INTO nullifiers (poll_id, nullifier) VALUES (?, ?)")
      .bind(poll.id, nullifier)
      .run();
    if (!meta.changes) throw new ApiError(409, "already_issued");

    return json({ ok: true, blindSignature: bytesToB64url(blindSignature) });
  }

  async function vote(body, env) {
    const poll = getPoll(body.pollId);
    assertOpen(poll);
    const token = decode(body.token, "bad_token");
    const signature = decode(body.signature, "bad_token");
    if (token.length !== TOKEN_BYTES) throw new ApiError(400, "bad_token");
    const { publicKey } = await keys(poll, env);
    let valid = false;
    try {
      valid = await suite.verify(publicKey, signature, token);
    } catch {
      valid = false;
    }
    if (!valid) throw new ApiError(400, "bad_token");

    if (!poll.options.includes(body.answer)) throw new ApiError(400, "bad_answer");

    const { meta } = await env.DB.prepare(
      "INSERT OR IGNORE INTO ballots (poll_id, token, signature, answer) VALUES (?, ?, ?, ?)",
    )
      .bind(poll.id, bytesToB64url(token), bytesToB64url(signature), body.answer)
      .run();
    if (!meta.changes) throw new ApiError(409, "already_voted");
    return json({ ok: true });
  }

  async function results(poll, env) {
    await assertPublishable(poll, env);
    const issued = await env.DB.prepare("SELECT COUNT(*) AS n FROM nullifiers WHERE poll_id = ?").bind(poll.id).first();
    const { results: rows } = await env.DB.prepare(
      "SELECT answer, COUNT(*) AS n FROM ballots WHERE poll_id = ? GROUP BY answer",
    )
      .bind(poll.id)
      .all();
    const counts = Object.fromEntries(poll.options.map((o) => [o, 0]));
    for (const r of rows) counts[r.answer] = r.n;
    const votes = rows.reduce((s, r) => s + r.n, 0);
    return json({ pollId: poll.id, tokensIssued: issued.n, votes, counts });
  }

  async function ballots(poll, env) {
    await assertPublishable(poll, env);
    const { results: rows } = await env.DB.prepare(
      "SELECT token, signature, answer FROM ballots WHERE poll_id = ? ORDER BY token",
    )
      .bind(poll.id)
      .all();
    return json({ pollId: poll.id, publicKey: poll.publicKey, scheme: "RSABSSA-SHA384-PSS-Randomized", ballots: rows });
  }

  return {
    async fetch(request, env) {
      const { pathname } = new URL(request.url);
      const route = `${request.method} ${pathname}`;
      try {
        if (route === "GET /api/polls") return json({ polls: polls.map(publicPoll) });
        if (route === "POST /api/challenge") {
          const { bind = "" } = await readJson(request);
          return json({ challenge: await createChallenge(env.CHALLENGE_SECRET, bind, now()) });
        }
        if (route === "POST /api/issue") return await issue(await readJson(request), env);
        if (route === "POST /api/vote") return await vote(await readJson(request), env);

        const m = /^GET \/api\/polls\/([a-z0-9-]+)\/(results|ballots)$/.exec(route);
        if (m) {
          const poll = getPoll(m[1]);
          return m[2] === "results" ? await results(poll, env) : await ballots(poll, env);
        }
        return json({ error: "not_found" }, 404);
      } catch (err) {
        if (err instanceof ApiError) return json({ ok: false, error: err.code, ...err.extra }, err.status);
        if (err instanceof IdentityError) {
          return json({ ok: false, error: err.code, detail: err.detail }, err.code === "config" ? 500 : 400);
        }
        throw err;
      }
    },
  };
}
