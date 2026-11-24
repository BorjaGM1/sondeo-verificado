// Flujo completo: identificarse → token ciego → votar → resultados y tablón.
// D1 se simula con node:sqlite usando la migración real.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { RSABSSA } from "@cloudflare/blindrsa-ts";
import { createApp } from "../src/app.js";
import { DEMOGRAPHICS } from "../src/polls.js";

const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const DAY = 86400000;
const enc = new TextEncoder();
const b64 = (buf) => Buffer.from(buf).toString("base64");
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64url"));

function fakeD1() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL("../migrations/0001_init.sql", import.meta.url), "utf8"));
  return {
    prepare(sql) {
      let args = [];
      const stmt = {
        bind: (...a) => ((args = a), stmt),
        run: async () => ({ meta: { changes: Number(db.prepare(sql).run(...args).changes) } }),
        first: async () => db.prepare(sql).get(...args) ?? null,
        all: async () => ({ results: db.prepare(sql).all(...args) }),
      };
      return stmt;
    },
    raw: db,
  };
}

const suite = RSABSSA.SHA384.PSS.Randomized();
const pollKeys = await suite.generateKey({ publicExponent: Uint8Array.from([1, 0, 1]), modulusLength: 2048 });
const spki = b64(await crypto.subtle.exportKey("spki", pollKeys.publicKey));
const pkcs8 = b64(await crypto.subtle.exportKey("pkcs8", pollKeys.privateKey));

const caKeys = await crypto.subtle.generateKey(RSA, true, ["sign", "verify"]);
const ca = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01", name: "CN=AC FNMT Usuarios (prueba), C=ES",
  notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + 365 * DAY),
  keys: caKeys, signingAlgorithm: RSA, extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
});

async function citizen(serial) {
  const keys = await crypto.subtle.generateKey(RSA, true, ["sign", "verify"]);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: String(Math.floor(Math.random() * 1e9)), subject: `CN=PRUEBA, 2.5.4.5=${serial}, C=ES`, issuer: ca.subject,
    notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + 365 * DAY),
    signingKey: caKeys.privateKey, publicKey: keys.publicKey, signingAlgorithm: RSA,
  });
  // Lo que hace Autofirma: firma PKCS#1 del reto con la clave del certificado.
  return { sign: async (text) => b64(await crypto.subtle.sign(RSA.name, keys.privateKey, enc.encode(text))), cert: b64(cert.rawData) };
}

const POLL = {
  id: "test", title: "Test", question: "¿?", options: ["A", "B", "No lo sé"],
  opensAt: new Date(Date.now() - DAY).toISOString(), closesAt: new Date(Date.now() + DAY).toISOString(),
  embargo: [], allowNie: false, publicKey: spki,
};

function setup({ poll = POLL } = {}) {
  const app = createApp({ anchors: [ca], polls: [poll], demographics: DEMOGRAPHICS });
  const DB = fakeD1();
  const env = { DB, CHALLENGE_SECRET: "c", NULLIFIER_SECRET: "n", POLL_KEYS: JSON.stringify({ [poll.id]: pkcs8 }) };
  const call = async (method, path, body) => {
    const res = await app.fetch(new Request(`http://x${path}`, { method, body: body && JSON.stringify(body) }), env);
    return { status: res.status, body: await res.json() };
  };
  return { call, DB, env };
}

// Lo que hace el navegador (client/main.js), paso a paso.
async function getToken(call, person, { pollId = "test", tamperBind = false } = {}) {
  const token = suite.prepare(crypto.getRandomValues(new Uint8Array(32)));
  const { blindedMsg, inv } = await suite.blind(pollKeys.publicKey, token);
  const bindSource = tamperBind ? crypto.getRandomValues(new Uint8Array(256)) : blindedMsg;
  const bind = b64url(await crypto.subtle.digest("SHA-256", bindSource));
  const { body: { challenge } } = await call("POST", "/api/challenge", { bind });
  const res = await call("POST", "/api/issue", {
    pollId, challenge, signature: await person.sign(challenge), certificate: person.cert, blindedMsg: b64url(blindedMsg),
  });
  if (!res.body.ok) return { res };
  const signature = await suite.finalize(pollKeys.publicKey, token, unb64(res.body.blindSignature), inv);
  return { res, token: b64url(token), signature: b64url(signature) };
}

const demo = { edad: "35-44", sexo: "Mujer", ccaa: "Madrid", recuerdo: "No voté" };

test("flujo completo: token ciego, voto, resultados y tablón", async () => {
  const { call, DB } = setup();
  const { res, token, signature } = await getToken(call, await citizen("IDCES-12345678Z"));
  assert.equal(res.status, 200);

  assert.deepEqual((await call("POST", "/api/vote", { pollId: "test", token, signature, answer: "B", ...demo })).body, { ok: true });

  const results = (await call("GET", "/api/polls/test/results")).body;
  assert.equal(results.tokensIssued, 1);
  assert.equal(results.votes, 1);
  assert.deepEqual(results.counts, { A: 0, B: 1, "No lo sé": 0 });

  const board = (await call("GET", "/api/polls/test/ballots")).body;
  assert.equal(board.ballots.length, 1);
  assert.equal(board.ballots[0].token, token);
  // Cualquiera puede verificar una papeleta del tablón con la clave pública.
  const pk = await crypto.subtle.importKey("spki", unb64(board.publicKey), { name: "RSA-PSS", hash: "SHA-384" }, true, ["verify"]);
  assert.ok(await suite.verify(pk, unb64(board.ballots[0].signature), unb64(board.ballots[0].token)));

  // En la base de datos no hay ni rastro del DNI.
  const dump = JSON.stringify(DB.raw.prepare("SELECT * FROM nullifiers").all());
  assert.ok(!dump.includes("12345678"));
});

test("un DNI solo saca un token por encuesta", async () => {
  const { call } = setup();
  const person = await citizen("IDCES-12345678Z");
  assert.equal((await getToken(call, person)).res.status, 200);
  const again = await getToken(call, person);
  assert.equal(again.res.status, 409);
  assert.equal(again.res.body.error, "already_issued");
  // Con otro certificado del mismo DNI (renovado) tampoco.
  assert.equal((await getToken(call, await citizen("IDCES-12345678Z"))).res.status, 409);
  // Otra persona sí.
  assert.equal((await getToken(call, await citizen("IDCES-00000000T"))).res.status, 200);
});

test("un token solo vota una vez", async () => {
  const { call } = setup();
  const { token, signature } = await getToken(call, await citizen("IDCES-12345678Z"));
  await call("POST", "/api/vote", { pollId: "test", token, signature, answer: "A", ...demo });
  const again = await call("POST", "/api/vote", { pollId: "test", token, signature, answer: "B", ...demo });
  assert.equal(again.status, 409);
  assert.equal(again.body.error, "already_voted");
});

test("rechaza tokens no firmados por la encuesta", async () => {
  const { call } = setup();
  const { token, signature } = await getToken(call, await citizen("IDCES-12345678Z"));
  const forged = b64url(crypto.getRandomValues(new Uint8Array(64)));
  assert.equal((await call("POST", "/api/vote", { pollId: "test", token: forged, signature, answer: "A", ...demo })).body.error, "bad_token");
  const otherSig = b64url(crypto.getRandomValues(new Uint8Array(256)));
  assert.equal((await call("POST", "/api/vote", { pollId: "test", token, signature: otherSig, answer: "A", ...demo })).body.error, "bad_token");
});

test("la firma del certificado debe autorizar exactamente ese token cegado", async () => {
  const { call } = setup();
  const { res } = await getToken(call, await citizen("IDCES-12345678Z"), { tamperBind: true });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "bind_mismatch");
});

test("NIE no puede votar si la encuesta no lo permite", async () => {
  const { call } = setup();
  const { res } = await getToken(call, await citizen("IDCES-X1234567L"));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, "nie_not_allowed");
});

test("valida respuesta y demografía", async () => {
  const { call } = setup();
  const { token, signature } = await getToken(call, await citizen("IDCES-12345678Z"));
  assert.equal((await call("POST", "/api/vote", { pollId: "test", token, signature, answer: "Z", ...demo })).body.error, "bad_answer");
  assert.equal((await call("POST", "/api/vote", { pollId: "test", token, signature, answer: "A", ...demo, ccaa: "Narnia" })).body.error, "bad_ccaa");
});

test("encuesta cerrada: ni tokens ni votos", async () => {
  const closed = { ...POLL, closesAt: new Date(Date.now() - 1000).toISOString() };
  const { call } = setup({ poll: closed });
  const { res } = await getToken(call, await citizen("IDCES-12345678Z"));
  assert.equal(res.body.error, "poll_closed");
});

test("embargo LOREG: no se publican resultados ni papeletas", async () => {
  const until = new Date(Date.now() + DAY).toISOString();
  const { call } = setup({ poll: { ...POLL, embargo: [{ from: new Date(Date.now() - 1000).toISOString(), until }] } });
  for (const path of ["/api/polls/test/results", "/api/polls/test/ballots"]) {
    const r = await call("GET", path);
    assert.equal(r.status, 451);
    assert.deepEqual(r.body, { ok: false, error: "embargo_loreg", until });
  }
});
