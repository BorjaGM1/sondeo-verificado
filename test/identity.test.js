// Simula lo que hace Autofirma con formato "NONE": firma PKCS#1 v1.5 SHA-256 del reto,
// con un certificado emitido por una CA de prueba que imita a la FNMT.
import { test } from "node:test";
import assert from "node:assert/strict";
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { createChallenge, verifyIdentity, parseSpanishId } from "../src/identity.js";

const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const SECRET = "secreto-de-prueba";
const DAY = 86400000;
const enc = new TextEncoder();

const genKeys = () => crypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
const b64 = (buf) => Buffer.from(buf).toString("base64");

async function makeCa(name) {
  const keys = await genKeys();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + 365 * DAY),
    keys,
    signingAlgorithm: ALG,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  });
  return { cert, keys };
}

async function makeUser(ca, serial, { notAfter = new Date(Date.now() + 365 * DAY) } = {}) {
  const keys = await genKeys();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: `CN=ESPAÑOL ESPAÑOL JUAN - ${serial.slice(6)}, 2.5.4.5=${serial}, C=ES`,
    issuer: ca.cert.subject,
    notBefore: new Date(Date.now() - DAY),
    notAfter,
    signingKey: ca.keys.privateKey,
    publicKey: keys.publicKey,
    signingAlgorithm: ALG,
    extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)],
  });
  return { cert, keys };
}

const sign = async (keys, challenge) => b64(await crypto.subtle.sign(ALG.name, keys.privateKey, enc.encode(challenge)));

const fnmt = await makeCa("CN=AC FNMT Usuarios (prueba), O=FNMT-RCM, C=ES");
const anchors = [fnmt.cert];
const opts = { secret: SECRET, anchors };

async function attempt({ user, challenge, signWith, mutate } = {}) {
  user ??= await makeUser(fnmt, "IDCES-12345678Z");
  challenge ??= await createChallenge(SECRET, "abc");
  const input = { challenge, signature: await sign(signWith ?? user.keys, challenge), certificate: b64(user.cert.rawData) };
  return verifyIdentity(mutate ? mutate(input) : input, opts);
}

const rejects = (p, code) => assert.rejects(p, (e) => e.code === code);

test("acepta un DNI firmado correctamente y devuelve el bind del reto", async () => {
  assert.deepEqual(await attempt(), { id: "12345678Z", tipo: "DNI", bind: "abc" });
});

test("acepta NIE y lo marca como tal", async () => {
  const user = await makeUser(fnmt, "IDCES-X1234567L");
  assert.equal((await attempt({ user })).tipo, "NIE");
});

test("acepta firma y certificado en base64 URL-safe (como a veces devuelve Autofirma)", async () => {
  const urlsafe = (s) => s.replace(/\+/g, "-").replace(/\//g, "_");
  const r = await attempt({ mutate: (i) => ({ ...i, signature: urlsafe(i.signature), certificate: urlsafe(i.certificate) }) });
  assert.equal(r.id, "12345678Z");
});

test("rechaza un reto manipulado", async () => {
  const challenge = (await createChallenge(SECRET, "abc")).replace(".abc.", ".xyz.");
  await rejects(attempt({ challenge }), "bad_challenge");
});

test("rechaza un reto caducado", async () => {
  const challenge = await createChallenge(SECRET, "", Date.now() - 10 * 60 * 1000);
  await rejects(attempt({ challenge }), "expired_challenge");
});

test("rechaza un certificado de una CA que no es de confianza", async () => {
  const fake = await makeCa("CN=AC FNMT Usuarios (prueba), O=FNMT-RCM, C=ES");
  await assert.rejects(attempt({ user: await makeUser(fake, "IDCES-12345678Z") }), (e) => {
    assert.equal(e.code, "untrusted_issuer");
    assert.deepEqual(e.detail, { issuer: fake.cert.subject, firmaDelRetoValida: true });
    return true;
  });
});

test("rechaza un certificado caducado", async () => {
  const user = await makeUser(fnmt, "IDCES-12345678Z", { notAfter: new Date(Date.now() - 1000) });
  await rejects(attempt({ user }), "certificate_expired");
});

test("rechaza una firma hecha con otra clave", async () => {
  await rejects(attempt({ signWith: await genKeys() }), "bad_signature");
});

test("rechaza una firma sobre otro reto", async () => {
  const user = await makeUser(fnmt, "IDCES-12345678Z");
  const other = await createChallenge(SECRET, "abc");
  await rejects(attempt({ user, mutate: (i) => ({ ...i, challenge: other }) }), "bad_signature");
});

test("rechaza un DNI con letra incorrecta", async () => {
  await rejects(attempt({ user: await makeUser(fnmt, "IDCES-12345678A") }), "bad_id_letter");
});

// Imita a AC USUARIOS G2: CA con clave P-256 que firma con ECDSA-SHA384, y usuario con clave P-256.
// Autofirma firma con SHA256withECDSA y devuelve la firma en DER (formato Java).
const EC_CA_ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-384" };
const EC_KEY = { name: "ECDSA", namedCurve: "P-256" };

function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.subarray(i);
    if (b[0] & 0x80) b = Uint8Array.of(0, ...b);
    return [0x02, b.length, ...b];
  };
  const half = raw.length / 2;
  const body = [...int(raw.subarray(0, half)), ...int(raw.subarray(half))];
  return Uint8Array.of(0x30, body.length, ...body);
}

test("acepta certificados EC como los de AC USUARIOS G2 con firma DER", async () => {
  const caKeys = await crypto.subtle.generateKey(EC_KEY, true, ["sign", "verify"]);
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "03", name: "CN=AC USUARIOS G2 (prueba), O=FNMT-RCM, C=ES",
    notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + 365 * DAY),
    keys: caKeys, signingAlgorithm: EC_CA_ALG,
  });
  const keys = await crypto.subtle.generateKey(EC_KEY, true, ["sign", "verify"]);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: "04", subject: "CN=JUAN, 2.5.4.5=IDCES-12345678Z, C=ES", issuer: caCert.subject,
    notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + 365 * DAY),
    signingKey: caKeys.privateKey, publicKey: keys.publicKey, signingAlgorithm: EC_CA_ALG,
  });
  const challenge = await createChallenge(SECRET);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, enc.encode(challenge)));
  const input = { challenge, signature: b64(rawToDer(raw)), certificate: b64(cert.rawData) };
  const ecOpts = { secret: SECRET, anchors: [caCert] };

  assert.equal((await verifyIdentity(input, ecOpts)).id, "12345678Z");
  const flipped = rawToDer(raw);
  flipped[flipped.length - 1] ^= 1;
  await rejects(verifyIdentity({ ...input, signature: b64(flipped) }, ecOpts), "bad_signature");
});

test("las CAs reales de la FNMT cargan y están vigentes", async () => {
  const { FNMT_CA_PEMS } = await import("../src/trust.js");
  const { parseTrustAnchors } = await import("../src/identity.js");
  const cas = parseTrustAnchors(FNMT_CA_PEMS);
  assert.deepEqual(cas.map((c) => c.subjectName.getField("CN")[0]), ["AC FNMT Usuarios", "AC USUARIOS G2"]);
  for (const c of cas) assert.ok(c.notAfter > new Date());
});

test("parseSpanishId valida formato", () => {
  assert.throws(() => parseSpanishId("12345678Z"), (e) => e.code === "no_spanish_id");
  assert.deepEqual(parseSpanishId("IDCES-00000000T"), { id: "00000000T", tipo: "DNI" });
});
