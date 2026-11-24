// Identificación con certificado de la FNMT firmado vía Autofirma.
//
// 1. El servidor emite un reto sin estado (HMAC), opcionalmente ligado a `bind`
//    (en el flujo final, el hash del token cegado).
// 2. El usuario firma el reto con Autofirma en formato "NONE" (PKCS#1 v1.5, SHA-256).
// 3. Aquí se verifica: reto auténtico y reciente, certificado emitido por una CA de
//    confianza y vigente, firma del reto con ese certificado, y DNI/NIE válido.
import "reflect-metadata";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(globalThis.crypto);

const SIG_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 30 * 1000;
const OID_SERIAL_NUMBER = "2.5.4.5";
const DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

const enc = new TextEncoder();

export class IdentityError extends Error {
  constructor(code, detail) {
    super(code);
    this.code = code;
    this.detail = detail;
  }
}

/** Acepta base64 estándar o URL-safe, con o sin relleno ni saltos de línea. */
export function b64ToBytes(b64) {
  const clean = String(b64).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function bytesToB64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacKey(secret) {
  if (!secret) throw new IdentityError("config", "Falta el secreto de retos");
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify",
  ]);
}

/** Reto con formato `sv1.<ts>.<nonce>.<bind>.<mac>`. `bind` debe ser base64url (sin puntos). */
export async function createChallenge(secret, bind = "", now = Date.now()) {
  if (!/^[A-Za-z0-9_-]{0,128}$/.test(bind)) throw new IdentityError("bad_bind");
  const nonce = bytesToB64url(crypto.getRandomValues(new Uint8Array(16)));
  const payload = `sv1.${now}.${nonce}.${bind}`;
  const mac = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(payload));
  return `${payload}.${bytesToB64url(new Uint8Array(mac))}`;
}

async function checkChallenge(secret, challenge, now) {
  const parts = String(challenge).split(".");
  if (parts.length !== 5 || parts[0] !== "sv1") throw new IdentityError("bad_challenge");
  const [, ts, , bind, mac] = parts;
  const payload = parts.slice(0, 4).join(".");
  let macBytes;
  try {
    macBytes = b64ToBytes(mac);
  } catch {
    throw new IdentityError("bad_challenge");
  }
  const ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), macBytes, enc.encode(payload));
  if (!ok) throw new IdentityError("bad_challenge");
  const t = Number(ts);
  if (!Number.isFinite(t) || t > now + CLOCK_SKEW_MS || now - t > CHALLENGE_TTL_MS) {
    throw new IdentityError("expired_challenge");
  }
  return { bind };
}

/** Valida `IDCES-12345678Z` (DNI) o `IDCES-X1234567L` (NIE) y su letra de control. */
export function parseSpanishId(serialNumber) {
  const m = /^IDCES-([0-9XYZ])([0-9]{7})([A-Z])$/.exec(serialNumber ?? "");
  if (!m) throw new IdentityError("no_spanish_id");
  const [, first, rest, letter] = m;
  const isNie = "XYZ".includes(first);
  const num = Number((isNie ? "XYZ".indexOf(first) : first) + rest);
  if (DNI_LETTERS[num % 23] !== letter) throw new IdentityError("bad_id_letter");
  return { id: first + rest + letter, tipo: isNie ? "NIE" : "DNI" };
}

export function parseTrustAnchors(pems) {
  return pems.map((pem) => new x509.X509Certificate(pem));
}

const EC_SIZES = { "P-256": 32, "P-384": 48 };

/** Java (Autofirma) da las firmas ECDSA en DER: SEQUENCE { INTEGER r, INTEGER s }. WebCrypto quiere r‖s. */
export function ecdsaDerToRaw(der, size) {
  const fail = () => {
    throw new IdentityError("bad_signature");
  };
  let i = 0;
  const readLen = () => {
    let len = der[i++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n < 1 || n > 2) fail();
      len = 0;
      for (let k = 0; k < n; k++) len = (len << 8) | der[i++];
    }
    return len;
  };
  const readInt = () => {
    if (der[i++] !== 0x02) fail();
    const len = readLen();
    let bytes = der.subarray(i, i + len);
    i += len;
    while (bytes.length > size && bytes[0] === 0) bytes = bytes.subarray(1);
    if (bytes.length > size || bytes.length === 0) fail();
    const out = new Uint8Array(size);
    out.set(bytes, size - bytes.length);
    return out;
  };
  if (der[i++] !== 0x30) fail();
  if (readLen() !== der.length - i) fail();
  const r = readInt();
  const s = readInt();
  if (i !== der.length) fail();
  const raw = new Uint8Array(size * 2);
  raw.set(r);
  raw.set(s, size);
  return raw;
}

// Autofirma compone el algoritmo según la clave: SHA256withRSA (PKCS#1 v1.5) o SHA256withECDSA.
async function verifyChallengeSignature(cert, sigBytes, data) {
  const { name, namedCurve } = cert.publicKey.algorithm;
  try {
    if (name === "ECDSA") {
      const size = EC_SIZES[namedCurve];
      if (!size) throw new IdentityError("unsupported_key");
      const key = await cert.publicKey.export({ name, namedCurve }, ["verify"]);
      return crypto.subtle.verify({ name, hash: "SHA-256" }, key, ecdsaDerToRaw(sigBytes, size), data);
    }
    const key = await cert.publicKey.export(SIG_ALG, ["verify"]);
    return crypto.subtle.verify(SIG_ALG.name, key, sigBytes, data);
  } catch (err) {
    if (err instanceof IdentityError) throw err;
    throw new IdentityError("unsupported_key");
  }
}

function isValidAt(cert, date) {
  return cert.notBefore <= date && date <= cert.notAfter;
}

async function findIssuer(cert, anchors, date) {
  for (const anchor of anchors) {
    if (anchor.subject !== cert.issuer || !isValidAt(anchor, date)) continue;
    if (await cert.verify({ publicKey: anchor.publicKey, signatureOnly: true })) return anchor;
  }
  return null;
}

/**
 * @param {{challenge: string, signature: string, certificate: string}} input  firma y certificado en base64
 * @param {{secret: string, anchors: x509.X509Certificate[], now?: number}} opts
 * @returns {Promise<{id: string, tipo: "DNI"|"NIE", bind: string}>}
 */
export async function verifyIdentity(input, { secret, anchors, now = Date.now() }) {
  const { challenge, signature, certificate } = input ?? {};
  if (typeof challenge !== "string" || typeof signature !== "string" || typeof certificate !== "string") {
    throw new IdentityError("bad_request");
  }
  const { bind } = await checkChallenge(secret, challenge, now);

  let cert;
  try {
    cert = new x509.X509Certificate(b64ToBytes(certificate));
  } catch {
    throw new IdentityError("bad_certificate");
  }
  const date = new Date(now);
  if (!isValidAt(cert, date)) throw new IdentityError("certificate_expired");

  const ku = cert.getExtension(x509.KeyUsagesExtension);
  if (ku && !(ku.usages & x509.KeyUsageFlags.digitalSignature)) throw new IdentityError("bad_key_usage");

  let sigBytes;
  try {
    sigBytes = b64ToBytes(signature);
  } catch {
    throw new IdentityError("bad_signature");
  }
  if (!(await verifyChallengeSignature(cert, sigBytes, enc.encode(challenge)))) {
    throw new IdentityError("bad_signature");
  }

  // Va después de la firma para que, si la CA no está en la lista, el diagnóstico diga cuál es
  // (es información pública del certificado, no identifica a nadie).
  if (!(await findIssuer(cert, anchors, date))) {
    throw new IdentityError("untrusted_issuer", { issuer: cert.issuer, firmaDelRetoValida: true });
  }

  const [serial] = cert.subjectName.getField(OID_SERIAL_NUMBER);
  return { ...parseSpanishId(serial), bind };
}
