// Genera la clave RSA de firma ciega de una encuesta.
//   node scripts/new-poll-key.mjs <poll-id>
// Escribe la clave pública (va en src/polls.js) por stdout y la privada en
// .poll-keys/<poll-id>.pkcs8 (gitignored). Para producción, añádela al secreto POLL_KEYS:
//   {"<poll-id>": "<contenido del .pkcs8>"}
import { mkdirSync, writeFileSync } from "node:fs";
import { RSABSSA } from "@cloudflare/blindrsa-ts";

const id = process.argv[2];
if (!/^[a-z0-9-]+$/.test(id ?? "")) throw new Error("Uso: node scripts/new-poll-key.mjs <poll-id>");

const suite = RSABSSA.SHA384.PSS.Randomized();
const { publicKey, privateKey } = await suite.generateKey({ publicExponent: Uint8Array.from([1, 0, 1]), modulusLength: 2048 });
const b64 = async (fmt, key) => Buffer.from(await crypto.subtle.exportKey(fmt, key)).toString("base64");

mkdirSync(".poll-keys", { recursive: true });
writeFileSync(`.poll-keys/${id}.pkcs8`, await b64("pkcs8", privateKey), { mode: 0o600 });
console.log(await b64("spki", publicKey));
