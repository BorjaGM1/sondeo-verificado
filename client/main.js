// Cliente. Aquí está la garantía de anonimato: el token se genera y se ciega en este navegador,
// así que el servidor que ve tu certificado nunca ve el token con el que votas.
/* global AutoScript */
import { RSABSSA } from "@cloudflare/blindrsa-ts";

const suite = RSABSSA.SHA384.PSS.Randomized();
const PSS = { name: "RSA-PSS", hash: "SHA-384" };
const $ = (id) => document.getElementById(id);

const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

const ERRORS = {
  already_issued: "Ya sacaste un token para esta encuesta (quizá en otro navegador).",
  already_voted: "Este token ya ha votado.",
  nie_not_allowed: "Esta encuesta es para personas con DNI (nacionalidad española).",
  poll_closed: "La encuesta no está abierta.",
  untrusted_issuer: "Tu certificado no es de persona física de la FNMT.",
  certificate_expired: "Tu certificado está caducado.",
};
const explain = (r) => ERRORS[r.error] ?? `Error: ${r.error}`;

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body && JSON.stringify(body),
  });
  return res.json();
}

const store = {
  key: (pollId) => `sondeo:${pollId}`,
  get(pollId) {
    try {
      return JSON.parse(localStorage.getItem(this.key(pollId))) ?? {};
    } catch {
      return {};
    }
  },
  set(pollId, value) {
    try {
      localStorage.setItem(this.key(pollId), JSON.stringify({ ...this.get(pollId), ...value }));
    } catch {
      /* sin almacenamiento: el token solo vive en esta pestaña */
    }
  },
};

function status(el, text, kind = "") {
  el.textContent = text;
  el.className = `status ${kind}`;
}

function select(name, label, options) {
  const opts = options.map((o) => `<option>${o}</option>`).join("");
  return `<label>${label}<select name="${name}" required><option value="">—</option>${opts}</select></label>`;
}

async function main() {
  const { polls, demographics } = await api("GET", "/api/polls");
  const wanted = new URLSearchParams(location.search).get("encuesta");
  const poll = polls.find((p) => p.id === wanted) ?? polls[0];
  const publicKey = await crypto.subtle.importKey("spki", fromB64(poll.publicKey), PSS, true, ["verify"]);
  let state = { ...store.get(poll.id) };

  $("title").textContent = poll.title;
  $("form-fields").innerHTML = [
    `<fieldset><legend>${poll.question}</legend>${poll.options
      .map((o) => `<label class="opt"><input type="radio" name="answer" value="${o}" required> ${o}</label>`)
      .join("")}</fieldset>`,
    `<p class="hint">Para poder ponderar el resultado (se publica junto a tu voto, sin nada que te identifique):</p>`,
    select("edad", "Edad", demographics.edad),
    select("sexo", "Sexo", demographics.sexo),
    select("ccaa", "Comunidad autónoma", demographics.ccaa),
    select("recuerdo", "¿Qué votaste en las generales de julio de 2023?", demographics.recuerdo),
  ].join("");

  function render() {
    $("step-identify").hidden = !!state.token;
    $("step-vote").hidden = !state.token || !!state.voted;
    $("step-done").hidden = !state.voted;
    if (state.voted) $("my-token").textContent = state.token.slice(0, 16) + "…";
  }

  // Paso 1: token ciego autorizado por tu certificado.
  $("identify").addEventListener("click", async () => {
    const out = $("identify-status");
    try {
      const token = suite.prepare(crypto.getRandomValues(new Uint8Array(32)));
      const { blindedMsg, inv } = await suite.blind(publicKey, token);
      const { challenge } = await api("POST", "/api/challenge", { bind: b64url(await sha256(blindedMsg)) });
      status(out, "Abriendo Autofirma… elige tu certificado.");

      AutoScript.sign(btoa(challenge), "SHA256withRSA", "NONE", "", async (signature, certificate) => {
        status(out, "Comprobando tu certificado…");
        const r = await api("POST", "/api/issue", { pollId: poll.id, challenge, signature, certificate, blindedMsg: b64url(blindedMsg) });
        if (!r.ok) return status(out, explain(r), "error");
        const sig = await suite.finalize(publicKey, token, fromB64(r.blindSignature), inv);
        state = { token: b64url(token), signature: b64url(sig) };
        store.set(poll.id, state);
        render();
      }, (type, message) => status(out, `Autofirma: ${message || type}`, "error"));
    } catch (e) {
      status(out, `Error: ${e.message}`, "error");
    }
  });

  // Paso 2: votar con el token (puede ser mucho después).
  $("vote-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const data = Object.fromEntries(new FormData(ev.target));
    const r = await api("POST", "/api/vote", { pollId: poll.id, token: state.token, signature: state.signature, ...data });
    if (!r.ok && r.error !== "already_voted") return status($("vote-status"), explain(r), "error");
    state = { ...state, voted: true };
    store.set(poll.id, state);
    render();
    loadResults(poll);
  });

  // Paso 3: cualquiera puede comprobar que su papeleta está en el tablón.
  $("check").addEventListener("click", async () => {
    const r = await api("GET", `/api/polls/${poll.id}/ballots`);
    if (r.error) return status($("check-status"), explain(r), "error");
    const mine = r.ballots.find((b) => b.token === state.token);
    status($("check-status"), mine ? `Está en el tablón: «${mine.answer}».` : "No aparece en el tablón.", mine ? "ok" : "error");
  });

  $("ballots-link").href = `/api/polls/${poll.id}/ballots`;
  AutoScript.cargarAppAfirma();
  render();
  await loadResults(poll);
}

async function loadResults(poll) {
  const res = await api("GET", `/api/polls/${poll.id}/results`);
  $("results").innerHTML = res.error
    ? `<p>${res.error === "embargo_loreg" ? `Resultados ocultos por la LOREG hasta ${new Date(res.until).toLocaleString("es")}.` : explain(res)}</p>`
    : `<p>${res.votes} votos · ${res.tokensIssued} tokens emitidos · dato bruto, sin ponderar</p><table>${Object.entries(res.counts)
        .sort((a, b) => b[1] - a[1])
        .map(([k, n]) => `<tr><td>${k}</td><td>${n}</td><td>${res.votes ? ((100 * n) / res.votes).toFixed(1) : "0.0"}%</td></tr>`)
        .join("")}</table>`;
}

main().catch((e) => {
  document.body.insertAdjacentHTML("afterbegin", `<p class="status error">No se pudo cargar: ${e.message}</p>`);
});
