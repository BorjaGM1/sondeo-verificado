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
const explain = (r) => {
  if (r.error === "below_min_votes") {
    return `Llevamos ${r.votes} de ${r.minVotes} votos. Hasta llegar a ${r.minVotes} no se publican resultados ni papeletas: con pocos votos se podría adivinar quién ha votado qué.`;
  }
  if (r.error === "embargo_loreg") return `Resultados ocultos por la LOREG hasta ${new Date(r.until).toLocaleString("es")}.`;
  return ERRORS[r.error] ?? `Error: ${r.error}`;
};

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

function busy(button, on, label) {
  button.disabled = on;
  button.setAttribute("aria-busy", on ? "true" : "false");
  if (label) button.textContent = label;
}

const esc = (t) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
// Respuestas que no son partidos: se muestran más discretas.
const NOT_A_PARTY = new Set(["Otro partido", "En blanco", "Nulo", "No votaría", "No lo sé"]);
const fmtDate = (iso) => new Date(iso).toLocaleDateString("es", { day: "numeric", month: "long" });

async function main() {
  const { polls } = await api("GET", "/api/polls");
  const wanted = new URLSearchParams(location.search).get("encuesta");
  const poll = polls.find((p) => p.id === wanted) ?? polls[0];
  const publicKey = await crypto.subtle.importKey("spki", fromB64(poll.publicKey), PSS, true, ["verify"]);
  let state = { ...store.get(poll.id) };

  document.title = `${poll.question} · Sondeo verificado`;
  $("question").textContent = poll.question;
  const open = Date.now() >= Date.parse(poll.opensAt) && Date.now() <= Date.parse(poll.closesAt);
  $("eyebrow").textContent = open ? `Encuesta abierta · cierra el ${fmtDate(poll.closesAt)}` : "Encuesta cerrada";
  $("eyebrow").classList.toggle("closed", !open);

  $("options").innerHTML =
    `<legend class="sr-only">${esc(poll.question)}</legend>` +
    poll.options
      .map((o) => `<label class="option${NOT_A_PARTY.has(o) ? " secondary" : ""}"><input type="radio" name="answer" value="${esc(o)}" required><span>${esc(o)}</span></label>`)
      .join("");
  $("options").addEventListener("change", () => ($("vote-btn").disabled = false));

  function render() {
    const step = !state.token ? "identify" : !state.voted ? "vote" : "done";
    const order = ["identify", "vote", "done"];
    for (const li of document.querySelectorAll(".steps li")) {
      const i = order.indexOf(li.dataset.step);
      li.classList.toggle("current", li.dataset.step === step);
      li.classList.toggle("done", i < order.indexOf(step));
      if (li.dataset.step === step) li.setAttribute("aria-current", "step");
      else li.removeAttribute("aria-current");
    }
    $("step-identify").hidden = step !== "identify" || !open;
    $("step-vote").hidden = step !== "vote" || !open;
    $("step-done").hidden = step !== "done";
    if (state.voted) $("my-token").textContent = state.token;
  }

  // Paso 1: token ciego autorizado por tu certificado.
  $("identify").addEventListener("click", async () => {
    const out = $("identify-status");
    const btn = $("identify");
    const fail = (msg) => {
      busy(btn, false, "Identificarme con Autofirma");
      status(out, msg, "error");
    };
    busy(btn, true, "Esperando a Autofirma…");
    status(out, "");
    try {
      const token = suite.prepare(crypto.getRandomValues(new Uint8Array(32)));
      const { blindedMsg, inv } = await suite.blind(publicKey, token);
      const { challenge } = await api("POST", "/api/challenge", { bind: b64url(await sha256(blindedMsg)) });
      status(out, "Se abrirá Autofirma: elige tu certificado y acepta la firma.");

      AutoScript.sign(btoa(challenge), "SHA256withRSA", "NONE", "", async (signature, certificate) => {
        busy(btn, true, "Comprobando tu certificado…");
        const r = await api("POST", "/api/issue", { pollId: poll.id, challenge, signature, certificate, blindedMsg: b64url(blindedMsg) });
        if (!r.ok) return fail(explain(r));
        const sig = await suite.finalize(publicKey, token, fromB64(r.blindSignature), inv);
        state = { token: b64url(token), signature: b64url(sig) };
        store.set(poll.id, state);
        render();
      }, (type, message) => fail(`Autofirma: ${message || type}`));
    } catch (e) {
      fail(`Error: ${e.message}`);
    }
  });

  // Paso 2: votar con el token (puede ser mucho después).
  $("vote-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = $("vote-btn");
    busy(btn, true, "Enviando…");
    const data = Object.fromEntries(new FormData(ev.target));
    const r = await api("POST", "/api/vote", { pollId: poll.id, token: state.token, signature: state.signature, ...data });
    if (!r.ok && r.error !== "already_voted") {
      busy(btn, false, "Enviar voto");
      return status($("vote-status"), explain(r), "error");
    }
    state = { ...state, voted: true };
    store.set(poll.id, state);
    render();
    loadResults(poll);
  });

  // Paso 3: cualquiera puede comprobar que su papeleta está en el tablón.
  $("check").addEventListener("click", async () => {
    const btn = $("check");
    busy(btn, true);
    const r = await api("GET", `/api/polls/${poll.id}/ballots`);
    busy(btn, false);
    if (r.error === "below_min_votes") {
      return status($("check-status"), `Podrás comprobarlo cuando haya ${r.minVotes} votos (vamos por ${r.votes}). Tu token queda guardado en este navegador.`);
    }
    if (r.error) return status($("check-status"), explain(r), "error");
    const mine = r.ballots.find((b) => b.token === state.token);
    status($("check-status"), mine ? `Está en el tablón: «${mine.answer}».` : "No aparece en el tablón.", mine ? "ok" : "error");
  });

  $("ballots-link").href = `/api/polls/${poll.id}/ballots`;
  // En móvil Autofirma no firma desde el navegador (y su librería muestra un aviso propio al cargar).
  const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  if (isMobile) {
    $("identify").disabled = true;
    $("identify").textContent = "Solo desde ordenador";
    $("identify-note").textContent = "La firma con certificado solo funciona en un ordenador (Windows, Mac o Linux) con Autofirma. Abre esta página allí.";
  } else {
    AutoScript.cargarAppAfirma();
  }
  render();
  showCodeHash();
  await loadResults(poll);
}

async function loadResults(poll) {
  const res = await api("GET", `/api/polls/${poll.id}/results`);
  const el = $("results");
  if (res.error === "below_min_votes") {
    const pct = Math.min(100, (100 * res.votes) / res.minVotes);
    el.innerHTML = `<p class="meter-num">${res.votes}<small>de ${res.minVotes} votos</small></p>
      <div class="meter" role="progressbar" aria-valuemin="0" aria-valuemax="${res.minVotes}" aria-valuenow="${res.votes}"><i style="width:${pct}%"></i></div>
      <p class="muted">Los resultados y el tablón se publican al llegar a ${res.minVotes} votos. Con menos, se podría adivinar quién ha votado qué.</p>`;
    return;
  }
  if (res.error) {
    el.innerHTML = `<p class="muted">${esc(explain(res))}</p>`;
    return;
  }
  const rows = Object.entries(res.counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, n]) => n));
  el.innerHTML = `<ul class="rows">${rows
    .map(([k, n]) => {
      const pct = res.votes ? (100 * n) / res.votes : 0;
      return `<li class="row"><span>${esc(k)}</span><span class="bar"><i style="width:${(100 * n) / max}%"></i></span><b>${pct.toFixed(1)}%<span class="n">${n}</span></b></li>`;
    })
    .join("")}</ul>
    <p class="fine">${res.votes} votos · ${res.tokensIssued} tokens emitidos. Dato bruto, sin ponderar: refleja a quien tiene certificado y ha votado aquí, no a toda España.</p>`;
}

// Huella del código que ejecuta este navegador, para compararla con la del log de despliegue.
async function showCodeHash() {
  try {
    const buf = await (await fetch("/app.js", { cache: "no-store" })).arrayBuffer();
    const hex = [...(await sha256(new Uint8Array(buf)))].map((b) => b.toString(16).padStart(2, "0")).join("");
    $("code-hash").textContent = hex.slice(0, 16) + "…";
    $("code-hash").title = `SHA-256 de /app.js: ${hex}`;
  } catch {
    $("code-hash").textContent = "no disponible";
  }
}

main().catch((e) => {
  $("eyebrow").textContent = "No se pudo cargar";
  $("results").innerHTML = `<p class="status error">${esc(e.message)}</p>`;
});
