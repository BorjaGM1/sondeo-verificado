/* global AutoScript */
const out = document.getElementById("out");
const log = (msg) => (out.textContent = typeof msg === "string" ? msg : JSON.stringify(msg, null, 2));

AutoScript.cargarAppAfirma();

const post = async (path, body) => {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
};

document.getElementById("go").addEventListener("click", async () => {
  log("Pidiendo reto…");
  const { challenge } = await post("/api/challenge", {});
  log("Abriendo Autofirma… elige tu certificado.");

  // El reto es ASCII, así que btoa vale. Formato "NONE" = firma PKCS#1 sin envoltorio.
  AutoScript.sign(
    btoa(challenge),
    "SHA256withRSA",
    "NONE",
    "",
    async (signature, certificate) => {
      log("Verificando en el servidor…");
      log(await post("/api/verify", { challenge, signature, certificate }));
    },
    (type, message) => log(`Error de Autofirma: ${type} — ${message}`),
  );
});
