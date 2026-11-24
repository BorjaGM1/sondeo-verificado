# sondeo-verificado

Encuestas de intención de voto anónimas pero verificadas con certificado digital, en Cloudflare Workers.
El porqué y el cómo están en [DESIGN.md](DESIGN.md).

- Te identificas firmando un reto con tu certificado de la FNMT (Autofirma).
- Tu navegador genera un token, lo ciega, y el servidor lo firma sin verlo (RFC 9474).
- Votas con el token: nadie puede relacionarlo con tu identidad. Un DNI, un token por encuesta.
- No se publican votos: ni la web ni la API muestran resultados. Ver DESIGN.md para consultarlos.

## Código

| | |
|---|---|
| `client/main.js` | Navegador: cegado del token, Autofirma, voto (se empaqueta en `public/app.js`) |
| `src/identity.js` | Verificación del reto firmado con el certificado |
| `src/app.js` | API: reto, emisión ciega y voto |
| `src/polls.js` | Encuestas, opciones y claves públicas |
| `migrations/` | Esquema D1 |

## Desarrollo

```bash
npm install
npm test
cp .dev.vars.example .dev.vars   # y rellena los secretos
npx wrangler d1 migrations apply sondeo-verificado --local
npm run dev
```

Secretos: `CHALLENGE_SECRET`, `NULLIFIER_SECRET` y `POLL_KEYS` (JSON `{"<encuesta>": "<pkcs8 base64>"}`,
ver `scripts/new-poll-key.mjs`).
