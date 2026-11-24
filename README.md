# sondeo-verificado

Encuestas de intención de voto anónimas pero verificadas con certificado digital, en Cloudflare Workers.
El porqué y el cómo están en [DESIGN.md](DESIGN.md).

## Estado

Spike de identificación: el usuario firma un reto con su certificado de la FNMT vía Autofirma y el
Worker lo verifica. Todavía no hay encuestas ni votos.

## Probarlo

```bash
npm install
npm test
cp .dev.vars.example .dev.vars   # y pon un secreto
npm run dev                      # http://localhost:8787
```

Para probar con un certificado real hace falta tener Autofirma instalada y añadir la CA de la FNMT
en `src/trust.js` (ver `certs/README.md`).
