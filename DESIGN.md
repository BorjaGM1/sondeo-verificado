# Sondeo verificado — diseño

Encuestas de intención de voto **anónimas pero verificadas**: una persona real = un voto por encuesta,
sin que ni el operador pueda saber qué votó cada uno, y con un recuento que cualquiera puede rehacer.

Todo el código es público. La idea de fondo: **no hace falta fiarse del servidor**. Las propiedades
importantes se garantizan en el navegador (código estático auditable) y en datos públicos.

## Propiedades que buscamos

1. **Unicidad**: cada DNI obtiene como mucho un token por encuesta.
2. **Anonimato frente al operador**: el servidor que ve tu DNI no puede relacionarlo con tu voto.
3. **Recuento verificable**: todas las papeletas se publican; cualquiera recuenta y cada votante comprueba la suya.
4. **Transparencia del resultado**: se publica siempre el dato bruto y el ponderado, con el script de ponderación.

## Flujo

```
Navegador                         Worker /api/identity            Worker /api/vote
─────────                         ───────────────────             ────────────────
genera token T (aleatorio)
ciega T → B  (RFC 9474)
pide reto con hash(B) ─────────▶  reto = HMAC(ts, nonce, hash(B))
firma el reto con Autofirma
  (cert FNMT, formato NONE) ────▶ verifica firma + cadena FNMT
                                  nullifier = HMAC(k, DNI ‖ encuesta)
                                  ¿ya usado? → rechaza
                                  guarda nullifier
                                  firma ciega de B ───────────▶
desciega → firma S sobre T
(puede esperar horas)
envía {T, S, respuesta,
  demografía declarada} ───────────────────────────────────────▶ verifica S con la clave pública
                                                                   de la encuesta, T no repetido,
                                                                   guarda la papeleta
```

- **Identificación** (`src/identity.js`): el Worker da un reto; el usuario lo firma con su certificado de la
  FNMT usando Autofirma (`AutoScript.sign(datos, "SHA256withRSA", "NONE", …)`, firma PKCS#1 sin más).
  En escritorio Autofirma devuelve la firma por un WebSocket local (`wss://127.0.0.1`), así que **no
  hace falta el servidor intermedio de Java**. El Worker verifica con WebCrypto: firma del reto, cadena
  hasta la CA de la FNMT, vigencia, y extrae el DNI del campo `serialNumber` (`IDCES-12345678Z`).
- **Emisión ciega** (`POST /api/issue`): RSABSSA-SHA384-PSS-Randomized (RFC 9474) con
  `@cloudflare/blindrsa-ts` en navegador (`client/main.js`) y Worker (`src/app.js`). Una clave por
  encuesta: la pública está en `src/polls.js`, la privada en el secreto `POLL_KEYS`
  (`scripts/new-poll-key.mjs`). El reto incluye `hash(B)` para que la firma con el certificado autorice
  exactamente ese token cegado. En Workers la firma usa la operación RSA nativa (`supportsRSARAW`):
  en JS puro tarda ~230 ms y se pasaría del límite de CPU del plan gratuito.
- **Voto** (`POST /api/vote`): llega el token desciegado. El servidor no puede relacionar `T` con `B`.
- **Público**: `GET /api/polls/:id/results` (recuento bruto + tokens emitidos) y
  `GET /api/polls/:id/ballots` (tablón con todas las papeletas y la clave pública para verificarlas).
- Si pierdes el token (otro navegador, borras datos) antes de votar, no puedes sacar otro: el
  nullifier ya está gastado. Es el precio de no guardar nada que te relacione con el token.

## Qué se guarda

| Tabla | Contenido | ¿Identifica? |
|---|---|---|
| `nullifiers` | `HMAC(k, encuesta:DNI)` | Seudónimo: el operador podría comprobar si un DNI concreto participó (no qué votó) |
| `ballots` | `T`, `S`, respuesta, edad, sexo, CCAA, recuerdo de voto | No |

Las dos tablas son `WITHOUT ROWID`: se guardan ordenadas por clave, no por orden de llegada, y el
tablón se publica ordenado por token.

Nada más: ni IPs, ni DNIs, ni certificados. Logs de Workers desactivados.

## Lo que NO podemos garantizar (y lo decimos)

- **El código desplegado**: no hay forma de demostrar qué corre en Cloudflare. Desplegamos solo desde
  GitHub Actions con logs públicos, pero eso es buena fe, no prueba. Por eso el anonimato depende del
  **cliente** (cegado en el navegador), que sí es verificable.
- **Correlación por IP y hora**: quien opera ambos endpoints podría cruzar "identificado a las 20:01
  desde IP X" con "votó a las 20:01 desde IP X". Mitigación: el token se guarda en el navegador y se
  puede votar más tarde; se recomienda hacerlo.
- **Emisión fraudulenta**: el operador podría emitir tokens a DNIs inventados. Se publica el número de
  tokens emitidos, pero detectar relleno requiere auditoría externa.

## Límites del certificado de la FNMT

- **No contiene edad, sexo ni provincia** → la demografía para ponderar es declarada.
- Distingue DNI (españoles) de NIE (extranjeros): para generales solo DNI.
- Sesgo propio: lo tiene más gente que hace trámites (autónomos, clase media, +30). Se corrige ponderando.
- **Solo escritorio** en v1: en móvil Autofirma necesita servidor intermedio y el certificado suele no estar.
- **Hay que tener Autofirma instalada**, y su instalador añade un certificado raíz propio al almacén de
  confianza (para el `wss://127.0.0.1`). Es fricción y genera desconfianza; mucha gente con certificado
  ya la tiene por los trámites, pero no todo el mundo querrá instalarla.
- Dos CAs emisoras: **AC FNMT Usuarios** (RSA) y **AC USUARIOS G2** (ECDSA, desde dic. 2024). Se aceptan
  firmas RSA y ECDSA (Autofirma elige el algoritmo según la clave y da ECDSA en DER).
- Revocación (OCSP de la FNMT): pendiente; en el spike solo se comprueba vigencia.

## Ponderación

Raking (ajuste iterativo) para que la muestra cuadre con:
- edad × sexo y comunidad autónoma (padrón del INE),
- recuerdo de voto en las últimas generales (resultados oficiales, incluida abstención).

Se publican bruto, ponderado y el script, para que cualquiera lo reproduzca.

## Legal

- **LOREG art. 69.7**: prohibido publicar sondeos en los 5 días anteriores a la votación. La web
  oculta resultados (también los parciales y el contador) en esa ventana.
- **RGPD**: la opinión política es categoría especial. No guardamos nada que la relacione con una
  persona; el nullifier es dato seudonimizado de participación y hay que tratarlo como tal.

## Stack

Cloudflare Workers + assets estáticos + D1. Deploy solo desde GitHub Actions.

## Estado

- [x] Spike: reto → firma con Autofirma → verificación en el Worker (`src/identity.js`)
- [x] Obtener e incluir las CAs de la FNMT (`certs/`)
- [x] Desplegado en https://sondeo-verificado.borjitaea.workers.dev
- [x] Probar con Autofirma y un certificado real (Windows, 2026-11-24: OK)
- [x] Emisión ciega + endpoint de voto + D1
- [x] Tablón público de papeletas y recuento bruto
- [ ] Probar el flujo completo con un certificado real
- [ ] Repo público en GitHub + deploy desde Actions
- [ ] Ponderación
- [ ] OCSP
