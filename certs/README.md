# CAs de la FNMT

Las dos CAs que emiten certificados de persona física, descargadas el 2026-11-24 de la
[página oficial de la FNMT](https://www.sede.fnmt.gob.es/descargas/certificados-raiz-de-la-fnmt).
Su SHA-1 coincide con la publicada allí. Están incrustadas en `src/trust.js`.

| Archivo | Sujeto | Clave | Caduca | SHA-1 (FNMT) | SHA-256 |
|---|---|---|---|---|---|
| `AC_FNMT_Usuarios.pem` | CN=AC FNMT Usuarios | RSA 2048 | 2029-10-28 | `808B72E43B574CF5877CB841A8DF88396D38AB94` | `601293CA20B09A03295D196256C6953FF9EBA811DB8E3CE140413C1BFFE9A869` |
| `AC_Usuarios_G2.pem` | CN=AC USUARIOS G2 | ECDSA P-256 | 2039-12-13 | `E9F499A0EFEFF7A60E9FE6B52FA3A8FEBBBDBA0A` | `283A9F9FE9674F67EFD6E27BB543E0EC192CBEFF20FC836C2243654744C5AF89` |

Para comprobarlo tú:

```bash
openssl x509 -in certs/AC_FNMT_Usuarios.pem -noout -subject -fingerprint -sha1
```
