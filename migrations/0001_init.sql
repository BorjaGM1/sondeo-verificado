-- WITHOUT ROWID: las filas se guardan ordenadas por clave primaria, no por orden de llegada,
-- para no regalar el orden temporal de emisión y de voto.

-- Un nullifier por persona y encuesta: HMAC(secreto, encuesta:DNI). No contiene el DNI.
CREATE TABLE nullifiers (
  poll_id   TEXT NOT NULL,
  nullifier TEXT NOT NULL,
  PRIMARY KEY (poll_id, nullifier)
) WITHOUT ROWID;

-- Papeletas: token desciegado + firma de la encuesta + respuesta. Todo público.
CREATE TABLE ballots (
  poll_id   TEXT NOT NULL,
  token     TEXT NOT NULL,
  signature TEXT NOT NULL,
  answer    TEXT NOT NULL,
  edad      TEXT NOT NULL,
  sexo      TEXT NOT NULL,
  ccaa      TEXT NOT NULL,
  recuerdo  TEXT NOT NULL,
  PRIMARY KEY (poll_id, token)
) WITHOUT ROWID;
