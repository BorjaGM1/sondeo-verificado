-- Se quita la demografía declarada: no se puede verificar (el certificado de la FNMT no la lleva)
-- y cada campo publicado junto al voto facilita reidentificar a alguien.
ALTER TABLE ballots DROP COLUMN edad;
ALTER TABLE ballots DROP COLUMN sexo;
ALTER TABLE ballots DROP COLUMN ccaa;
ALTER TABLE ballots DROP COLUMN recuerdo;
