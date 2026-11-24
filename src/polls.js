// Encuestas. La clave pública de cada encuesta verifica los tokens con los que se vota.

const PARTIDOS = ["PP", "PSOE", "Vox", "Sumar", "Podemos", "Se Acabó La Fiesta", "ERC", "Junts", "EH Bildu", "PNV", "BNG", "CC", "UPN"];

export const POLLS = [
  {
    id: "prueba-2026-11",
    title: "Prueba: intención de voto en elecciones generales",
    question: "Si mañana se celebrasen elecciones generales, ¿a qué partido votarías?",
    options: [...PARTIDOS, "Otro partido", "En blanco", "Nulo", "No votaría", "No lo sé"],
    // Horas de España peninsular (CET en invierno).
    opensAt: "2026-11-24T00:00:00+01:00",
    closesAt: "2026-12-31T23:59:59+01:00",
    // Para generales solo votan españoles: el certificado debe llevar DNI, no NIE.
    allowNie: false,
    publicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFPL/2qWsYP9fTfum8IyIXgpDYZekcGkAD5yvo7B46NncsmA4ezLUpMICOQKABpLNYxHguf+h4f2PQD72E4GQrGn8fnv3WflHU7zAB65+aR90ioUWYt1/RrhKTBBn/9aYEwDYzwvP0c3Wzg6uejPm3XzRb9R8TsiJMHwDOyXyHfTf4Q/EoploSzUqc7vq8kXoBLx0L61NJib2FOAX3tn8TbKcXfWyUeKwpcwmXehcKMYwis9AArb0D/tTLPZ3/ay0NTCwhQPhm92tB3LfldpRq4zhV3OThB6uP5+r36x9kh1X7sFCPK/4kAnb93438g1awq/tHUCR+L9jrRh5ciTMwIDAQAB",
  },
];
