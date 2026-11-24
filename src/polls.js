// Encuestas y opciones de demografía. Todo esto es público: la clave pública de cada encuesta
// permite a cualquiera comprobar que cada papeleta del tablón lleva una firma válida.

const PARTIDOS = ["PP", "PSOE", "Vox", "Sumar", "Podemos", "Se Acabó La Fiesta", "ERC", "Junts", "EH Bildu", "PNV", "BNG", "CC", "UPN"];

export const DEMOGRAPHICS = {
  edad: ["18-24", "25-34", "35-44", "45-54", "55-64", "65+"],
  sexo: ["Mujer", "Hombre", "Otro / prefiero no decirlo"],
  ccaa: [
    "Andalucía", "Aragón", "Asturias", "Baleares", "Canarias", "Cantabria", "Castilla y León",
    "Castilla-La Mancha", "Cataluña", "Comunidad Valenciana", "Extremadura", "Galicia", "Madrid",
    "Murcia", "Navarra", "País Vasco", "La Rioja", "Ceuta", "Melilla", "Vivo en el extranjero",
  ],
  // Recuerdo de voto en las generales de julio de 2023: la variable clave para ponderar.
  recuerdo: [
    "PP", "PSOE", "Vox", "Sumar", "ERC", "Junts", "EH Bildu", "PNV", "BNG", "CC", "UPN",
    "Otro partido", "En blanco", "Nulo", "No voté", "No tenía edad o derecho a voto", "No recuerdo / prefiero no decirlo",
  ],
};

export const POLLS = [
  {
    id: "prueba-2026-11",
    title: "Prueba: intención de voto en elecciones generales",
    question: "Si mañana se celebrasen elecciones generales, ¿a qué partido votarías?",
    options: [...PARTIDOS, "Otro partido", "En blanco", "Nulo", "No votaría", "No lo sé"],
    opensAt: "2026-11-24T00:00:00Z",
    closesAt: "2026-12-31T23:59:59Z",
    // LOREG art. 69.7: ventanas en las que no se publican resultados ni papeletas.
    embargo: [],
    // Para generales solo votan españoles: el certificado debe llevar DNI, no NIE.
    allowNie: false,
    publicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFPL/2qWsYP9fTfum8IyIXgpDYZekcGkAD5yvo7B46NncsmA4ezLUpMICOQKABpLNYxHguf+h4f2PQD72E4GQrGn8fnv3WflHU7zAB65+aR90ioUWYt1/RrhKTBBn/9aYEwDYzwvP0c3Wzg6uejPm3XzRb9R8TsiJMHwDOyXyHfTf4Q/EoploSzUqc7vq8kXoBLx0L61NJib2FOAX3tn8TbKcXfWyUeKwpcwmXehcKMYwis9AArb0D/tTLPZ3/ay0NTCwhQPhm92tB3LfldpRq4zhV3OThB6uP5+r36x9kh1X7sFCPK/4kAnb93438g1awq/tHUCR+L9jrRh5ciTMwIDAQAB",
  },
];
