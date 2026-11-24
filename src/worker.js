import { createApp } from "./app.js";
import { parseTrustAnchors } from "./identity.js";
import { FNMT_CA_PEMS } from "./trust.js";
import { POLLS, DEMOGRAPHICS } from "./polls.js";

// rsaRaw: en Workers la firma ciega usa la operación RSA nativa (rápida); en JS puro
// una firma RSA-2048 puede pasarse del límite de CPU.
export default createApp({
  anchors: parseTrustAnchors(FNMT_CA_PEMS),
  polls: POLLS,
  demographics: DEMOGRAPHICS,
  rsaRaw: true,
});
