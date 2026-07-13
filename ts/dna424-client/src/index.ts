/**
 * dna424-client — embeddable web client SDK for the 424 DNA ecosystem.
 *
 *   - identity     : P-256 keypair + opaque binding signing (WebCrypto)
 *   - AttestClient : HTTP to the AttestCore web API (provision / verify)
 *
 * NFC tag provisioning lives on mobile (WebNFC cannot drive NTAG 424 SDM
 * configuration); the web SDK focuses on identity + verification.
 */
export * from "./identity.js";
export * from "./keystore.js";
export * from "./attestClient.js";
export * from "./sdm.js";
