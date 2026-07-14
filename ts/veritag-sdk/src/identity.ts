/**
 * Identity: P-256 keypair + opaque binding signing, using WebCrypto (SubtleCrypto).
 *
 * The private key is created as `extractable: false` so it cannot leave the
 * browser/Node KeyStore — the web analogue of the mobile Secure Enclave.
 * Persistence across reloads is handled by `keystore.ts` (IndexedDbKeyStore /
 * loadOrCreateIdentity / rotateIdentity), which stores the non-extractable
 * CryptoKey without ever exposing the raw private bytes.
 */

const ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN_ALG = { name: "ECDSA", hash: "SHA-256" } as const;

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface Identity {
  publicKeyHex: string; // uncompressed 04||X||Y
  signBinding(payload: Uint8Array): Promise<string>; // DER hex
}

/** Wrap a (possibly non-extractable) CryptoKeyPair as an Identity. */
export async function identityFromKeyPair(pair: CryptoKeyPair): Promise<Identity> {
  const raw = await crypto.subtle.exportKey("raw", pair.publicKey); // 65 bytes, 04||X||Y
  const publicKeyHex = toHex(raw);

  return {
    publicKeyHex,
    async signBinding(payload: Uint8Array): Promise<string> {
      // WebCrypto returns a P1363 (r||s) signature; convert to DER for the core.
      const p1363 = await crypto.subtle.sign(SIGN_ALG, pair.privateKey, payload as BufferSource);
      return p1363ToDerHex(new Uint8Array(p1363));
    },
  };
}

export async function createIdentity(): Promise<Identity> {
  // extractable:false — the private key never leaves the KeyStore. To survive a
  // reload, persist the (non-extractable) CryptoKeyPair via keystore.ts.
  const pair = await crypto.subtle.generateKey(ALG, false, ["sign", "verify"]);
  return identityFromKeyPair(pair);
}

/** Build the default binding payload: SHA-256(uid + '|' + context). */
export async function buildBinding(uid: string, context: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`${uid}|${context}`);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/** Convert a 64-byte r||s signature into DER-encoded ECDSA. */
export function p1363ToDerHex(sig: Uint8Array): string {
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  const enc = (x: Uint8Array) => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++;
    let v = x.slice(i);
    if (v[0] & 0x80) v = Uint8Array.from([0, ...v]);
    return v;
  };
  const R = enc(r);
  const S = enc(s);
  const body = Uint8Array.from([0x02, R.length, ...R, 0x02, S.length, ...S]);
  const der = Uint8Array.from([0x30, body.length, ...body]);
  return [...der].map((b) => b.toString(16).padStart(2, "0")).join("");
}
