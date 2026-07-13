/**
 * NTAG 424 DNA — SDM CMAC, browser side (the verify counterpart to the server's
 * crypto/cmac.py). Lets a web app *simulate a tap*: given the short-lived
 * ChipKey returned at provisioning, compute the exact CMAC a real chip would
 * mirror into its URL — so the whole enrol → mint → tap → verify loop runs in the
 * browser with no extra tooling.
 *
 * AES-CMAC (RFC 4493) is built on WebCrypto AES-CBC (no native CMAC). Validated
 * byte-exact against the NXP AN12196 vectors (see test/sdm.test.mjs).
 */
const RB = 0x87;
const ZERO16 = new Uint8Array(16);

function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-CBC" }, false, ["encrypt"]);
}

/** One AES block (ECB) via CBC with a zero IV: the first 16 bytes of ciphertext. */
async function aesBlock(key: CryptoKey, block: Uint8Array): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ZERO16 }, key, block as BufferSource);
  return new Uint8Array(ct).slice(0, 16);
}

function shiftLeft1(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length);
  let carry = 0;
  for (let i = b.length - 1; i >= 0; i--) {
    out[i] = ((b[i] << 1) | carry) & 0xff;
    carry = b[i] & 0x80 ? 1 : 0;
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

async function subkeys(key: CryptoKey): Promise<[Uint8Array, Uint8Array]> {
  const l = await aesBlock(key, ZERO16);
  const k1 = shiftLeft1(l);
  if (l[0] & 0x80) k1[15] ^= RB;
  const k2 = shiftLeft1(k1);
  if (k1[0] & 0x80) k2[15] ^= RB;
  return [k1, k2];
}

/** AES-CMAC (RFC 4493) over an arbitrary-length message. */
export async function aesCmac(keyRaw: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const key = await importKey(keyRaw);
  const [k1, k2] = await subkeys(key);
  const n = Math.max(1, Math.ceil(msg.length / 16));
  const complete = msg.length > 0 && msg.length % 16 === 0;
  const lastStart = (n - 1) * 16;

  let last: Uint8Array;
  if (complete) {
    last = xor(msg.slice(lastStart, lastStart + 16), k1);
  } else {
    const padded = new Uint8Array(16);
    const tail = msg.slice(lastStart);
    padded.set(tail);
    padded[tail.length] = 0x80;
    last = xor(padded, k2);
  }

  let x: Uint8Array = ZERO16;
  for (let i = 0; i < n - 1; i++) {
    x = await aesBlock(key, xor(x, msg.slice(i * 16, i * 16 + 16)));
  }
  return aesBlock(key, xor(x, last));
}

/** The 8-byte SDM CMAC for (uid, readCtr) under chipKey (odd bytes of the CMAC). */
export async function computeSdmCmac(
  chipKey: Uint8Array,
  uid: Uint8Array,
  readCtr: number,
): Promise<Uint8Array> {
  const ctrLe = new Uint8Array([readCtr & 0xff, (readCtr >> 8) & 0xff, (readCtr >> 16) & 0xff]);
  const sv2 = new Uint8Array([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80, ...uid, ...ctrLe]);
  const sessionKey = await aesCmac(chipKey, sv2);
  const mac16 = await aesCmac(sessionKey, new Uint8Array(0)); // empty input
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = mac16[1 + i * 2]; // odd-indexed bytes
  return out;
}

export const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));

export const bytesToHex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
