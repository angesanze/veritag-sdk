/**
 * Persistent identity storage — Phase 3.
 *
 * Stores the P-256 CryptoKeyPair in IndexedDB. The private CryptoKey is
 * **non-extractable**: IndexedDB can persist the handle, but neither this code
 * nor any script can read the raw private bytes back out — the web analogue of
 * a Secure Enclave key. This replaces the ArtTrust 1.0 pattern of keeping a raw
 * private key hex in plaintext storage.
 *
 * `loadOrCreateIdentity` is the one call apps need: it returns a stable Identity
 * across reloads without ever exposing the private key.
 */
import { Identity, identityFromKeyPair } from "./identity.js";

const DB_NAME = "dna424";
const STORE = "identity";
const KEY = "default";

const ALG = { name: "ECDSA", namedCurve: "P-256" } as const;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(db: IDBDatabase, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = fn(db.transaction(STORE, mode).objectStore(STORE));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export class IndexedDbKeyStore {
  async has(): Promise<boolean> {
    const db = await openDb();
    const v = await tx<CryptoKeyPair | undefined>(db, "readonly", (s) => s.get(KEY));
    return v !== undefined;
  }

  /** Persist a CryptoKeyPair. The private key must be non-extractable. */
  async save(pair: CryptoKeyPair): Promise<void> {
    const db = await openDb();
    await tx(db, "readwrite", (s) => s.put(pair, KEY));
  }

  async load(): Promise<CryptoKeyPair | undefined> {
    const db = await openDb();
    return tx<CryptoKeyPair | undefined>(db, "readonly", (s) => s.get(KEY));
  }

  /** Delete the stored identity (rotation / revocation). Irreversible. */
  async clear(): Promise<void> {
    const db = await openDb();
    await tx(db, "readwrite", (s) => s.delete(KEY));
  }
}

async function generateNonExtractablePair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(ALG, false, ["sign", "verify"])) as CryptoKeyPair;
}

/** Return the persisted identity, creating + storing one on first run. */
export async function loadOrCreateIdentity(
  store: IndexedDbKeyStore = new IndexedDbKeyStore(),
): Promise<Identity> {
  let pair = await store.load();
  if (!pair) {
    pair = await generateNonExtractablePair();
    await store.save(pair);
  }
  return identityFromKeyPair(pair);
}

/**
 * Rotate the identity: generate a fresh non-extractable key, replace the stored
 * one, and return the new Identity. The previous private key is irrecoverable by
 * design — there is no raw-key export path.
 *
 * Backup / recovery follows the same principle: you never export the private
 * key. To "recover" you enroll a NEW identity and re-register its public key
 * with the issuer registry (and revoke the old issuer id). Losing the device
 * means losing the key, not leaking it — which is the security goal.
 */
export async function rotateIdentity(
  store: IndexedDbKeyStore = new IndexedDbKeyStore(),
): Promise<Identity> {
  const pair = await generateNonExtractablePair();
  await store.save(pair);
  return identityFromKeyPair(pair);
}
