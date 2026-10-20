import { b64, keysFrom, newRecordsKey, newRecoverySecret, newVault, recordsKeyFromRecovery, recoveryText, unb64, unwrapKey, wrapKey, type VaultMeta, type Wrap } from "./private.ts";

// Private in a browser: where the records key lives on the web, never on
// the server. A passkey's PRF secret or the recovery key unwraps it on a new browser; then this browser
// keeps it wrapped by a key of its own that cannot be read out of it (a non-extractable Web Crypto key
// in IndexedDB), until the person signs out. `configureBrowser` names the product.

let DB = "private-keys";
let PRODUCT = "Private";
/** The product's name for its passkeys, and the IndexedDB database its keys live in. */
export function configureBrowser(options: { product: string; database: string }) {
  PRODUCT = options.product;
  DB = options.database;
}
const STORE = "keys";
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
/** A copy on a plain ArrayBuffer, as Web Crypto and WebAuthn take bytes. */
const own = (u: Uint8Array) => new Uint8Array(u);

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}
async function idb<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const r = run(d.transaction(STORE, mode).objectStore(STORE));
    r.onsuccess = () => resolve(r.result as T);
    r.onerror = () => reject(r.error);
  });
}

type Kept = { deviceKey: CryptoKey; iv: Uint8Array; wrapped: ArrayBuffer };

/** Keeps the records key in this browser, wrapped by a key the browser will not give out. */
export async function rememberHere(meta: VaultMeta, recordsKey: Uint8Array) {
  try {
    const deviceKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = random(12);
    const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, deviceKey, own(recordsKey));
    await idb("readwrite", (s) => s.put({ deviceKey, iv, wrapped } satisfies Kept, meta.publicKey));
  } catch {
    // A private window keeps nothing: the passkey or the recovery key is asked for again next time.
  }
}
/** The records key this browser kept for this vault, or null. */
export async function keptHere(meta: VaultMeta): Promise<Uint8Array | null> {
  try {
    const kept = await idb<Kept | undefined>("readonly", (s) => s.get(meta.publicKey));
    if (!kept) return null;
    const key = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: own(kept.iv) }, kept.deviceKey, kept.wrapped));
    keysFrom(key, meta);
    return key;
  } catch {
    return null;
  }
}
/** Signing out forgets every key this browser kept. */
export async function forgetHere() {
  try {
    await idb("readwrite", (s) => s.clear());
  } catch {}
}

// Passkeys: used here only for their PRF secret, which opens the records key. The passkey never
// signs anyone in, so the server checks nothing about it and keeps only its id and salt.

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer } };
const prfOf = (c: PublicKeyCredential) => (c.getClientExtensionResults() as { prf?: PrfResults }).prf;

export const passkeysPossible = () => typeof PublicKeyCredential !== "undefined" && !!navigator.credentials;

/** A new passkey for the product and its secret, or null where this browser or its passkeys have no PRF. */
export async function newPasskey(name: string): Promise<{ wrap: Omit<Extract<Wrap, { kind: "passkey" }>, "wrapped">; secret: Uint8Array } | null> {
  if (!passkeysPossible()) return null;
  const salt = random(32);
  const created = (await navigator.credentials.create({
    publicKey: {
      rp: { name: PRODUCT, id: location.hostname },
      user: { id: random(16), name, displayName: name },
      challenge: random(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!created) return null;
  const credential = b64(new Uint8Array(created.rawId));
  const prf = prfOf(created);
  let first = prf?.results?.first;
  // Some browsers only say the passkey can do it when it is made; asking once gives the secret.
  if (!first && prf?.enabled) first = (await passkeySecret([{ kind: "passkey", credential, salt: b64(salt), wrapped: "", created: "" }]))?.secret.buffer as ArrayBuffer | undefined;
  if (!first) return null;
  return { wrap: { kind: "passkey", credential, salt: b64(salt), created: new Date().toISOString().slice(0, 10), name: "Passkey" }, secret: new Uint8Array(first) };
}

/** The secret of one of these passkeys, as the person chooses it, with the wrap it belongs to. */
export async function passkeySecret(wraps: Wrap[]) {
  const passkeys = wraps.filter((w): w is Extract<Wrap, { kind: "passkey" }> => w.kind === "passkey");
  if (!passkeys.length || !passkeysPossible()) return null;
  const got = (await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      rpId: location.hostname,
      userVerification: "required",
      allowCredentials: passkeys.map((p) => ({ type: "public-key" as const, id: own(unb64(p.credential)) })),
      extensions: { prf: { evalByCredential: Object.fromEntries(passkeys.map((p) => [p.credential, { first: own(unb64(p.salt)) }])) } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  const first = got && prfOf(got)?.results?.first;
  if (!got || !first) return null;
  const wrap = passkeys.find((p) => p.credential === b64(new Uint8Array(got.rawId)));
  return wrap ? { wrap, secret: new Uint8Array(first) } : null;
}

/** Opens the records key with a passkey. */
export async function unlockWithPasskey(meta: VaultMeta) {
  const found = await passkeySecret(meta.wraps);
  if (!found) return null;
  const key = unwrapKey(found.secret, found.wrap.wrapped, "passkey");
  keysFrom(key, meta);
  return key;
}
/** Opens the records key with the recovery key, as typed. */
export const unlockWithRecovery = recordsKeyFromRecovery;

/** A new vault: the records key, its recovery key, and a passkey where one can be made. */
export async function newKeys(name: string) {
  const recordsKey = newRecordsKey();
  const recovery = newRecoverySecret();
  const meta: VaultMeta = { ...newVault(keysFrom(recordsKey)), wraps: [{ kind: "recovery", wrapped: wrapKey(recovery, recordsKey, "recovery"), created: new Date().toISOString().slice(0, 10) }] };
  let passkey = false;
  try {
    const made = await newPasskey(name);
    if (made) {
      meta.wraps.push({ ...made.wrap, wrapped: wrapKey(made.secret, recordsKey, "passkey") });
      passkey = true;
    }
  } catch {
    // Declined or not possible here: the recovery key alone opens them on another device.
  }
  return { recordsKey, meta, recoveryText: recoveryText(recovery), passkey };
}
