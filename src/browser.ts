import { b64, keysFrom, newRecordsKey, newRecoverySecret, newVault, recordsKeyFromRecovery, recoveryText, unb64, unwrapKey, wrapKey, type VaultMeta, type Wrap } from "./private.ts";

let DB = "private-keys";
let PRODUCT = "Private";
export function configureBrowser(options: { product: string; database: string }) {
  PRODUCT = options.product;
  DB = options.database;
}
const STORE = "keys";
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
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

export async function rememberHere(meta: VaultMeta, recordsKey: Uint8Array) {
  try {
    const deviceKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = random(12);
    const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, deviceKey, own(recordsKey));
    await idb("readwrite", (s) => s.put({ deviceKey, iv, wrapped } satisfies Kept, meta.publicKey));
  } catch {
  }
}
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
export async function forgetHere() {
  try {
    await idb("readwrite", (s) => s.clear());
  } catch {}
}

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer } };
const prfOf = (c: PublicKeyCredential) => (c.getClientExtensionResults() as { prf?: PrfResults }).prf;

export const passkeysPossible = () => typeof PublicKeyCredential !== "undefined" && !!navigator.credentials;

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
  if (!first && prf?.enabled) first = (await passkeySecret([{ kind: "passkey", credential, salt: b64(salt), wrapped: "", created: "" }]))?.secret.buffer as ArrayBuffer | undefined;
  if (!first) return null;
  return { wrap: { kind: "passkey", credential, salt: b64(salt), created: new Date().toISOString().slice(0, 10), name: "Passkey" }, secret: new Uint8Array(first) };
}

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

export async function unlockWithPasskey(meta: VaultMeta) {
  const found = await passkeySecret(meta.wraps);
  if (!found) return null;
  const key = unwrapKey(found.secret, found.wrap.wrapped, "passkey");
  keysFrom(key, meta);
  return key;
}
export const unlockWithRecovery = recordsKeyFromRecovery;

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
  }
  return { recordsKey, meta, recoveryText: recoveryText(recovery), passkey };
}
