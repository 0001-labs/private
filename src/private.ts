import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

// Private: records only the person's own
// devices can open. Every record is locked on the person's device with their records key, which the
// server never holds, so whoever runs the server, its database, backups and logs sees only what this
// file writes. One implementation for browsers, Workers, tests and an iPhone app's JavaScriptCore
// (which has no Web Crypto): the audited noble libraries do the work everywhere.
//
// - The records key (32 random bytes) locks each row with AES-256-GCM, its place and purpose bound
//   as associated data. Rows are found by an HMAC of their id, never the id itself.
// - The exchange key pair (X25519, drawn from the records key) lets anyone seal something only the
//   person can open: what an assistant sends, a share someone writes for them, an edit to a list.
// - The records key reaches a new device wrapped: by a passkey's PRF secret, by the recovery key, or
//   by that device's own key. The server keeps the wrapped copies, which open nothing without those.

export const PRIVATE_VERSION = 1;

/** UTF-8 written by hand: JavaScriptCore has no TextEncoder. */
export function utf8(s: string) {
  const out: number[] = [];
  for (const ch of s) {
    let c = ch.codePointAt(0)!;
    if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}
export function fromUtf8(b: Uint8Array) {
  let out = "";
  for (let i = 0; i < b.length; ) {
    const x = b[i];
    const n = x < 0x80 ? 1 : x >= 0xf0 ? 4 : x >= 0xe0 ? 3 : x >= 0xc0 ? 2 : 1;
    let c = n === 1 ? (x < 0x80 ? x : 0xfffd) : x & (0xff >> (n + 1));
    for (let k = 1; k < n; k++) c = (c << 6) | ((b[i + k] ?? 0) & 63);
    out += String.fromCodePoint(c > 0x10ffff ? 0xfffd : c);
    i += n;
  }
  return out;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** Base64url without padding, written by hand: JavaScriptCore has no btoa. */
export function b64(bytes: Uint8Array) {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i < bytes.length) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : "");
  }
  return out;
}
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));
export function unb64(text: string) {
  const clean = text.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const c of clean) {
    const v = B64_INDEX.get(c);
    if (v === undefined) throw Error("Not base64");
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 255;
    }
  }
  return out.subarray(0, o);
}

// Private's v1 labels read "money/v1" because Money made the first vaults with them; every product uses
// them unchanged, since each person's keys are random. A new label is a new version, never an edit.
const LABEL = "money/v1";
const derive = (key: Uint8Array, info: string, length = 32) => hkdf(sha256, key, undefined, utf8(`${LABEL}/${info}`), length);

/** The keys one records key opens: rows are locked with `rows`, found by `index`. */
export type Keys = { records: Uint8Array; rows: Uint8Array; index: Uint8Array; exchange: { publicKey: Uint8Array; privateKey: Uint8Array } };

export const newRecordsKey = () => randomBytes(32);

/** A random key for one kept file; it travels inside the transaction that shows the file. */
export const newFileKey = () => randomBytes(32);

/** Locks bytes with a key: "v1." and the nonce and ciphertext. `aad` binds them to where they belong. */
export function lock(key: Uint8Array, plain: Uint8Array, aad: string) {
  const nonce = randomBytes(12);
  const sealed = gcm(key, nonce, utf8(aad)).encrypt(plain);
  const out = new Uint8Array(12 + sealed.length);
  out.set(nonce);
  out.set(sealed, 12);
  return out;
}
export function unlock(key: Uint8Array, locked: Uint8Array, aad: string) {
  if (locked.length < 28) throw Error("Locked data is too short");
  return gcm(key, locked.subarray(0, 12), utf8(aad)).decrypt(locked.subarray(12));
}
/**
 * A platform's own AES-256-GCM for text, where JavaScript is slow (an iPhone app's JavaScriptCore runs
 * without a JIT): the same format, "v1." and base64url of the nonce, ciphertext and tag, as CryptoKit's
 * combined box writes it. The key arrives as base64url. `unlock` throws on a wrong key or changed text.
 */
export type TextCipher = { lock(key: string, text: string, aad: string): string; unlock(key: string, locked: string, aad: string): string };
let native: TextCipher | null = null;
const keyNames = new WeakMap<Uint8Array, string>();
const nameOf = (key: Uint8Array) => keyNames.get(key) ?? (keyNames.set(key, b64(key)), keyNames.get(key)!);
/** Locks and opens text with the platform's cipher from now on (null: this file's own). */
export function useTextCipher(cipher: TextCipher | null) {
  native = cipher;
}
export const lockText = (key: Uint8Array, text: string, aad: string) => (native ? native.lock(nameOf(key), text, aad) : `v1.${b64(lock(key, utf8(text), aad))}`);
export function unlockText(key: Uint8Array, locked: string, aad: string) {
  if (!locked.startsWith("v1.")) throw Error("Not locked by Private");
  if (native) return native.unlock(nameOf(key), locked, aad);
  return fromUtf8(unlock(key, unb64(locked.slice(3)), aad));
}

/** Seals bytes so only the holder of `publicKey`'s private half can open them (X25519, HKDF, AES-GCM). */
export function seal(publicKey: Uint8Array, plain: Uint8Array, purpose: string) {
  const ephemeral = x25519.utils.randomSecretKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeral);
  const shared = x25519.getSharedSecret(ephemeral, publicKey);
  const key = hkdf(sha256, shared, concat(ephemeralPublic, publicKey), utf8(`${LABEL}/seal/${purpose}`), 32);
  return `s1.${b64(concat(ephemeralPublic, lock(key, plain, purpose)))}`;
}
export function openSealed(keys: Pick<Keys, "exchange">, sealed: string, purpose: string) {
  if (!sealed.startsWith("s1.")) throw Error("Not sealed by Private");
  const bytes = unb64(sealed.slice(3));
  const ephemeralPublic = bytes.subarray(0, 32);
  const shared = x25519.getSharedSecret(keys.exchange.privateKey, ephemeralPublic);
  const key = hkdf(sha256, shared, concat(ephemeralPublic, keys.exchange.publicKey), utf8(`${LABEL}/seal/${purpose}`), 32);
  return unlock(key, bytes.subarray(32), purpose);
}
export const sealJson = (publicKey: Uint8Array, value: unknown, purpose: string) => seal(publicKey, utf8(JSON.stringify(value)), purpose);
export const openSealedJson = <T>(keys: Pick<Keys, "exchange">, sealed: string, purpose: string) => JSON.parse(fromUtf8(openSealed(keys, sealed, purpose))) as T;

function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * What the server keeps of a vault: the public half of the exchange pair (its private half is drawn
 * from the records key), a check that a records key is the right one, and the records key wrapped
 * for each way back in. Nothing here opens a record without a passkey, the recovery key or a device.
 */
export type Wrap =
  | { kind: "recovery"; wrapped: string; created: string }
  | { kind: "passkey"; credential: string; salt: string; wrapped: string; created: string; name?: string };
export type VaultMeta = { v: 1; publicKey: string; check: string; wraps: Wrap[] };

const CHECK = "money-vault-check";

/** Everything a records key opens; with the vault's meta, it must be that vault's key. */
export function keysFrom(records: Uint8Array, meta?: Pick<VaultMeta, "check" | "publicKey">): Keys {
  const rows = derive(records, "rows");
  const index = derive(records, "index");
  const privateKey = derive(records, "exchange");
  const publicKey = x25519.getPublicKey(privateKey);
  if (meta) {
    let check = "";
    try {
      check = unlockText(rows, meta.check, "check");
    } catch {}
    if (check !== CHECK) throw Error("That key does not open these records");
    if (b64(publicKey) !== meta.publicKey) throw Error("These records' public key is not their own");
  }
  return { records, rows, index, exchange: { privateKey, publicKey } };
}

/** A new vault's meta for a records key. */
export function newVault(keys: Keys): VaultMeta {
  return { v: 1, publicKey: b64(keys.exchange.publicKey), check: lockText(keys.rows, CHECK, "check"), wraps: [] };
}

/** The records key wrapped by a secret only the person has (a passkey's PRF output, the recovery key). */
export function wrapKey(secret: Uint8Array, records: Uint8Array, purpose: "recovery" | "passkey" | "device") {
  return `v1.${b64(lock(derive(secret, `wrap/${purpose}`), records, `wrap/${purpose}`))}`;
}
export function unwrapKey(secret: Uint8Array, wrapped: string, purpose: "recovery" | "passkey" | "device") {
  if (!wrapped.startsWith("v1.")) throw Error("Not wrapped by Private");
  return unlock(derive(secret, `wrap/${purpose}`), unb64(wrapped.slice(3)), `wrap/${purpose}`);
}

// The recovery key: 32 random bytes written in Crockford's base32 (no I, L, O or U to misread), with
// two check letters, in nine groups of six.
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const newRecoverySecret = () => randomBytes(32);
export function recoveryText(secret: Uint8Array) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of secret) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(value >> bits) & 31];
    }
  }
  if (bits) out += B32[(value << (5 - bits)) & 31];
  const check = sha256(secret);
  out += B32[check[0] & 31] + B32[check[1] & 31];
  return out.match(/.{1,6}/g)!.join("-");
}
export function recoverySecret(text: string) {
  const clean = text.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  if (clean.length !== 54 || [...clean].some((c) => !B32.includes(c))) throw Error("A recovery key has 54 letters and digits");
  const out = new Uint8Array(32);
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const c of clean.slice(0, 52)) {
    value = ((value << 5) | B32.indexOf(c)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 255;
    }
  }
  const check = sha256(out);
  if (clean.slice(52) !== B32[check[0] & 31] + B32[check[1] & 31]) throw Error("That recovery key has a typo");
  return out;
}

/** One locked row as a store keeps it: its section's name, its hashed key, and the locked value. */
export type LockedRow = { section: string; key: string; value: string };

/** A row's place in the store: its id hashed with the person's own key, so the id never shows. */
export const rowKey = (keys: Pick<Keys, "index">, section: string, id: string) => b64(hmac(sha256, keys.index, utf8(`${section}\u0000${id}`))).slice(0, 32);
export const lockRow = (keys: Pick<Keys, "rows">, section: string, key: string, value: string) => lockText(keys.rows, value, `row/${section}/${key}`);
export const unlockRow = (keys: Pick<Keys, "rows">, section: string, key: string, value: string) => unlockText(keys.rows, value, `row/${section}/${key}`);

/** A short fingerprint of a public key, to compare with the person a list is shared with. */
export const fingerprint = (publicKey: string) => {
  const h = sha256(utf8(publicKey));
  return Array.from(h.subarray(0, 4), (b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase();
};

/** The records key a recovery key opens, as typed, checked against the vault. */
export function recordsKeyFromRecovery(meta: VaultMeta, typed: string) {
  const secret = recoverySecret(typed);
  for (const w of meta.wraps)
    if (w.kind === "recovery")
      try {
        const key = unwrapKey(secret, w.wrapped, "recovery");
        keysFrom(key, meta);
        return key;
      } catch {}
  throw Error("That recovery key does not open these records");
}
