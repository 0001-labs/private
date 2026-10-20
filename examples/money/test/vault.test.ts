import { expect, it } from "vite-plus/test";
import { sampleState } from "../ios/core/sample";
import { validateState } from "../shared/model";
import { lockAll, openRows, vaultChanges } from "../shared/vault-records";
import {
  b64,
  fingerprint,
  keysFrom,
  newRecordsKey,
  newRecoverySecret,
  newVault,
  openSealedJson,
  recoverySecret,
  recoveryText,
  sealJson,
  unb64,
  unwrapKey,
  wrapKey,
} from "../shared/private/private.ts";

const today = "2026-10-20";
/** Words, amounts and ids from the made-up records that must never show in what the server keeps. */
function secretsOf(state: ReturnType<typeof sampleState>) {
  const words = new Set<string>();
  for (const a of state.accounts) words.add(a.name);
  for (const t of state.transactions.slice(0, 200)) {
    words.add(t.description);
    words.add(t.id);
    words.add(`"amount":${t.amount}`);
  }
  for (const p of state.plans) words.add(p.title);
  // Six characters or more, so a word cannot turn up in the random letters of the locked text by chance.
  return [...words].filter((w) => w.length >= 6);
}

it("base64 and the recovery key read back exactly, and a typo is caught", () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33]) {
    const bytes = crypto.getRandomValues(new Uint8Array(n));
    expect([...unb64(b64(bytes))]).toEqual([...bytes]);
  }
  const secret = newRecoverySecret();
  const text = recoveryText(secret);
  expect(text).toMatch(/^([0-9A-Z]{6}-){8}[0-9A-Z]{6}$/);
  expect([...recoverySecret(text.toLowerCase().replace(/-/g, " "))]).toEqual([...secret]);
  const typo = text.slice(0, 3) + (text[3] === "A" ? "B" : "A") + text.slice(4);
  expect(() => recoverySecret(typo)).toThrow();
});

it("locks every record and opens them again whole, with only the right key", () => {
  const state = validateState(sampleState(today));
  const keys = keysFrom(newRecordsKey());
  const { put, cache } = lockAll(state, keys);
  const opened = openRows(put, 7, keys);
  // Each section comes back in id order, as the store has always read it.
  const byId = <T extends { id: string }>(xs: T[]) => [...xs].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const sorted = Object.fromEntries(Object.entries(state).map(([k, v]) => [k, Array.isArray(v) && typeof v[0] === "object" ? byId(v as { id: string }[]) : v]));
  expect(opened.state).toEqual({ ...sorted, version: 7 });
  expect(opened.cache).toEqual(cache);
  const other = keysFrom(newRecordsKey());
  expect(() => openRows(put, 7, other)).toThrow();
});

it("keeps nothing readable: no names, words, amounts or ids in the stored rows", () => {
  const state = validateState(sampleState(today));
  const keys = keysFrom(newRecordsKey());
  const { put } = lockAll(state, keys);
  const stored = JSON.stringify(put);
  for (const secret of secretsOf(state)) expect(stored).not.toContain(secret);
  // A row's key is a hash, the same length whatever it names.
  expect(new Set(put.map((r) => r.key.length))).toEqual(new Set([32]));
  // Transactions are kept by month, so the store learns how many months, never how many payments.
  expect(put.filter((r) => r.section === "transactions").length).toBeLessThan(state.transactions.length);
});

it("a row moved to another place or changed by the store is refused", () => {
  const state = validateState(sampleState(today));
  const keys = keysFrom(newRecordsKey());
  const { put } = lockAll(state, keys);
  const [a, b] = put.filter((r) => r.section === "transactions");
  expect(() => openRows(put.map((r) => (r === a ? { ...a, key: b.key } : r)), 1, keys)).toThrow();
  const flipped = a.value.slice(0, -2) + (a.value.at(-2) === "A" ? "B" : "A") + a.value.at(-1);
  expect(() => openRows(put.map((r) => (r === a ? { ...a, value: flipped } : r)), 1, keys)).toThrow();
  expect(() => openRows(put.map((r) => (r === a ? { ...a, section: "plans" } : r)), 1, keys)).toThrow();
});

it("sends only the buckets that changed", () => {
  const state = validateState(sampleState(today));
  const keys = keysFrom(newRecordsKey());
  const first = lockAll(state, keys);
  const latest = [...state.transactions].sort((x, y) => (x.date < y.date ? 1 : -1))[0];
  const next = { ...state, transactions: state.transactions.map((t) => (t.id === latest.id ? { ...t, note: "Changed" } : t)) };
  const changes = vaultChanges(next, keys, first.cache);
  expect(changes.put.map((r) => r.section)).toEqual(["transactions"]);
  expect(changes.del).toEqual([]);
  const gone = vaultChanges({ ...state, plans: [] }, keys, first.cache);
  expect(gone.del.length + gone.put.length).toBeGreaterThan(0);
  expect(vaultChanges(state, keys, first.cache).put).toEqual([]);
});

it("the records key comes back only through its wraps, and the vault knows its own key", () => {
  const records = newRecordsKey();
  const keys = keysFrom(records);
  const meta = newVault(keys);
  const recovery = newRecoverySecret();
  const prf = crypto.getRandomValues(new Uint8Array(32));
  const byRecovery = wrapKey(recovery, records, "recovery");
  const byPasskey = wrapKey(prf, records, "passkey");
  expect([...unwrapKey(recovery, byRecovery, "recovery")]).toEqual([...records]);
  expect([...unwrapKey(prf, byPasskey, "passkey")]).toEqual([...records]);
  expect(() => unwrapKey(prf, byRecovery, "recovery")).toThrow();
  expect(() => unwrapKey(recovery, byRecovery, "passkey")).toThrow();
  expect(() => keysFrom(records, meta)).not.toThrow();
  expect(() => keysFrom(newRecordsKey(), meta)).toThrow("does not open");
  expect(JSON.stringify(meta)).not.toContain(b64(records));
  expect(fingerprint(meta.publicKey)).toMatch(/^[0-9A-F]{2}( [0-9A-F]{2}){3}$/);
});

it("what is sealed to a person opens only with their key, and only for its purpose", () => {
  const keys = keysFrom(newRecordsKey());
  const sealed = sealJson(keys.exchange.publicKey, { description: "Netto", amount: 4550 }, "feed");
  expect(sealed).not.toContain("Netto");
  expect(openSealedJson(keys, sealed, "feed")).toEqual({ description: "Netto", amount: 4550 });
  expect(() => openSealedJson(keys, sealed, "share")).toThrow();
  expect(() => openSealedJson(keysFrom(newRecordsKey()), sealed, "feed")).toThrow();
});

it("writes and reads UTF-8 as the platform does, without TextEncoder", async () => {
  const { utf8, fromUtf8 } = await import("../shared/private/private.ts");
  for (const text of ["", "Netto", "80.67 kr", "¥1,200 ラーメン", "Ærø · København", "𝔐oney 💴", "a\u0000b"]) {
    expect([...utf8(text)]).toEqual([...new TextEncoder().encode(text)]);
    expect(fromUtf8(new TextEncoder().encode(text))).toBe(text);
  }
});
