import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, fingerprint, lockText, unlockText, useTextCipher, fromUtf8, keysFrom, newRecordsKey, newRecoverySecret, newVault, openSealedJson, recordsKeyFromRecovery, recoverySecret, recoveryText, sealJson, unb64, utf8, wrapKey } from "../src/private.ts";
import { bucketsOf, changedRows, openedRows } from "../src/rows.ts";

test("bytes, words and the recovery key read back exactly; a typo is caught", () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33]) {
    const bytes = crypto.getRandomValues(new Uint8Array(n));
    assert.deepEqual([...unb64(b64(bytes))], [...bytes]);
  }
  for (const text of ["", "Netto", "¥1,200 ラーメン", "Ærø", "𝔐 💴"]) {
    assert.deepEqual([...utf8(text)], [...new TextEncoder().encode(text)]);
    assert.equal(fromUtf8(new TextEncoder().encode(text)), text);
  }
  const secret = newRecoverySecret();
  const text = recoveryText(secret);
  assert.match(text, /^([0-9A-Z]{6}-){8}[0-9A-Z]{6}$/);
  assert.deepEqual([...recoverySecret(text.toLowerCase())], [...secret]);
  assert.throws(() => recoverySecret(text.slice(0, 3) + (text[3] === "A" ? "B" : "A") + text.slice(4)));
});

test("rows lock and open only with their key, in their place; only changes are sent", () => {
  const keys = keysFrom(newRecordsKey());
  const records = Array.from({ length: 40 }, (_, i) => ({ id: `r${i}`, date: `2026-${String((i % 3) + 1).padStart(2, "0")}-01`, words: `Secret shop ${i}` }));
  const buckets = bucketsOf("payments", records, (r) => r.date.slice(0, 7), (r) => r.id);
  const first = changedRows(buckets, keys, {});
  assert.equal(first.put.length, 3);
  assert.ok(!JSON.stringify(first.put).includes("Secret shop"));
  assert.equal(openedRows(first.put, keys, ["payments"]).plain.length, 3);
  assert.throws(() => openedRows(first.put, keysFrom(newRecordsKey()), ["payments"]));
  assert.throws(() => openedRows(first.put.map((r, i) => (i === 0 ? { ...r, key: first.put[1].key } : r)), keys, ["payments"]));
  const next = bucketsOf("payments", records.map((r) => (r.id === "r0" ? { ...r, words: "Changed" } : r)), (r) => r.date.slice(0, 7), (r) => r.id);
  assert.equal(changedRows(next, keys, first.cache).put.length, 1);
});

test("the records key comes back through the recovery key alone; seals open only for their person and purpose", () => {
  const records = newRecordsKey();
  const keys = keysFrom(records);
  const recovery = newRecoverySecret();
  const meta = { ...newVault(keys), wraps: [{ kind: "recovery" as const, wrapped: wrapKey(recovery, records, "recovery"), created: "2026-10-20" }] };
  assert.deepEqual([...recordsKeyFromRecovery(meta, recoveryText(recovery))], [...records]);
  assert.throws(() => recordsKeyFromRecovery(meta, recoveryText(newRecoverySecret())));
  assert.throws(() => keysFrom(newRecordsKey(), meta));
  const sealed = sealJson(keys.exchange.publicKey, { words: "Secret bakery" }, "inbox");
  assert.ok(!sealed.includes("Secret"));
  assert.deepEqual(openSealedJson(keys, sealed, "inbox"), { words: "Secret bakery" });
  assert.throws(() => openSealedJson(keys, sealed, "share"));
  assert.match(fingerprint(meta.publicKey), /^[0-9A-F]{2}( [0-9A-F]{2}){3}$/);
});

test("a platform's own cipher writes and reads the same locked text", async () => {
  const key = newRecordsKey();
  const { gcm } = await import("@noble/ciphers/aes.js");
  // A stand-in for CryptoKit: AES-GCM over the combined nonce, ciphertext and tag.
  useTextCipher({
    lock: (k, text, aad) => {
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const sealed = gcm(unb64(k), nonce, utf8(aad)).encrypt(utf8(text));
      return `v1.${b64(new Uint8Array([...nonce, ...sealed]))}`;
    },
    unlock: (k, locked, aad) => {
      const bytes = unb64(locked.slice(3));
      return fromUtf8(gcm(unb64(k), bytes.subarray(0, 12), utf8(aad)).decrypt(bytes.subarray(12)));
    },
  });
  const byNative = lockText(key, "Secret ¥1,200", "row/x");
  useTextCipher(null);
  assert.equal(unlockText(key, byNative, "row/x"), "Secret ¥1,200");
  assert.throws(() => unlockText(key, byNative, "row/y"));
});
