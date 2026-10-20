# Private

Records only the person's own devices can open.

Private locks a person's records with a key that exists only on their iPhone and in their browser. The server keeps the locked rows, and so do its database, backups and logs, but it cannot open them. Whoever runs it cannot read them either. It is the code behind [Money, money, money](https://moneymoneymoney.app)'s Private, published so anyone can check what it does.

## What is here

| Path | What it does |
|---|---|
| `src/private.ts` | Keys, locking, sealing and recovery. A random 32-byte records key per person. Rows are locked with AES-256-GCM, with their section and key bound as associated data, and found by an HMAC of their id. An X25519 exchange pair, drawn from the records key, lets anyone seal something only the person can open. The records key is wrapped by a passkey's PRF secret, a 54-letter recovery key or a device key. One implementation for browsers, Cloudflare Workers, tests and an app's JavaScriptCore. |
| `src/rows.ts` | A product's records in buckets: only the buckets that changed are sent, then opened and checked. |
| `src/store.ts` | The store in a SQLite Durable Object: locked rows with a version check, locked files, and a sealed inbox. Its `adopt` takes the first locked rows and deletes the plain ones in the same transaction. |
| `src/browser.ts` | The records key kept in IndexedDB, wrapped by a non-extractable Web Crypto key; passkeys used only for their PRF secret. |
| `examples/money/` | How Money uses it, for reading: its records in buckets, its device session, its routes, the web's lock and unlock screens, the iPhone bridge and CryptoKit cipher, and their tests. They import Money's own modules and do not build here. |
| `THREAT-MODEL.md` | What is protected, from whom, and what is not. |

The cryptography is [noble](https://paulmillr.com/noble/): `@noble/ciphers`, `@noble/curves` and `@noble/hashes`, audited and MIT-licensed. Private adds no primitives of its own.

## Use

```bash
pnpm install
pnpm test
```

```ts
import { keysFrom, newRecordsKey, newVault, newRecoverySecret, recoveryText, wrapKey } from "./src/private.ts";
import { bucketsOf, changedRows, openedRows } from "./src/rows.ts";

const recordsKey = newRecordsKey();
const keys = keysFrom(recordsKey);
const recovery = newRecoverySecret(); // show recoveryText(recovery) to the person once
const meta = { ...newVault(keys), wraps: [{ kind: "recovery", wrapped: wrapKey(recovery, recordsKey, "recovery"), created: "2026-10-20" }] };
const { put } = changedRows(bucketsOf("payments", payments, (p) => p.date.slice(0, 7), (p) => p.id), keys, {});
// send meta and put to the store; later, openedRows(rows, keys, ["payments"]) on the device
```

## Format

- **Locked text:** `v1.` followed by the base64url of the 12-byte nonce, the ciphertext and the 16-byte tag. This is CryptoKit's combined box, so an app can use the platform's own AES-GCM (`useTextCipher`).
- **Sealed values:** `s1.` followed by the base64url of the ephemeral X25519 public key and the locked bytes.
- **Labels:** the key-derivation labels read `money/v1/…` because Money made the first vaults. A new label means a new version, never an edit.

## Report a problem

Please report anything that weakens the promise privately: see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
