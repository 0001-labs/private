# Money's use of Private

These are the files where [Money, money, money](https://moneymoneymoney.app) builds on Private. They are here to read, not to build: they import Money's own records model and app modules.

| File | What it does |
|---|---|
| `shared/vault-records.ts` | Money's records in buckets: a month of transactions or balances, a currency's rates, a section's plans. |
| `shared/vault-session.ts` | The device's side. It opens and saves locked rows, and adds what assistants sealed. It reads dropped files through a pass-through reader, files payments and scans for business ones. It claims codes by hashed ids, and seals each shared list to the people it is shared with. |
| `shared/on-read.ts` | What Money puts right each time records are read. This now runs on the device. |
| `server/vault.ts` | The Worker's routes for locked records, the pass-through readers (nothing kept, nothing logged) and sharing with keys. |
| `web/` | The lock and unlock screens, and the fetch boundary that answers the app's own requests from the vault. |
| `ios/` | The bridge that runs the same session in the iPhone's JavaScriptCore; CryptoKit's AES-GCM in Private's format; the Keychain. |
| `test/` | Tests showing a server that holds no readable word: moving plain records in, assistants' sends, dropped files and sharing. |

One step that applied only to the owner's own records was left out of `vault-session.ts` and `on-read.ts`.
