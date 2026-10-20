# Threat model

## Promise

A product using Private, with the person's records locked, keeps nothing on its servers that its operator can read. The operator could:

- read the database directly
- read any backup or log
- deploy server code that reads every store
- sign in as the person, by controlling the sign-in service

None of these yields a readable record, file or share.

## How

- **The records key is made on the person's device and never sent unwrapped.** The server keeps the public key, a check value, and copies wrapped by secrets it never sees: a passkey's PRF output and a recovery key. Each device keeps its own wrapped copy.
- **Each record bucket is locked with AES-256-GCM.** Its section and hashed key are associated data, so a row cannot be moved or swapped unnoticed. Bucket keys are HMACs, so ids (which may contain words and amounts) and record counts are hidden.
- **Once a store is locked, the product's plain read and write paths refuse it.** The first lock deletes the plain records in the same transaction.
- **Senders without the key seal to the person's public key:** an assistant adding payments, or someone sharing a list. Only the person's device opens what they sent.

## What it does not protect

- **Data in transit to the device.** Anything a server or a third party must read passes through in plain for that moment: an assistant's send before it is sealed, a file an AI model reads. Money says so and keeps none of it readable.
- **Metadata.** The operator still sees:
  - who has an account, their email and plan
  - how much is stored, and when it changes
  - which currencies' exchange rates are asked for
  - which shops' logos are asked for
  - who shares with whom
- **The code that holds the key.** In a browser, the operator serves the page that holds the key and could change it. Publishing this code, and the hash of each released bundle, lets anyone check what was served. An iPhone app's code is fixed in its signed build.
- **Earlier plain copies.** Point-in-time recovery at the host keeps them for its window after the first lock.
- **Rollback.** The server could serve an older set of locked rows. Nothing detects this yet.
- **Key substitution.** The operator could swap a recipient's public key to read a share meant for them. `fingerprint()` exists so people can compare keys out of band, but no screen shows it yet.
- **Lost keys.** If the person loses every device, their passkey and their recovery key, nobody can open the records, including the operator. This is by design.

## Cryptography

AES-256-GCM, X25519, HKDF-SHA-256 and HMAC-SHA-256 from the audited noble libraries. Nonces are random, 96 bits, and each key's use is bounded by its purpose label.
