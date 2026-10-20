import { unb64, type LockedRow as VaultRow, type VaultMeta, type Wrap } from "./private.ts";

// Private's store: a person's locked records in a SQLite Durable Object
// of their own. The store keeps what the person's devices send and cannot read any of it: rows locked
// with a key it never sees, files locked with keys kept inside those rows, and an inbox of what others
// sealed to the person's public key (an assistant's send, an edit to a shared list). Once a store
// holds a vault, the product deletes its plain records in the same step (`adopt`'s `clear`) and every
// plain path must refuse it.

type Sql = DurableObjectStorage["sql"];

/** The most a person's inbox holds before senders are asked to wait for the person to open the product. */
export const INBOX_LIMIT = 2_000;
/** The most a locked file weighs: a kept receipt of 1.9 MB, locked and written in base64. */
export const FILE_MAX = 2_700_000;
/** A store row's limit, less room. */
const ROW_MAX = 1_900_000;

export type Sealed = { id: string; kind: string; body: string; created: number; meta: Record<string, string> };

const isMeta = (v: unknown): v is VaultMeta => {
  const m = v as VaultMeta;
  return !!m && m.v === 1 && typeof m.publicKey === "string" && unb64(m.publicKey).length === 32 && typeof m.check === "string" && m.check.startsWith("v1.") && Array.isArray(m.wraps) && m.wraps.length <= 20 && m.wraps.every(isWrap);
};
const isWrap = (w: Wrap) =>
  !!w &&
  typeof w.wrapped === "string" &&
  w.wrapped.startsWith("v1.") &&
  w.wrapped.length < 200 &&
  (w.kind === "recovery" || (w.kind === "passkey" && typeof w.credential === "string" && w.credential.length < 400 && typeof w.salt === "string" && w.salt.length < 100));

export class VaultTables {
  /** `sections` names the product's sections; a row in any other is refused. */
  constructor(
    private readonly sql: Sql,
    private readonly transaction: <T>(fn: () => T) => T,
    private readonly sections: readonly string[],
  ) {
    sql.exec("CREATE TABLE IF NOT EXISTS vault (name TEXT PRIMARY KEY, value TEXT NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS vault_rows (key TEXT PRIMARY KEY, section TEXT NOT NULL, value TEXT NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS vault_files (id TEXT PRIMARY KEY, body BLOB NOT NULL, created INTEGER NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS sealed (id TEXT PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL, meta TEXT NOT NULL, created INTEGER NOT NULL)");
  }
  private value(name: string) {
    return this.sql.exec<{ value: string }>("SELECT value FROM vault WHERE name = ?", name).toArray()[0]?.value ?? null;
  }
  meta(): VaultMeta | null {
    const v = this.value("meta");
    return v ? (JSON.parse(v) as VaultMeta) : null;
  }
  version() {
    return Number(this.value("version") ?? 0);
  }
  read() {
    return {
      meta: this.meta(),
      version: this.version(),
      rows: this.sql.exec<VaultRow>("SELECT section, key, value FROM vault_rows ORDER BY key").toArray().map((r) => ({ ...r })),
    };
  }
  /**
   * Takes the person's first locked rows in place of their plain records, in one step: the plain
   * records, receipts and uploads waiting to be read are deleted in the same transaction. `clear`
   * deletes the product's plain tables, so nothing readable stays behind.
   */
  adopt(meta: unknown, rows: VaultRow[], expected: number, current: number, clear: () => void) {
    if (!isMeta(meta)) throw Error("Refused: not a vault");
    if (meta.wraps.length === 0) throw Error("Refused: a vault needs a way back in");
    checkRows(rows, this.sections);
    return this.transaction(() => {
      if (this.meta()) throw Error("Conflict: these records are already locked.");
      if (expected !== current) throw Error("Conflict: another tab changed these records. Reload before saving.");
      clear();
      for (const r of rows) this.sql.exec("INSERT INTO vault_rows VALUES (?,?,?)", r.key, r.section, r.value);
      const version = current + 1;
      this.sql.exec("INSERT OR REPLACE INTO vault VALUES ('meta', ?)", JSON.stringify(meta));
      this.sql.exec("INSERT OR REPLACE INTO vault VALUES ('version', ?)", String(version));
      return { version };
    });
  }
  /** Writes what a device changed, if it read the version that is kept; `refuse` names sections this person may not keep. */
  write(put: VaultRow[], del: string[], expected: number, refuse: readonly string[] = []) {
    checkRows(put, this.sections);
    if (!Array.isArray(del) || del.some((k) => typeof k !== "string" || k.length > 64)) throw Error("Refused: unknown rows");
    if (put.some((r) => refuse.includes(r.section))) throw Error(`Refused: ${put.find((r) => refuse.includes(r.section))!.section}`);
    return this.transaction(() => {
      if (!this.meta()) throw Error("Refused: these records are not locked");
      const current = this.version();
      if (expected !== current) throw Error("Conflict: another tab changed these records. Reload before saving.");
      for (const k of del) this.sql.exec("DELETE FROM vault_rows WHERE key = ?", k);
      for (const r of put) this.sql.exec("INSERT OR REPLACE INTO vault_rows VALUES (?,?,?)", r.key, r.section, r.value);
      const version = current + 1;
      this.sql.exec("INSERT OR REPLACE INTO vault VALUES ('version', ?)", String(version));
      return { version };
    });
  }
  /** New ways back in (a passkey added, the recovery key replaced); the vault's own key cannot change here. */
  setWraps(meta: unknown) {
    if (!isMeta(meta)) throw Error("Refused: not a vault");
    const kept = this.meta();
    if (!kept) throw Error("Refused: these records are not locked");
    if (kept.publicKey !== meta.publicKey || kept.check !== meta.check) throw Error("Refused: a vault keeps its key");
    if (meta.wraps.length === 0) throw Error("Refused: a vault needs a way back in");
    this.sql.exec("INSERT OR REPLACE INTO vault VALUES ('meta', ?)", JSON.stringify({ ...kept, wraps: meta.wraps }));
  }
  filePut(id: string, body: Uint8Array) {
    if (body.byteLength > FILE_MAX) throw Error("Refused: file too large");
    this.sql.exec("INSERT OR REPLACE INTO vault_files VALUES (?,?,?)", id, body, Date.now());
  }
  fileGet(id: string) {
    const row = this.sql.exec<{ body: ArrayBuffer }>("SELECT body FROM vault_files WHERE id = ?", id).toArray()[0];
    return row ? row.body : null;
  }
  fileDelete(id: string) {
    this.sql.exec("DELETE FROM vault_files WHERE id = ?", id);
  }
  /** Keeps something sealed to the person, opened by their device the next time it reads. */
  sealedPut(s: Omit<Sealed, "created">) {
    const count = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sealed").toArray()[0].n;
    if (count >= INBOX_LIMIT) throw Error("Refused: the inbox is full until its owner opens it");
    this.sql.exec("INSERT OR IGNORE INTO sealed VALUES (?,?,?,?,?)", s.id, s.kind, s.body, JSON.stringify(s.meta), Date.now());
  }
  sealedList(): Sealed[] {
    return this.sql
      .exec<{ id: string; kind: string; body: string; meta: string; created: number }>("SELECT id, kind, body, meta, created FROM sealed ORDER BY created, id LIMIT 500")
      .toArray()
      .map((r) => ({ id: r.id, kind: r.kind, body: r.body, created: r.created, meta: JSON.parse(r.meta) }));
  }
  sealedCount() {
    return this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sealed").toArray()[0].n;
  }
  sealedDone(ids: string[]) {
    for (const id of ids.slice(0, 500)) this.sql.exec("DELETE FROM sealed WHERE id = ?", id);
  }
}

function checkRows(rows: VaultRow[], sections: readonly string[]) {
  if (!Array.isArray(rows)) throw Error("Refused: send rows");
  for (const r of rows)
    if (
      !r ||
      !sections.includes(r.section) ||
      typeof r.key !== "string" ||
      !/^[A-Za-z0-9_-]{32}$/.test(r.key) ||
      typeof r.value !== "string" ||
      !/^v1\.[A-Za-z0-9_-]+$/.test(r.value) ||
      r.value.length > ROW_MAX
    )
      throw Error("Refused: a row that is not locked");
}
