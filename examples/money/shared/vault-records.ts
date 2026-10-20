import { emptyState, validateState, type State } from "./model";
import type { Keys, LockedRow } from "./private/private.ts";
import { bucketsOf, changedRows, openedRows, type PlainBucket, type RowCache } from "./private/rows.ts";

// Money's records as Private keeps them (shared/private, a copy of src/): locked rows the
// server stores and cannot read. Records are kept in buckets (a month of transactions, a currency's rates, a section's plans), so the store
// learns neither ids nor how many payments there are, and a change locks only its own bucket.

/** One locked row: a section's name (so a free account can be refused transactions), the bucket's hashed key, and the locked value. */
export type VaultRow = LockedRow;
/** What a device last read: each row's key and its value before locking, to send only what changed. */
export type VaultCache = RowCache;
export type VaultChanges = { put: VaultRow[]; del: string[] };

export const VAULT_SECTIONS = ["meta", "accounts", "snapshots", "transactions", "plans", "imports", "import-rows", "views", "invoices", "goals", "rates"] as const;
export type VaultSection = (typeof VAULT_SECTIONS)[number];
/** What a free account may not keep (shared/accounts.ts): transactions and anything imported. */
export const PAID_SECTIONS: VaultSection[] = ["transactions", "imports", "import-rows"];

type ImportRow = { importId: string; index: number; row: State["imports"][number]["rows"][number] };
const listed = ["accounts", "snapshots", "transactions", "plans", "imports", "views", "invoices", "goals", "rates"] as const;

function bucketOf(section: VaultSection, record: unknown): string {
  switch (section) {
    case "transactions":
    case "snapshots":
      return String((record as { date: string }).date).slice(0, 7);
    case "rates":
      return (record as { currency: string }).currency;
    case "import-rows": {
      const r = record as ImportRow;
      return `${r.importId}/${Math.floor(r.index / 500)}`;
    }
    default:
      return "all";
  }
}

const idOf = (section: VaultSection, record: unknown) =>
  section === "import-rows" ? `${(record as ImportRow).importId}/${String((record as ImportRow).index).padStart(8, "0")}` : String((record as { id: string }).id);

/** Every bucket's plain value, by its name, ready to lock. */
export function plainBuckets(state: State): PlainBucket[] {
  const { version: _version, ...rest } = state;
  const meta = Object.fromEntries(Object.entries(rest).filter(([k]) => !(listed as readonly string[]).includes(k)));
  const sections: [VaultSection, unknown[]][] = listed.map((s) => [s, s === "imports" ? state.imports.map(({ rows: _, ...i }) => ({ ...i, rows: [] })) : (state[s] as unknown[])]);
  sections.push(["import-rows", state.imports.flatMap((i) => i.rows.map((row, index) => ({ importId: i.id, index, row })))]);
  return [{ section: "meta", bucket: "meta", plain: JSON.stringify(meta) }, ...sections.flatMap(([section, records]) => bucketsOf(section, records, (r) => bucketOf(section, r), (r) => idOf(section, r)))];
}

/** The rows to send: those whose plain value differs from what the device last read, and those gone. */
export const vaultChanges = (state: State, keys: Keys, cache: VaultCache) => changedRows(plainBuckets(state), keys, cache);

/** Every row locked, for a new vault or one moved over from plain records. */
export const lockAll = (state: State, keys: Keys) => vaultChanges(state, keys, {});

/** The records the rows hold, and the cache to diff the next save against. */
export function openRows(rows: VaultRow[], version: number, keys: Keys): { state: State; cache: VaultCache } {
  const s: Record<string, unknown> = { ...emptyState() };
  for (const key of listed) s[key] = [];
  const importRows: ImportRow[] = [];
  const { plain, cache } = openedRows(rows, keys, VAULT_SECTIONS);
  for (const row of plain) {
    const value = JSON.parse(row.plain);
    if (row.section === "meta") Object.assign(s, value);
    else if (row.section === "import-rows") importRows.push(...(value as ImportRow[]));
    else (s[row.section] as unknown[]).push(...(value as unknown[]));
  }
  for (const key of listed) (s[key] as { id: string }[]).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  importRows.sort((a, b) => (a.importId < b.importId ? -1 : a.importId > b.importId ? 1 : a.index - b.index));
  for (const i of s.imports as State["imports"]) i.rows = importRows.filter((r) => r.importId === i.id).map((r) => r.row);
  s.version = version;
  return { state: validateState(s), cache };
}
