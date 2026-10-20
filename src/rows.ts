import { lockRow, rowKey, unlockRow, type Keys, type LockedRow } from "./private.ts";

// A product's records as Private keeps them: the product says how its records fall into buckets (a
// month of payments, a section's settings) and their plain values; this locks each bucket, sends only
// the buckets that changed, and opens them again. Buckets, not single records, so the store learns
// neither ids nor how many records there are, and a change locks only its own bucket.

/** One bucket before locking: its section (readable, so a store can refuse a section), its name and its plain value. */
export type PlainBucket = { section: string; bucket: string; plain: string };
/** What a device last read: each row's key and its value before locking, to send only what changes. */
export type RowCache = Record<string, { section: string; plain: string }>;
export type RowChanges = { put: LockedRow[]; del: string[]; cache: RowCache };

/** The rows to send: buckets whose plain value differs from what the device last read, and rows gone. */
export function changedRows(buckets: PlainBucket[], keys: Pick<Keys, "rows" | "index">, cache: RowCache): RowChanges {
  const next: RowCache = {};
  const put: LockedRow[] = [];
  for (const b of buckets) {
    const key = rowKey(keys, b.section, b.bucket);
    next[key] = { section: b.section, plain: b.plain };
    if (cache[key]?.plain !== b.plain || cache[key]?.section !== b.section) put.push({ section: b.section, key, value: lockRow(keys, b.section, key, b.plain) });
  }
  return { put, del: Object.keys(cache).filter((k) => !next[k]), cache: next };
}

/** Every row opened, refusing any not locked by these keys for its place: the plain values and the cache. */
export function openedRows(rows: LockedRow[], keys: Pick<Keys, "rows">, sections: readonly string[]) {
  const cache: RowCache = {};
  const plain: { section: string; plain: string }[] = [];
  for (const row of rows) {
    if (!sections.includes(row.section)) throw Error("An unknown section in the records");
    const value = unlockRow(keys, row.section, row.key, row.value);
    cache[row.key] = { section: row.section, plain: value };
    plain.push({ section: row.section, plain: value });
  }
  return { plain, cache };
}

/**
 * Cuts a section's records into buckets by `bucketOf`, in id order, each at most `max` characters
 * before locking (a store row's limit is two megabytes), a full bucket continuing as `name#1`, `#2`.
 */
export function bucketsOf<T>(section: string, records: T[], bucketOf: (r: T) => string, idOf: (r: T) => string, max = 900_000): PlainBucket[] {
  const out: PlainBucket[] = [];
  const buckets = new Map<string, T[]>();
  for (const r of [...records].sort((a, b) => (idOf(a) < idOf(b) ? -1 : 1))) {
    const name = bucketOf(r);
    if (!buckets.has(name)) buckets.set(name, []);
    buckets.get(name)!.push(r);
  }
  for (const [name, rows] of buckets) {
    let part: T[] = [];
    let size = 0;
    let n = 0;
    const flush = () => {
      out.push({ section, bucket: n ? `${name}#${n}` : name, plain: JSON.stringify(part) });
      n++;
      part = [];
      size = 0;
    };
    for (const r of rows) {
      const length = JSON.stringify(r).length;
      if (part.length && size + length > max) flush();
      part.push(r);
      size += length;
    }
    if (part.length) flush();
  }
  return out;
}
