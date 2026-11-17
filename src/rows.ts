import { lockRow, rowKey, unlockRow, type Keys, type LockedRow } from "./private.ts";

export type PlainBucket = { section: string; bucket: string; plain: string };
export type RowCache = Record<string, { section: string; plain: string }>;
export type RowChanges = { put: LockedRow[]; del: string[]; cache: RowCache };

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
