import { applyFiling, applyItems, applyScan, filingRows, keptFiling, keptScan, scanRows } from "./background";
import { decideBusiness } from "./business";
import { applyCodes, carryCodes, type CodedKind } from "./codes";
import { addFromFeed, deleteFromFeed, editFromFeed, FEED_BATCH, itemsForPayment, type FeedResult, type FeedTransaction } from "./feed";
import { unreadReceipts } from "./items";
import { money, validateState, type Item, type State } from "./model";
import { foldedWise, tidy } from "./on-read";
import { mergeRates, rateCurrencies, ratesFrom } from "./rates";
import { attachReceipt } from "./receipts";
import { emptyShared, sharedHome, type SharedHome } from "./shared-home";
import { applySharedEdit, sharedSlice } from "./sharing";
import { lockAll, openRows, vaultChanges, type VaultCache, type VaultRow } from "./vault-records";
import { b64, keysFrom, lock, newFileKey, openSealedJson, rowKey, sealJson, unb64, unlock, utf8, type Keys, type VaultMeta } from "./private/private.ts";

// A device's side of locked records. Everything the Worker did with
// plain records it now does here, on the person's own device, with their key: opening and saving
// the rows, what Money puts right on read, adding what assistants sealed to them, the drop zone's
// readings, filing, the business scan, codes, and sealing each shared list for the people it is
// shared with. The network is `api`, so the web and the iPhone's core run the same code.

export type Api = {
  /** A JSON request to Money's own `/api/…`; throws `ApiError` on a refusal. */
  json<T>(method: string, path: string, body?: unknown): Promise<T>;
  /** Bytes up or down: a locked file, or a file for a reader. */
  bytes(method: string, path: string, body?: Uint8Array, headers?: Record<string, string>): Promise<Uint8Array>;
  /** A file for a reader, answered with JSON. */
  send<T>(path: string, body: Uint8Array, headers: Record<string, string>): Promise<T>;
};
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
  }
}

export type Who = { owner: boolean; code: string | null; access: string };
type Served = { meta: VaultMeta | null; version: number; rows: VaultRow[]; inbox: number };
type Inbox = { id: string; kind: string; body: string; meta: Record<string, string> };
/** What a list's owner seals for each person it is shared with. */
export type ShareCopy = { list: string; owner: string; name: string; version: number; home: SharedHome; slice: ReturnType<typeof sharedSlice>; files: Record<string, string> };

const toB64Url = (text: string) => b64(utf8(text));
const keptFile = 1_900_000;
const keepable = (type: string) => type === "application/pdf" || ["image/jpeg", "image/png", "image/gif", "image/webp"].includes(type);

export class VaultSession {
  /** The records as last read or saved, and what each row held, to send only what changes. */
  state: State | null = null;
  private cache: VaultCache = {};
  /** The copies last sealed, by list and person, so an unchanged list is not sealed again. */
  private sealedAt = new Map<string, string>();
  /** What was shared with this person, opened: the lists and their files' keys. */
  copies: (ShareCopy & { role: string; ownerKey?: string })[] = [];

  constructor(
    readonly api: Api,
    readonly keys: Keys,
    readonly who: Who,
  ) {}

  /** One change at a time: a page's polling read never races its own save. */
  private queue: Promise<unknown> = Promise.resolve();
  private one<T>(run: () => Promise<T>): Promise<T> {
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }

  /** Opens a vault with a records key, refusing a key that is not its own. */
  static open(api: Api, recordsKey: Uint8Array, meta: VaultMeta, who: Who) {
    return new VaultSession(api, keysFrom(recordsKey, meta), who);
  }

  /** The records, opened, with what waited in the inbox added and what Money puts right on read done, saved when anything changed. */
  read(today: string): Promise<State> {
    return this.one(() => this.readNow(today));
  }
  private async readNow(today: string): Promise<State> {
    const served = await this.api.json<Served>("GET", "/api/vault");
    if (!served.meta) throw new ApiError(409, "These records are not locked yet");
    const opened = openRows(served.rows, served.version, this.keys);
    this.cache = opened.cache;
    this.state = opened.state;
    let s = structuredClone(opened.state);
    const done: string[] = [];
    if (served.inbox) {
      const { inbox } = await this.api.json<{ inbox: Inbox[] }>("GET", "/api/vault/inbox");
      for (const m of inbox) {
        s = await this.applyOne(s, m).catch(() => s);
        done.push(m.id);
      }
    }
    const lapsed = this.who.access === "lapsed";
    const steps = tidy(s, { lapsed });
    s = (await this.withRates(s, today)) ?? s;
    if (!lapsed) s = foldedWise(s, today) ?? s;
    const changed = steps.length || done.length || JSON.stringify(s) !== JSON.stringify(opened.state);
    let saved = opened.state;
    if (changed && !lapsed)
      try {
        saved = await this.writeNow(s, opened.state.version, false);
      } catch (e) {
        // Changed on another device meanwhile: show what was read; the next read puts it right.
        if (!(e instanceof ApiError) || e.status !== 409) throw e;
        return opened.state;
      }
    if (done.length) await this.api.json("POST", "/api/vault/inbox/done", { ids: done });
    void this.seal().catch(() => undefined);
    return lapsed ? s : saved;
  }

  /** Saves the records: codes for new ones, then only the rows that changed, with the version check. */
  write(next: State, expected: number): Promise<State> {
    return this.one(() => this.writeNow(next, expected));
  }
  private async writeNow(next: State, expected: number, seal = true): Promise<State> {
    const s = validateState(structuredClone(next));
    if (this.state) await this.withCodes(s, this.state);
    const changes = vaultChanges(s, this.keys, this.cache);
    if (!changes.put.length && !changes.del.length && this.state && expected === this.state.version) return this.state;
    const { version } = await this.api.json<{ version: number }>("PUT", "/api/vault", { put: changes.put, del: changes.del, expectedVersion: expected });
    this.cache = changes.cache;
    this.state = { ...s, version };
    if (seal) void this.seal().catch(() => undefined);
    return this.state;
  }

  /** One message from the inbox: an assistant's send, a receipt it found, or an edit to a shared list. */
  private async applyOne(s: State, m: Inbox): Promise<State> {
    if (m.kind === "feed") {
      const sent = openSealedJson<{ op: string; input: unknown; feed: { id?: string; name: string }; file?: { id: string; type: string; key: string } }>(this.keys, m.body, "inbox");
      const feed = { id: sent.feed.id ?? "receipt", name: sent.feed.name };
      if (sent.op === "add") return (await addFromFeed(s, sent.input, feed)).state;
      if (sent.op === "edit") return editFromFeed(s, sent.input, { id: feed.id, name: feed.name }).state;
      if (sent.op === "delete") return deleteFromFeed(s, sent.input, { id: feed.id, name: feed.name }).state;
      if (sent.op === "receipt") {
        const input = sent.input as { code: string; items?: Parameters<typeof attachReceipt>[4] };
        const done = attachReceipt(s, input.code, feed.name, sent.file ? { id: sent.file.id, type: sent.file.type } : undefined, input.items);
        if ("error" in done) {
          if (sent.file) await this.api.bytes("DELETE", `/api/vault/files/${sent.file.id}`).catch(() => undefined);
          return s;
        }
        if (sent.file) done.tx.raw = { ...(done.tx.raw ?? {}), receiptKey: sent.file.key };
        return done.state;
      }
      return s;
    }
    if (m.kind === "share-edit") {
      // Only from a person this list is shared with to edit, as the registry still says.
      const { shares } = await this.api.json<{ shares: { list: string; person: string; role: string }[] }>("GET", "/api/shares");
      if (!shares.some((g) => g.list === m.meta.list && g.person === m.meta.person && g.role === "edit")) return s;
      const sent = openSealedJson<{ list: string; transactions: unknown }>(this.keys, m.body, "share-edit");
      if (sent.list !== m.meta.list) return s;
      return applySharedEdit(s, m.meta.list, sent.transactions);
    }
    return s;
  }

  /** The reference rates the records lack: only currency codes and a first day go to the server. */
  private async withRates(s: State, today: string) {
    const currencies = rateCurrencies(s);
    if (!currencies.length) return null;
    const from = ratesFrom(s, today);
    try {
      const { series } = await this.api.json<{ series: Record<string, Record<string, number>> }>("GET", `/api/rates?currencies=${currencies.join(",")}&from=${from}&today=${today}`);
      return mergeRates(s, series, from, today);
    } catch {
      return null;
    }
  }

  /** Codes for records new since the last read, claimed against a hash of each id, never the id. */
  private async withCodes(s: State, previous: State) {
    if (!this.who.code) return;
    const needed = carryCodes(s, previous);
    if (!needed.length) return;
    const refs = new Map(needed.map((n) => [this.codeRef(n.id), n]));
    const { codes } = await this.api.json<{ codes: { kind: CodedKind; id: string; code: string }[] }>("POST", "/api/vault/codes", {
      needed: [...refs].map(([ref, n]) => ({ kind: n.kind, id: ref })),
    });
    applyCodes(
      s,
      codes.flatMap((c) => (refs.has(c.id) ? [{ ...refs.get(c.id)!, code: c.code }] : [])),
    );
  }
  /** What the registry knows a record by: its id hashed with this person's key. */
  codeRef = (id: string) => rowKey(this.keys, "code", id);
  /** The record a registry's ref names, among these records. */
  recordOf(ref: string) {
    const s = this.state;
    if (!s) return null;
    for (const r of [...s.accounts, ...s.views, ...s.transactions, ...s.plans, ...s.invoices, ...s.goals]) if (this.codeRef(r.id) === ref) return r.id;
    return null;
  }

  // Files: each locked with a key of its own, kept on the transaction that shows it.

  /** A kept receipt, opened: its key is on the payment that shows it. */
  async receipt(id: string): Promise<{ type: string; bytes: Uint8Array } | null> {
    const t = this.state?.transactions.find((x) => x.raw?.receipt === id);
    const key = t?.raw?.receiptKey;
    if (!t || !key) return null;
    const locked = await this.api.bytes("GET", `/api/vault/files/${id}`);
    return { type: t.raw?.receiptType || "application/octet-stream", bytes: unlock(unb64(key), locked, `file/${id}`) };
  }
  /** A receipt of a list shared with this person, opened with the key its owner sealed in the copy. */
  async sharedReceipt(list: string, id: string): Promise<{ type: string; bytes: Uint8Array } | null> {
    const copy = this.copies.find((c) => c.list === list);
    const key = copy?.files[id];
    if (!key) return null;
    const t = copy.slice?.transactions.find((x) => (x as { raw?: Record<string, string> }).raw?.receipt === id);
    const locked = await this.api.bytes("GET", `/api/shared/${encodeURIComponent(list)}/file/${id}`);
    return { type: (t as { raw?: Record<string, string> } | undefined)?.raw?.receiptType || copy.home.transactions.find((x) => x.raw?.receipt === `${list}/${id}`)?.raw?.receiptType || "application/octet-stream", bytes: unlock(unb64(key), locked, `file/${id}`) };
  }
  /** Locks a file with a new key and keeps it; answers its id and key, for the payment that will show it. */
  async keepFile(bytes: Uint8Array, id: string = crypto.randomUUID()) {
    const key = newFileKey();
    await this.api.bytes("PUT", `/api/vault/files/${id}`, lock(key, bytes, `file/${id}`), { "Content-Type": "application/octet-stream" });
    return { id, key: b64(key) };
  }

  /** Applies a change to the records as they are when its turn comes, and saves it. */
  private change(apply: (s: State) => State | Promise<State>) {
    return this.one(async () => {
      const s = this.state!;
      return this.writeNow(await apply(structuredClone(s)), s.version);
    });
  }

  /**
   * The drop zone: the file is read by the pass-through reader, which keeps nothing; what it found is
   * added here as a feed adds it, and a photo or a PDF that something came of is kept locked. The
   * reading, the slow part, waits for nothing; only the save takes its turn.
   */
  async addFile(bytes: Uint8Array, type: string, name: string, today: string) {
    const context = { today, accounts: this.state!.accounts.map((a) => ({ name: a.name, currency: a.currency, kind: a.kind })) };
    const read = await this.api.send<{ found: FeedTransaction[]; skipped: FeedResult["skipped"]; unreadable: string }>("/api/ai/read", bytes, {
      "Content-Type": type,
      "X-File-Name": encodeURIComponent(name),
      "X-Read-Context": toB64Url(JSON.stringify(context)),
    });
    const result: FeedResult = { added: [], skipped: [...read.skipped] };
    if (!read.found.length) return { ...result, unreadable: read.skipped.length ? "" : read.unreadable || "No transactions found" };
    const fileId = keepable(type) && bytes.length <= keptFile ? crypto.randomUUID() : undefined;
    const kept = fileId ? await this.keepFile(bytes, fileId) : undefined;
    await this.change(async (s) => {
      let next = s;
      for (let i = 0; i < read.found.length; i += FEED_BATCH) {
        const part = await addFromFeed(next, { transactions: read.found.slice(i, i + FEED_BATCH) }, { id: "inbox", name: "Drop zone", ...(fileId ? { receipt: fileId, receiptType: type } : {}) });
        next = part.state;
        result.added.push(...part.result.added);
        result.skipped.push(...part.result.skipped);
      }
      if (!kept) return next;
      return { ...next, transactions: next.transactions.map((t) => (t.raw?.receipt === fileId ? { ...t, raw: { ...t.raw, receiptKey: kept.key } } : t)) };
    });
    // Nothing new came of it: the file is not kept either.
    if (fileId && !result.added.length) await this.api.bytes("DELETE", `/api/vault/files/${fileId}`).catch(() => undefined);
    return { ...result, unreadable: "" };
  }

  // Behind the scenes, as the Worker did: each batch passes through Claude and is answered, nothing kept.

  async fileUnfiled() {
    const { rows, categories, waiting } = filingRows(this.state!);
    if (!rows.length || !categories.length) return { filed: 0, left: waiting };
    const { filed } = await this.api.json<{ filed: { id: string; category: string }[] }>("POST", "/api/ai/file", { rows, categories });
    const updates = keptFiling(rows, categories, filed);
    if (updates.length) await this.change((s) => applyFiling(s, updates));
    return { filed: updates.length, left: Math.max(0, waiting - updates.length) };
  }
  async scanBusiness() {
    const { rows, examples, waiting } = scanRows(this.state!);
    if (!rows.length) return { caught: 0, left: waiting };
    const { payments } = await this.api.json<{ payments: { id: string; likely: boolean; reason: string }[] }>("POST", "/api/ai/scan", { rows, examples });
    const updates = keptScan(rows, payments);
    await this.change((s) => applyScan(s, updates));
    return { caught: updates.filter((u) => u.likely).length, left: Math.max(0, waiting - rows.length) };
  }
  async readItems(max = 4) {
    const waiting = unreadReceipts(this.state!);
    const updates: { id: string; items?: Item[] }[] = [];
    let failed = 0;
    for (const t of waiting.slice(0, max)) {
      const file = await this.receipt(t.raw!.receipt).catch(() => null);
      if (!file) {
        updates.push({ id: t.id });
        continue;
      }
      try {
        const { lines } = await this.api.send<{ lines: Parameters<typeof itemsForPayment>[1] }>("/api/ai/lines", file.bytes, {
          "Content-Type": file.type,
          "X-Read-Context": toB64Url(JSON.stringify({ description: t.description, amount: money(t.amount, t.currency), date: t.date })),
        });
        updates.push({ id: t.id, items: itemsForPayment(t, (lines ?? []).map((i) => ({ ...i, name: i.name || "Item", quantity: (i.quantity ?? 0) > 0 ? i.quantity : 1 }))) });
      } catch {
        failed++;
      }
    }
    if (updates.length) await this.change((s) => applyItems(s, updates));
    return { read: updates.length, failed, left: Math.max(0, waiting.length - updates.length) };
  }
  decide(ids: string[], business: boolean) {
    return this.change((s) => decideBusiness(s, ids, business));
  }

  // Sharing with keys.

  /**
   * Seals each list this person shares for each person it is shared with, to that person's public
   * key, with the keys of the receipts it shows; a person without a key yet is skipped until they
   * lock their own records. A list unchanged since its last seal is not sealed again.
   */
  async seal() {
    const s = this.state;
    if (!s || !this.who.code) return 0;
    const { shares } = await this.api.json<{ shares: { list: string; person: string; role: string }[] }>("GET", "/api/shares");
    const people = [...new Set(shares.map((g) => g.person).filter((p) => !p.startsWith("mail:")))];
    if (!people.length) return 0;
    const { keys } = await this.api.json<{ keys: Record<string, string> }>("POST", "/api/vault/people", { people });
    const copies: { list: string; person: string; sealed: string }[] = [];
    for (const g of shares) {
      const key = keys[g.person];
      if (!key) continue;
      const slice = sharedSlice(s, g.list);
      if (!slice) continue;
      const home = sharedHome(s, [g.list], this.who.code);
      const accountIds = new Set(slice.accounts.map((a) => a.id));
      const files = Object.fromEntries(
        s.transactions.filter((t) => accountIds.has(t.accountId) && t.raw?.receipt && t.raw.receiptKey).map((t) => [t.raw!.receipt, t.raw!.receiptKey]),
      );
      const copy: ShareCopy = { list: g.list, owner: this.who.code, name: slice.name, version: s.version, home, slice, files };
      const plain = JSON.stringify(copy);
      const at = `${g.list}/${g.person}/${key}`;
      if (this.sealedAt.get(at) === plain) continue;
      copies.push({ list: g.list, person: g.person, sealed: sealJson(unb64(key), copy, "share") });
      this.sealedAt.set(at, plain);
    }
    for (let i = 0; i < copies.length; i += 20) await this.api.json("PUT", "/api/shares/copies", { copies: copies.slice(i, i + 20) });
    return copies.length;
  }

  /** What is shared with this person: the plain projections of owners not yet locked, and the copies locked owners sealed to them. */
  async shared(): Promise<SharedHome> {
    let result = emptyShared();
    try {
      result = await this.api.json<SharedHome>("GET", "/api/shared/state");
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 404) throw e;
    }
    const { copies } = await this.api.json<{ copies: { list: string; owner: string; role: string; sealed: string }[] }>("GET", "/api/shared/sealed");
    this.copies = [];
    for (const c of copies) {
      try {
        const copy = openSealedJson<ShareCopy>(this.keys, c.sealed, "share");
        if (copy.list !== c.list || copy.owner !== c.owner) continue;
        this.copies.push({ ...copy, role: c.role });
      } catch {
        // A copy sealed to an older key of this person's is left until its owner seals it again.
      }
    }
    // One projection per owner, even when several overlapping lists were shared.
    const seen = new Set([...result.accounts, ...result.snapshots, ...result.transactions, ...result.plans, ...result.rates].map((x) => x.id));
    for (const c of this.copies)
      for (const key of ["accounts", "snapshots", "transactions", "plans", "rates"] as const)
        for (const x of c.home[key] as { id: string }[])
          if (!seen.has(x.id)) {
            seen.add(x.id);
            (result[key] as { id: string }[]).push(x);
          }
    result.categories = [...new Set([...result.categories, ...this.copies.flatMap((c) => c.home.categories)])];
    return result;
  }
  /** An edit to a list shared with this person, sealed to its owner; their device applies it. */
  async sharedEdit(list: string, transactions: unknown) {
    const copy = this.copies.find((c) => c.list === list);
    if (!copy) throw new ApiError(404, "Not shared with you");
    if (copy.role !== "edit") throw new ApiError(403, "You can view this list, not change it");
    const { keys } = await this.api.json<{ keys: Record<string, string> }>("POST", "/api/vault/people", { people: [copy.owner] });
    if (!keys[copy.owner]) throw new ApiError(409, "Its owner's key is not known");
    await this.api.json("POST", `/api/shared/${encodeURIComponent(list)}/edit`, { sealed: sealJson(unb64(keys[copy.owner]), { list, transactions }, "share-edit") });
  }
}

/**
 * Locks plain records for the first time: every receipt locked with its own key, every row with the
 * records key, then swapped for the plain records in one step on the server. `plainReceipt` reads a
 * kept receipt while the records are still plain.
 */
export async function lockFirst(api: Api, recordsKey: Uint8Array, meta: VaultMeta, plain: State, plainReceipt: (id: string) => Promise<Uint8Array | null>) {
  const keys = keysFrom(recordsKey, meta);
  const s = structuredClone(plain);
  const session = new VaultSession(api, keys, { owner: false, code: null, access: "paid" });
  const files = new Map<string, string>();
  for (const t of s.transactions) {
    const id = t.raw?.receipt;
    if (!id || !/^[0-9a-f-]{36}$/.test(id)) continue;
    if (!files.has(id)) {
      const bytes = await plainReceipt(id);
      if (!bytes) continue;
      files.set(id, (await session.keepFile(bytes, id)).key);
    }
    t.raw = { ...t.raw!, receiptKey: files.get(id)! };
  }
  const { put } = lockAll(validateState(s), keys);
  return api.json<{ version: number }>("POST", "/api/vault/adopt", { meta, rows: put, expectedVersion: plain.version });
}
