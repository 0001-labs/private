import { z } from "zod";
import { headers } from "./auth";
import type { CodedKind } from "../shared/codes";
import { PAID_SECTIONS, type VaultRow } from "../shared/vault-records";
import { claudeColumns, type ColumnReader } from "./csv";
import { claudeLines, claudeReader, images, INBOX_MAX, readFound, texts, type LineReader, type ReadContext, type Reader } from "./inbox";
import { claudeFiler, type Filer } from "./categorize";
import { claudeBusinessScanner, type BusinessScanner } from "./business";
import { rateSeries, type RateStore } from "./rates";
import { isListCode } from "../shared/idv1";
import type { Sealed } from "../shared/private/store.ts";

// The routes a device with locked records uses. The store keeps rows,
// files and an inbox it cannot read; the readers under /api/ai pass a file or a batch through to
// Claude and answer, keeping nothing and logging nothing. Every route sits behind the person's own
// sign-in, as the records always have.

export interface VaultStore {
  vaulted(): Promise<boolean>;
  versionRead(): Promise<number>;
  vaultRead(): Promise<{ meta: unknown; version: number; rows: VaultRow[]; inbox: number }>;
  vaultAdopt(meta: unknown, rows: VaultRow[], expected: number): Promise<{ version: number }>;
  vaultWrite(put: VaultRow[], del: string[], expected: number, refuse?: readonly string[]): Promise<{ version: number }>;
  vaultWraps(meta: unknown): Promise<void>;
  vaultPublicKey(): Promise<string | null>;
  vaultFilePut(id: string, body: Uint8Array): Promise<void>;
  vaultFileGet(id: string): Promise<ArrayBuffer | null>;
  vaultFileDelete(id: string): Promise<void>;
  sealedPut(s: Omit<Sealed, "created">): Promise<void>;
  sealedList(): Promise<Sealed[]>;
  sealedDone(ids: string[]): Promise<void>;
}
export interface VaultRegistry {
  codeClaim(store: string, needed: { kind: CodedKind; id: string }[]): Promise<{ kind: CodedKind; id: string; code: string }[]>;
  personKeySet(person: string, store: string, key: string): Promise<void>;
  personKeys(people: string[]): Promise<Record<string, string>>;
  grantsOf(store: string): Promise<{ list: string; person: string; role: string }[]>;
  grantsFor(person: string): Promise<{ list: string; person: string; store: string; owner: string; role: string }[]>;
  shareCopySet(store: string, list: string, person: string, sealed: string): Promise<boolean>;
  shareCopiesFor(person: string): Promise<{ list: string; owner: string; role: string; store: string; sealed: string; updated: number }[]>;
}
export type VaultEnv = { ANTHROPIC_API_KEY?: string };

/** Who asks, as the Worker knows them. */
export type VaultPerson = {
  store: string;
  /** Their person code, null until an account has one. */
  code: string | null;
  access: "owner" | "paid" | "free" | "lapsed" | "closed";
  /** The `money.privacy` flag for this person. A store already locked works whatever it says. */
  privacy: boolean;
  /** The iPhone app's bearer token: no page origin to check. */
  bearer: boolean;
};

const json = (body: unknown, status = 200) => Response.json(body, { status, headers });
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const day = /^\d{4}-\d{2}-\d{2}$/;
/** The most rows one save sends: a whole vault's first lock. */
const BODY_MAX = 40_000_000;

async function bodyJson(request: Request, max = BODY_MAX) {
  if (Number(request.headers.get("content-length")) > max) throw new VaultError(413, "Too large");
  const text = await request.text();
  if (text.length > max) throw new VaultError(413, "Too large");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new VaultError(400, "Send JSON");
  }
}
class VaultError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** A device's write from a page needs the page's own origin and JSON; the app's bearer token is never sent by a browser on its own. */
function writable(request: Request, url: URL, who: VaultPerson, type = "application/json") {
  if (!who.bearer && request.headers.get("origin") !== url.origin) throw new VaultError(403, "Invalid origin");
  if (!request.headers.get("content-type")?.startsWith(type)) throw new VaultError(415, `Send ${type}`);
}

const rowsSchema = z.array(z.object({ section: z.string(), key: z.string(), value: z.string() }).strict());

/**
 * /api/vault…, /api/ai/…, /api/rates and the locked side of sharing. Null for any other path.
 * `store` is the person's own; `storeOf` opens another's only to keep what a grant lets this
 * person send them (a shared list's edit) or read (a shared receipt's locked file).
 */
export async function vaultRoutes(
  request: Request,
  who: VaultPerson,
  store: VaultStore,
  registry: VaultRegistry,
  storeOf: (name: string) => VaultStore,
  env: VaultEnv,
  rates: RateStore,
  readers: { reader?: Reader | null; columns?: ColumnReader | null; lines?: LineReader | null; filer?: Filer | null; scanner?: BusinessScanner | null } = {},
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;
  const ours =
    path === "/api/vault" ||
    path.startsWith("/api/vault/") ||
    path.startsWith("/api/ai/") ||
    path === "/api/rates" ||
    path === "/api/shares/copies" ||
    path === "/api/shared/sealed" ||
    /^\/api\/shared\/[^/]+\/(edit|file\/[0-9a-f-]{36})$/.test(path);
  if (!ours) return null;
  try {
    const locked = await store.vaulted();
    // Off for this person and nothing locked yet: the vault is not here.
    if (!who.privacy && !locked) return json({ error: "Not found" }, 404);
    const paid = who.access === "owner" || who.access === "paid";

    if (path === "/api/vault") {
      if (request.method === "GET") {
        if (!locked) return json({ meta: null, version: await store.versionRead(), rows: [], inbox: 0 });
        return json(await store.vaultRead());
      }
      if (request.method !== "PUT") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      if (who.access === "lapsed") return json({ error: "Your subscription has ended. Your records are kept; start Money again to change them." }, 402);
      const body = z.object({ put: rowsSchema.max(5000), del: z.array(z.string()).max(5000), expectedVersion: z.number().int().min(0) }).strict().parse(await bodyJson(request));
      const refuse = who.access === "free" ? PAID_SECTIONS : [];
      if (refuse.length && body.put.some((r) => refuse.includes(r.section as never)))
        return json({ error: "Transactions come with the Money plan", access: "free" }, 402);
      return json(await store.vaultWrite(body.put, body.del, body.expectedVersion, refuse));
    }
    if (path === "/api/vault/adopt") {
      // The first lock: a new account's empty records, or plain records moved over by the person's device.
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      if (!who.privacy) return json({ error: "Not found" }, 404);
      const body = z.object({ meta: z.unknown(), rows: rowsSchema.max(20000), expectedVersion: z.number().int().min(0) }).strict().parse(await bodyJson(request));
      if (who.access === "free" && body.rows.some((r) => (PAID_SECTIONS as string[]).includes(r.section)))
        return json({ error: "Transactions come with the Money plan", access: "free" }, 402);
      const done = await store.vaultAdopt(body.meta, body.rows, body.expectedVersion);
      const key = await store.vaultPublicKey();
      if (who.code && key) await registry.personKeySet(who.code, who.store, key);
      return json(done);
    }
    // Before the first lock only the readers, the rates and the files being moved over are open.
    const staging = /^\/api\/vault\/files\/[0-9a-f-]{36}$/.test(path) && request.method === "PUT";
    if (!locked && path !== "/api/rates" && !path.startsWith("/api/ai/") && !staging) return json({ error: "Lock your records first", vault: false }, 409);

    if (path === "/api/vault/meta") {
      // A way back in added or replaced (a passkey, a new recovery key); the vault keeps its key.
      if (request.method !== "PUT") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      await store.vaultWraps(await bodyJson(request, 50_000));
      const key = await store.vaultPublicKey();
      if (who.code && key) await registry.personKeySet(who.code, who.store, key);
      return json({ ok: true });
    }
    const file = /^\/api\/vault\/files\/([0-9a-f-]{36})$/.exec(path);
    if (file) {
      if (!uuid.test(file[1])) return json({ error: "Not found" }, 404);
      if (request.method === "GET") {
        const body = await store.vaultFileGet(file[1]);
        return body ? new Response(body, { headers: { ...headers, "Content-Type": "application/octet-stream", "Cache-Control": "private, max-age=86400" } }) : json({ error: "Not found" }, 404);
      }
      writable(request, url, who, request.method === "DELETE" ? "" : "application/octet-stream");
      if (request.method === "DELETE") {
        await store.vaultFileDelete(file[1]);
        return json({ deleted: true });
      }
      if (request.method !== "PUT") return json({ error: "Method not allowed" }, 405);
      if (!paid) return json({ error: "Receipts come with the Money plan", access: who.access }, 402);
      const bytes = new Uint8Array(await request.arrayBuffer());
      await store.vaultFilePut(file[1], bytes);
      return json({ kept: true }, 201);
    }
    if (path === "/api/vault/inbox") {
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      return json({ inbox: await store.sealedList() });
    }
    if (path === "/api/vault/inbox/done") {
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      const body = z.object({ ids: z.array(z.string().max(80)).max(500) }).strict().parse(await bodyJson(request, 100_000));
      await store.sealedDone(body.ids);
      return json({ done: body.ids.length });
    }
    if (path === "/api/vault/codes") {
      // Codes for new records, kept against a hash of the record's id, never the id.
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      const kinds = ["account", "view", "transaction", "plan", "invoice", "goal"] as const;
      const body = z.object({ needed: z.array(z.object({ kind: z.enum(kinds), id: z.string().regex(/^[A-Za-z0-9_-]{32}$/) })).max(2000) }).strict().parse(await bodyJson(request, 400_000));
      return json({ codes: body.needed.length ? await registry.codeClaim(who.store, body.needed) : [] });
    }
    if (path === "/api/vault/people") {
      // The public keys of the people this person shares with, to seal their copies to.
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      const body = z.object({ people: z.array(z.string().max(12)).max(200) }).strict().parse(await bodyJson(request, 20_000));
      const mine = new Set((await registry.grantsOf(who.store)).map((g) => g.person));
      const owners = new Set(who.code ? (await registry.grantsFor(who.code)).map((g) => g.owner) : []);
      return json({ keys: await registry.personKeys(body.people.filter((p) => mine.has(p) || owners.has(p))) });
    }
    if (path === "/api/shares/copies") {
      if (request.method !== "PUT") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      const body = z.object({ copies: z.array(z.object({ list: z.string(), person: z.string().max(12), sealed: z.string().max(8_000_000) }).strict()).max(100) }).strict().parse(await bodyJson(request));
      let kept = 0;
      for (const c of body.copies) if (isListCode(c.list) && c.sealed.startsWith("s1.") && (await registry.shareCopySet(who.store, c.list, c.person, c.sealed))) kept++;
      return json({ kept });
    }
    if (path === "/api/shared/sealed") {
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      const copies = who.code ? await registry.shareCopiesFor(who.code) : [];
      return json({ copies: copies.map(({ store: _store, ...c }) => c) });
    }
    const sharedEdit = /^\/api\/shared\/([^/]+)\/edit$/.exec(path);
    if (sharedEdit) {
      // An edit to a list shared with this person, sealed to its owner: their device applies it.
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      writable(request, url, who);
      const grant = who.code ? (await registry.grantsFor(who.code)).find((g) => g.list === sharedEdit[1]) : undefined;
      if (!grant) return json({ error: "Not shared with you" }, 404);
      if (grant.role !== "edit") return json({ error: "You can view this list, not change it" }, 403);
      const body = z.object({ sealed: z.string().startsWith("s1.").max(8_000_000) }).strict().parse(await bodyJson(request));
      const owner = storeOf(grant.store);
      if (!(await owner.vaulted())) return json({ error: "Its owner's records are not locked" }, 409);
      await owner.sealedPut({ id: crypto.randomUUID(), kind: "share-edit", body: body.sealed, meta: { list: grant.list, person: who.code! } });
      return json({ received: true }, 202);
    }
    const sharedFile = /^\/api\/shared\/([^/]+)\/file\/([0-9a-f-]{36})$/.exec(path);
    if (sharedFile) {
      // A shared payment's receipt, still locked: its key travels only in the sealed copy.
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      const grant = who.code ? (await registry.grantsFor(who.code)).find((g) => g.list === sharedFile[1]) : undefined;
      if (!grant || !uuid.test(sharedFile[2])) return json({ error: "Not shared with you" }, 404);
      const body = await storeOf(grant.store).vaultFileGet(sharedFile[2]);
      return body ? new Response(body, { headers: { ...headers, "Content-Type": "application/octet-stream", "Cache-Control": "private, max-age=86400" } }) : json({ error: "Not found" }, 404);
    }

    if (path === "/api/rates") {
      // Reference rates for the currencies a device names, from a first day: codes and dates only.
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      const currencies = (url.searchParams.get("currencies") || "").split(",").filter((c) => /^[A-Z]{3}$/.test(c)).slice(0, 20);
      const from = url.searchParams.get("from") || "";
      const today = url.searchParams.get("today") || "";
      if (!day.test(from) || !day.test(today) || from > today) return json({ error: "Name the days" }, 400);
      return json({ series: await rateSeries(currencies, from, today, rates) });
    }

    // The pass-through readers: what a device sends is read by Claude and answered; nothing is kept or logged.
    if (path.startsWith("/api/ai/")) {
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      if (!who.bearer && request.headers.get("origin") !== url.origin) return json({ error: "Invalid origin" }, 403);
      if (who.access === "lapsed") return json({ error: "Your subscription has ended." }, 402);
      if (!paid) return json({ error: "Reading comes with the Money plan", access: "free" }, 402);
      if (!env.ANTHROPIC_API_KEY) return json({ error: "Reading files is not set up yet" }, 503);
      const key = env.ANTHROPIC_API_KEY;
      if (path === "/api/ai/read") {
        const type = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
        if (type !== "application/pdf" && !(images as readonly string[]).includes(type) && !texts.includes(type)) return json({ error: "Drop a photo, a PDF or a CSV" }, 415);
        const bytes = new Uint8Array(await request.arrayBuffer());
        if (!bytes.length) return json({ error: "The file is empty" }, 400);
        if (bytes.length > INBOX_MAX) return json({ error: "Files up to 10 MB" }, 413);
        const name = decodeURIComponent(request.headers.get("x-file-name") || "file").slice(0, 120);
        const context = contextOf(request.headers.get("x-read-context"));
        const read = await readFound(bytes, type, name, context, readers.reader ?? claudeReader(key), readers.columns ?? claudeColumns(key));
        if ("error" in read) return json({ error: read.error }, read.status);
        return json({ found: read.found, skipped: read.result.skipped, unreadable: read.unreadable });
      }
      if (path === "/api/ai/lines") {
        const type = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
        if (type !== "application/pdf" && !(images as readonly string[]).includes(type)) return json({ error: "Send a picture or a PDF" }, 415);
        const bytes = new Uint8Array(await request.arrayBuffer());
        if (!bytes.length || bytes.length > INBOX_MAX) return json({ error: "Send a receipt up to 10 MB" }, 413);
        const tx = paymentOf(request.headers.get("x-read-context"));
        try {
          return json({ lines: await (readers.lines ?? claudeLines(key))({ bytes, type }, tx) });
        } catch {
          return json({ error: "Could not read the receipt. Try again in a moment." }, 502);
        }
      }
      if (path === "/api/ai/file") {
        const body = z.object({ rows: z.array(z.object({ id: z.string().max(250), text: z.string().max(2000) })).max(40), categories: z.array(z.string().min(1).max(1000)).min(1).max(100) }).strict().parse(await bodyJson(request, 200_000));
        try {
          return json({ filed: await (readers.filer ?? claudeFiler(key))(body.rows, body.categories) });
        } catch {
          return json({ error: "Could not file them now" }, 502);
        }
      }
      if (path === "/api/ai/scan") {
        const body = z
          .object({ rows: z.array(z.object({ id: z.string().max(250), text: z.string().max(2000) })).max(40), examples: z.object({ business: z.array(z.string().max(500)).max(40), personal: z.array(z.string().max(500)).max(40) }) })
          .strict()
          .parse(await bodyJson(request, 200_000));
        try {
          return json({ payments: await (readers.scanner ?? claudeBusinessScanner(key))(body.rows, body.examples) });
        } catch {
          return json({ error: "Could not look now" }, 502);
        }
      }
      return json({ error: "Not found" }, 404);
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    if (e instanceof VaultError) return json({ error: e.message }, e.status);
    if (e instanceof z.ZodError) return json({ error: "Check what was sent" }, 400);
    const message = e instanceof Error ? e.message : "";
    // The store's own refusals say what they refused, never what was sent.
    if (message.startsWith("Conflict:")) return json({ error: "Another device changed these records. Reload before saving." }, 409);
    if (message.startsWith("Refused:")) return json({ error: message.slice(9) }, 400);
    return json({ error: "Could not do that. Try again." }, 400);
  }
}

/** The read context a device sends beside a file, base64url JSON in a header: today and its accounts' names and currencies. */
function contextOf(header: string | null): ReadContext {
  try {
    const value = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob((header || "").replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
    return z.object({ today: z.string().regex(day), accounts: z.array(z.object({ name: z.string().max(120), currency: z.string().max(3), kind: z.string().max(20).optional() })).max(60) }).parse(value);
  } catch {
    return { today: new Date().toISOString().slice(0, 10), accounts: [] };
  }
}
function paymentOf(header: string | null) {
  try {
    const value = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob((header || "").replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
    return z.object({ description: z.string().max(300), amount: z.string().max(60), date: z.string().max(10) }).parse(value);
  } catch {
    return { description: "", amount: "", date: "" };
  }
}

