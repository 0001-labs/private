import { expect, it } from "vite-plus/test";
import { sampleState } from "../ios/core/sample";
import { validateState, type State } from "../shared/model";
import { candidateFor, type CodedKind } from "../shared/codes";
import { ApiError, lockFirst, VaultSession, type Api } from "../shared/vault-session";
import type { VaultRow } from "../shared/vault-records";
import { keysFrom, newRecordsKey, newRecoverySecret, newVault, sealJson, unb64, wrapKey, type VaultMeta } from "../shared/private/private.ts";

// The server as a device meets it, kept in memory: what it holds is what the operator could read.
// Every test ends by looking through all of it for the records' words.

type Store = { meta: VaultMeta | null; version: number; rows: Map<string, VaultRow>; files: Map<string, Uint8Array>; inbox: { id: string; kind: string; body: string; meta: Record<string, string> }[] };
function server() {
  const stores = new Map<string, Store>();
  const keys = new Map<string, string>();
  const grants: { store: string; owner: string; list: string; person: string; role: string }[] = [];
  const copies = new Map<string, { list: string; person: string; owner: string; role: string; sealed: string }>();
  const plain = new Map<string, Uint8Array>();
  const storeOf = (name: string) => {
    if (!stores.has(name)) stores.set(name, { meta: null, version: 3, rows: new Map(), files: new Map(), inbox: [] });
    return stores.get(name)!;
  };
  const api = (name: string, code: string): Api => ({
    async json<T>(method: string, path: string, body?: unknown) {
      const s = storeOf(name);
      const b = body as Record<string, never>;
      if (path === "/api/vault" && method === "GET") return { meta: s.meta, version: s.version, rows: [...s.rows.values()], inbox: s.inbox.length } as T;
      if (path === "/api/vault" && method === "PUT") {
        if (b.expectedVersion !== s.version) throw new ApiError(409, "Conflict");
        for (const k of b.del as string[]) s.rows.delete(k);
        for (const r of b.put as VaultRow[]) s.rows.set(r.key, r);
        return { version: ++s.version } as T;
      }
      if (path === "/api/vault/adopt") {
        if (b.expectedVersion !== s.version) throw new ApiError(409, "Conflict");
        s.meta = b.meta;
        for (const r of b.rows as VaultRow[]) s.rows.set(r.key, r);
        keys.set(code, (b.meta as VaultMeta).publicKey);
        return { version: ++s.version } as T;
      }
      if (path === "/api/vault/inbox") return { inbox: s.inbox } as T;
      if (path === "/api/vault/inbox/done") {
        s.inbox = s.inbox.filter((m) => !(b.ids as string[]).includes(m.id));
        return {} as T;
      }
      if (path.startsWith("/api/rates")) return { series: {} } as T;
      if (path === "/api/vault/codes") return { codes: (b.needed as { kind: CodedKind; id: string }[]).map((n) => ({ ...n, code: candidateFor(n.kind) })) } as T;
      if (path === "/api/shares") return { shares: grants.filter((g) => g.store === name) } as T;
      if (path === "/api/vault/people") return { keys: Object.fromEntries((b.people as string[]).filter((p) => keys.has(p)).map((p) => [p, keys.get(p)!])) } as T;
      if (path === "/api/shares/copies") {
        for (const c of b.copies as { list: string; person: string; sealed: string }[]) {
          const g = grants.find((x) => x.store === name && x.list === c.list && x.person === c.person);
          if (g) copies.set(`${c.list}/${c.person}`, { ...c, owner: g.owner, role: g.role });
        }
        return {} as T;
      }
      if (path === "/api/shared/state") throw new ApiError(404, "None");
      if (path === "/api/shared/sealed") return { copies: [...copies.values()].filter((c) => c.person === code) } as T;
      const edit = /^\/api\/shared\/([^/]+)\/edit$/.exec(path);
      if (edit) {
        const g = grants.find((x) => x.list === edit[1] && x.person === code)!;
        storeOf(g.store).inbox.push({ id: crypto.randomUUID(), kind: "share-edit", body: b.sealed, meta: { list: g.list, person: code } });
        return {} as T;
      }
      throw new ApiError(404, `No ${method} ${path}`);
    },
    async bytes(method: string, path: string, body?: Uint8Array) {
      const s = storeOf(name);
      const id = path.split("/").pop()!;
      if (method === "PUT") s.files.set(id, body!);
      if (method === "DELETE") s.files.delete(id);
      if (path.startsWith("/api/shared/")) return storeOf(grants.find((g) => g.list === path.split("/")[3])!.store).files.get(id)!;
      return s.files.get(id) ?? new Uint8Array();
    },
    async send<T>(path: string) {
      if (path === "/api/ai/read") return { found: [{ date: "2026-10-19", amount: 777, currency: "JPY", description: "Secret Dropped Ramen" }], skipped: [], unreadable: "" } as T;
      throw new ApiError(404, path);
    },
  });
  /** Everything the server holds, as the operator would see it. */
  const everything = () => JSON.stringify({ stores: [...stores].map(([k, s]) => [k, s.meta, [...s.rows.values()], [...s.files.values()].map((f) => new TextDecoder().decode(f)), s.inbox]), copies: [...copies.values()] });
  return { api, storeOf, keys, grants, plain, everything };
}

const today = "2026-10-20";
const words = (s: State) => [...new Set([...s.accounts.map((a) => a.name), ...s.transactions.slice(0, 50).map((t) => t.description)])].filter((w) => w.length >= 6);
async function vault(api: Api, plain: State, receipts: Record<string, Uint8Array> = {}) {
  const recordsKey = newRecordsKey();
  const meta = { ...newVault(keysFrom(recordsKey)), wraps: [{ kind: "recovery" as const, wrapped: wrapKey(newRecoverySecret(), recordsKey, "recovery"), created: today }] };
  await lockFirst(api, recordsKey, meta, plain, async (id) => receipts[id] ?? null);
  return { recordsKey, meta };
}

it("moves plain records into the vault, receipts included, and the server keeps none of their words", async () => {
  const srv = server();
  const plain = validateState({ ...sampleState(today), version: 3 });
  const receiptId = "0f6c3d7e-2b1a-4c5d-9e8f-1a2b3c4d5e6f";
  plain.transactions[0] = { ...plain.transactions[0], raw: { receipt: receiptId, receiptType: "image/jpeg" } };
  const { recordsKey, meta } = await vault(srv.api("user:v", "Vv1007"), plain, { [receiptId]: new TextEncoder().encode("A receipt from Secret Picture Shop") });
  const session = VaultSession.open(srv.api("user:v", "Vv1007"), recordsKey, meta, { owner: false, code: "Vv1007", access: "paid" });
  const read = await session.read(today);
  expect(read.transactions.length).toBe(plain.transactions.length);
  const file = await session.receipt(receiptId);
  expect(new TextDecoder().decode(file!.bytes)).toBe("A receipt from Secret Picture Shop");
  const held = srv.everything();
  for (const w of [...words(plain), "Secret Picture Shop"]) expect(held).not.toContain(w);
});

it("adds what an assistant sealed and what the drop zone read, and saves them locked", async () => {
  const srv = server();
  const plain = validateState({ ...sampleState(today), version: 3 });
  const { recordsKey, meta } = await vault(srv.api("user:v", "Vv1007"), plain);
  const account = plain.accounts.find((a) => a.kind === "bank" && a.currency === "JPY")!;
  // What the Worker does with an assistant's send to a locked store (server/worker.ts sealFeed).
  srv.storeOf("user:v").inbox.push({
    id: "m1",
    kind: "feed",
    meta: { op: "add" },
    body: sealJson(unb64(meta.publicKey), { op: "add", input: { transactions: [{ date: "2026-10-20", amount: 640, currency: "JPY", description: "Secret Feed Bakery", account: account.name }] }, feed: { id: "f1", name: "Grok Bot" } }, "inbox"),
  });
  const session = VaultSession.open(srv.api("user:v", "Vv1007"), recordsKey, meta, { owner: false, code: "Vv1007", access: "paid" });
  const read = await session.read(today);
  expect(read.transactions.some((t) => t.description === "Secret Feed Bakery")).toBe(true);
  expect(srv.storeOf("user:v").inbox).toEqual([]);
  const dropped = await session.addFile(new TextEncoder().encode("%PDF Secret Dropped Ramen"), "application/pdf", "ramen.pdf", today);
  expect(dropped.added.length).toBe(1);
  const again = VaultSession.open(srv.api("user:v", "Vv1007"), recordsKey, meta, { owner: false, code: "Vv1007", access: "paid" });
  const reread = await again.read(today);
  const ramen = reread.transactions.find((t) => t.description === "Secret Dropped Ramen")!;
  expect(new TextDecoder().decode((await again.receipt(ramen.raw!.receipt))!.bytes)).toBe("%PDF Secret Dropped Ramen");
  const held = srv.everything();
  for (const w of ["Secret Feed Bakery", "Secret Dropped Ramen", ...words(plain)]) expect(held).not.toContain(w);
});

it("seals a shared list to the person it is shared with, who opens it, and their edit reaches the owner sealed", async () => {
  const srv = server();
  const plain = validateState({ ...sampleState(today), version: 3 });
  const owner = await vault(srv.api("user:v", "Vv1007"), plain);
  const friend = await vault(srv.api("user:w", "Ww1008"), validateState({ ...sampleState(today), accounts: [], snapshots: [], transactions: [], plans: [], goals: [], version: 3 }));
  const mine = VaultSession.open(srv.api("user:v", "Vv1007"), owner.recordsKey, owner.meta, { owner: false, code: "Vv1007", access: "paid" });
  let s = await mine.read(today);
  // A code for the account, as Plus gives it, then a grant to edit.
  const bank = s.accounts.find((a) => a.kind === "bank")!;
  s = await mine.write({ ...s, accounts: s.accounts.map((a) => (a.id === bank.id ? { ...a, code: undefined } : a)) }, s.version);
  const list = s.accounts.find((a) => a.id === bank.id)!.code!;
  expect(list).toMatch(/^\d{2}[A-Za-z]{4}$/);
  srv.grants.push({ store: "user:v", owner: "Vv1007", list, person: "Ww1008", role: "edit" });
  expect(await mine.seal()).toBe(1);
  expect(await mine.seal()).toBe(0);
  const theirs = VaultSession.open(srv.api("user:w", "Ww1008"), friend.recordsKey, friend.meta, { owner: false, code: "Ww1008", access: "paid" });
  await theirs.read(today);
  const home = await theirs.shared();
  expect(home.accounts.map((a) => a.name)).toEqual([bank.name]);
  const shownTx = theirs.copies[0].slice!.transactions;
  expect(shownTx.length).toBe(s.transactions.filter((t) => t.accountId === bank.id).length);
  await theirs.sharedEdit(list, shownTx.map((t, i) => (i === 0 ? { ...t, note: "Secret note from a friend" } : t)));
  expect(srv.storeOf("user:v").inbox.map((m) => m.kind)).toEqual(["share-edit"]);
  expect(srv.everything()).not.toContain("Secret note from a friend");
  const after = await mine.read(today);
  expect(after.transactions.some((t) => t.note === "Secret note from a friend")).toBe(true);
  for (const w of words(plain)) expect(srv.everything()).not.toContain(w);
});
