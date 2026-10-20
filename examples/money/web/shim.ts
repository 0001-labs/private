import { useEffect, useState } from "react";
import { ApiError, VaultSession, type Api } from "../../shared/vault-session";

// The web app on locked records. The app keeps asking `/api/state`,
// `/api/inbox` and the rest as it always has; with the vault open, those requests are answered here,
// on the person's device, by the vault session, which talks to the server only in locked rows,
// sealed copies and the pass-through readers. As the film kit does (src/film/kit.tsx), the boundary
// is `fetch`: no part of the app needs to know whether its records are locked.

const original = globalThis.fetch.bind(globalThis);
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** Money's own API over the browser's fetch, as the vault session needs it. */
export const webApi: Api = {
  async json<T>(method: string, path: string, body?: unknown) {
    const r = await original(path, {
      method,
      ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    });
    const answer = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, (answer as { error?: string }).error ?? `Money answered ${r.status}`, answer);
    return answer as T;
  },
  async bytes(method, path, body, headers) {
    const r = await original(path, { method, ...(body ? { body: new Uint8Array(body), headers } : {}) });
    if (!r.ok) throw new ApiError(r.status, `Money answered ${r.status}`);
    return new Uint8Array(await r.arrayBuffer());
  },
  async send<T>(path: string, body: Uint8Array, headers: Record<string, string>) {
    const r = await original(path, { method: "POST", body: new Uint8Array(body), headers });
    const answer = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, (answer as { error?: string }).error ?? `Money answered ${r.status}`, answer);
    return answer as T;
  },
};

const failure = (e: unknown) => {
  if (e instanceof ApiError) return json(e.body && typeof e.body === "object" ? e.body : { error: e.message }, e.status);
  return json({ error: e instanceof Error && e.message.includes("Conflict") ? "Another tab changed these records. Reload before saving." : "Could not do that. Try again." }, 400);
};
const today = () => new Date().toLocaleDateString("en-CA");

/** Whether the app's records are answered by the vault, so a kept file is opened here rather than linked. */
export let vaultOpen = false;

/** Answers the app's record requests from the vault session from now on. */
export function installVault(session: VaultSession) {
  vaultOpen = true;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, location.href);
    if (url.origin !== location.origin) return original(input, init);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const path = url.pathname;
    try {
      if (path === "/api/state" && method === "GET") return json(await session.read(today()));
      if (path === "/api/state" && method === "PUT") {
        const body = JSON.parse(String(init?.body)) as { state: unknown; expectedVersion: number };
        return json(await session.write(body.state as never, body.expectedVersion));
      }
      if (path === "/api/version") {
        // Something sealed to the person waits: a version ahead makes the page read again, which adds it.
        const r = await original(input, init);
        const v = (await r.json()) as { version: number; inbox?: number };
        return json({ version: v.version + (v.inbox ? 1 : 0) });
      }
      if (path === "/api/inbox" && method === "POST") {
        const type = (new Headers(init?.headers).get("content-type") || "").split(";")[0].trim().toLowerCase();
        const name = decodeURIComponent(new Headers(init?.headers).get("x-file-name") || "file");
        const body = init?.body instanceof Blob ? new Uint8Array(await init.body.arrayBuffer()) : new Uint8Array(init?.body as ArrayBuffer);
        const result = await session.addFile(body, type, name, today());
        return json(result, result.added.length ? 201 : 200);
      }
      const receipt = /^\/api\/receipt\/([0-9a-f-]{36})$/.exec(path);
      if (receipt) {
        const file = await session.receipt(receipt[1]);
        return file ? new Response(new Uint8Array(file.bytes), { headers: { "Content-Type": file.type } }) : json({ error: "Not found" }, 404);
      }
      const sharedReceipt = /^\/api\/shared\/([^/]+)\/receipt\/([0-9a-f-]{36})$/.exec(path);
      if (sharedReceipt) {
        const file = await session.sharedReceipt(decodeURIComponent(sharedReceipt[1]), sharedReceipt[2]);
        if (file) return new Response(new Uint8Array(file.bytes), { headers: { "Content-Type": file.type } });
        return original(input, init);
      }
      if (path === "/api/receipts/items" && method === "POST") return json(await session.readItems());
      if (path === "/api/categories/file" && method === "POST") return json(await session.fileUnfiled());
      if (path === "/api/business/scan" && method === "POST") return json(await session.scanBusiness());
      if (path === "/api/business/decide" && method === "POST") {
        const body = JSON.parse(String(init?.body)) as { ids: string[]; business: boolean };
        return json(await session.decide(body.ids, body.business));
      }
      if (path === "/api/shared/state" && method === "GET") return json(await session.shared());
      if (path === "/api/shared" && method === "GET") {
        // The lists shared with this person: plain ones from owners not locked yet, and the sealed copies.
        const plain = await original(input, init);
        const listed = plain.ok ? ((await plain.json()) as { code: string | null; lists: unknown[] }) : { code: session.who.code, lists: [] };
        if (!session.copies.length) await session.shared();
        const sealed = session.copies.map((c) => ({ list: c.list, name: c.name, accountIds: c.slice?.accounts.map((a) => a.id) ?? [], role: c.role, owner: c.owner }));
        return json({ ...listed, lists: [...listed.lists, ...sealed] });
      }
      const list = /^\/api\/shared\/([^/]+)$/.exec(path);
      if (list) {
        const code = decodeURIComponent(list[1]);
        if (!session.copies.length) await session.shared();
        const copy = session.copies.find((c) => c.list === code);
        if (!copy) return original(input, init);
        if (method === "GET") return json({ ...copy.slice, list: copy.list, role: copy.role, owner: copy.owner });
        if (method === "PUT") {
          const body = JSON.parse(String(init?.body)) as { transactions: unknown };
          await session.sharedEdit(code, body.transactions);
          // Its owner's device applies it when it next opens Money; until then the copy shows as it was.
          return json({ ...copy.slice, transactions: body.transactions, list: copy.list, role: copy.role, owner: copy.owner, waiting: true });
        }
      }
      const open = /^\/api\/open\/([^/]+)$/.exec(path);
      if (open) {
        // The registry knows a locked record by a hash of its id; this device knows which record that is.
        const r = await original(input, init);
        const found = (await r.json()) as { own?: boolean; kind?: string; id?: string; ref?: string; list?: string };
        if (found.own && found.id) return json({ ...found, id: session.recordOf(found.id) ?? found.id });
        if (found.ref) return json({ own: false, list: found.list });
        return json(found, r.status);
      }
      if ((path === "/api/shares" && method === "POST") || (path.startsWith("/api/shares/") && method === "DELETE")) {
        const r = await original(input, init);
        if (r.ok) void session.seal().catch(() => undefined);
        return r;
      }
    } catch (e) {
      return failure(e);
    }
    return original(input, init);
  };
}

/**
 * A kept receipt's address for an image, a frame or a download. Plain records link the server's
 * file; locked ones are opened here and shown from the page's own memory (a blob address).
 */
export function useFileUrl(url: string | null) {
  const [shown, setShown] = useState<string | null>(vaultOpen ? null : url);
  useEffect(() => {
    if (!vaultOpen || !url) return setShown(url);
    let address: string | null = null;
    let gone = false;
    setShown(null);
    void fetch(url)
      .then((r) => (r.ok ? r.blob() : null))
      .then((blob) => {
        if (!blob || gone) return;
        address = URL.createObjectURL(blob);
        setShown(address);
      })
      .catch(() => undefined);
    return () => {
      gone = true;
      if (address) URL.revokeObjectURL(address);
    };
  }, [url]);
  return shown;
}
