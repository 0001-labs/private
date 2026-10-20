import { validateState } from "../../shared/model";
import { ApiError, VaultSession, type Api, type Who } from "../../shared/vault-session";
import { b64, fromUtf8, keysFrom, useTextCipher, newRecordsKey, newRecoverySecret, newVault, recordsKeyFromRecovery, recoveryText, unb64, utf8, wrapKey, type VaultMeta } from "../../shared/private/private.ts";
import { lockAll } from "../../shared/vault-records";
import { sampleState } from "./sample";

// Locked records in the iPhone app: the web's vault session, run here in
// JavaScriptCore, so the app opens, saves and adds exactly as the web does. JavaScriptCore has no
// network of its own; each request goes to the app (`MoneyNative.request`), which sends it with the
// person's token and answers through `answer`. Calls run as promises and end with `MoneyNative.done`.

declare const MoneyNative: {
  request(id: string, method: string, path: string, body: string, headers: string): void;
  done(call: string, ok: boolean, payload: string): void;
  /** CryptoKit's AES-GCM for locked text: JavaScriptCore in an app runs without a JIT, so ours is slow there. */
  lockText?(key: string, text: string, aad: string): string;
  unlockText?(key: string, locked: string, aad: string): string;
};

// The app's own AES-GCM, the same locked format, wherever it offers one (MoneyCore.swift).
if (typeof MoneyNative !== "undefined" && MoneyNative.lockText && MoneyNative.unlockText)
  useTextCipher({ lock: (k, t, a) => MoneyNative.lockText!(k, t, a), unlock: (k, l, a) => MoneyNative.unlockText!(k, l, a) });

/** Standard base64 with padding, as Foundation's `Data(base64Encoded:)` reads it. */
const std64 = (bytes: Uint8Array) => {
  const url = b64(bytes).replace(/-/g, "+").replace(/_/g, "/");
  return url + "=".repeat((4 - (url.length % 4)) % 4);
};

const waiting = new Map<string, (answer: { status: number; body: Uint8Array }) => void>();
let next = 0;
function request(method: string, path: string, body: Uint8Array | null, headers: Record<string, string>) {
  return new Promise<{ status: number; body: Uint8Array }>((resolve) => {
    const id = `r${++next}`;
    waiting.set(id, resolve);
    MoneyNative.request(id, method, path, body ? std64(body) : "", JSON.stringify(headers));
  });
}
const parsed = (body: Uint8Array) => {
  const text = fromUtf8(body);
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
};
const refused = (status: number, body: Uint8Array) => {
  const answer = parsed(body) as { error?: string };
  return new ApiError(status, answer.error ?? `Money answered ${status}`, answer);
};

const api: Api = {
  async json<T>(method: string, path: string, body?: unknown) {
    const r = await request(method, path, body === undefined ? null : utf8(JSON.stringify(body)), body === undefined ? {} : { "Content-Type": "application/json" });
    if (r.status < 200 || r.status >= 300) throw refused(r.status, r.body);
    return parsed(r.body) as T;
  },
  async bytes(method, path, body, headers) {
    const r = await request(method, path, body ?? null, headers ?? {});
    if (r.status < 200 || r.status >= 300) throw refused(r.status, r.body);
    return r.body;
  },
  async send<T>(path: string, body: Uint8Array, headers: Record<string, string>) {
    const r = await request("POST", path, body, headers);
    if (r.status < 200 || r.status >= 300) throw refused(r.status, r.body);
    return parsed(r.body) as T;
  },
};

let session: VaultSession | null = null;
const opened = () => {
  if (!session) throw Error("The records are not unlocked");
  return session;
};

/** Each takes its arguments as strings, as the app passes them, and answers JSON. */
const calls: Record<string, (...args: string[]) => Promise<unknown>> = {
  read: (today) => opened().read(today),
  write: (records, version) => opened().write(validateState(JSON.parse(records)), Number(version)),
  addFile: (data, type, name, today) => opened().addFile(unb64(data), type, name, today),
  receipt: async (id) => {
    const file = await opened().receipt(id);
    return file ? { type: file.type, data: std64(file.bytes) } : null;
  },
  readItems: () => opened().readItems(),
  fileUnfiled: () => opened().fileUnfiled(),
  scanBusiness: () => opened().scanBusiness(),
};

export const vault = {
  /** The app's answer to a request. */
  answer(id: string, status: number, body: string) {
    const resolve = waiting.get(id);
    waiting.delete(id);
    resolve?.({ status: Number(status), body: body ? unb64(body) : new Uint8Array() });
    return "";
  },
  /** Opens the vault with the records key the app keeps in its Keychain; throws when it is not this vault's. */
  open(meta: string, key: string, who: string) {
    session = VaultSession.open(api, unb64(key), JSON.parse(meta) as VaultMeta, JSON.parse(who) as Who);
    return JSON.stringify(true);
  },
  /** The records key a typed recovery key opens, for the app to keep. */
  recover(meta: string, typed: string) {
    return JSON.stringify(std64(recordsKeyFromRecovery(JSON.parse(meta) as VaultMeta, typed)));
  },
  close() {
    session = null;
    return "";
  },
  /** Made-up records locked as the server would keep them, with their recovery key, for the app's tests. */
  sample(today: string) {
    const key = newRecordsKey();
    const recovery = newRecoverySecret();
    const meta: VaultMeta = { ...newVault(keysFrom(key)), wraps: [{ kind: "recovery", wrapped: wrapKey(recovery, key, "recovery"), created: today }] };
    const state = validateState({ ...sampleState(today), version: 4 });
    return JSON.stringify({ served: { meta, version: 4, rows: lockAll(state, keysFrom(key)).put, inbox: 0 }, recovery: recoveryText(recovery), transactions: state.transactions.length });
  },
  /** Starts a call; it ends with `MoneyNative.done(call, ok, json)`. */
  call(call: string, name: string, args: string) {
    const run = calls[name];
    if (!run) {
      MoneyNative.done(call, false, `No such call: ${name}`);
      return "";
    }
    run(...(JSON.parse(args) as string[])).then(
      (value) => MoneyNative.done(call, true, JSON.stringify(value ?? null)),
      (e: unknown) => MoneyNative.done(call, false, e instanceof Error ? e.message : String(e)),
    );
    return "";
  },
};
