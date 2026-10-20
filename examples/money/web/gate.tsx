import { useEffect, useState, type ReactNode } from "react";
import { Button, Input, LoadingIndicator, Notice, Toaster } from "../ui";
import { copyText } from "../design/0-face/feedback";
import { validateState, type State } from "../../shared/model";
import { lockFirst, VaultSession, type Who } from "../../shared/vault-session";
import type { VaultMeta } from "../../shared/private/private.ts";
import { keptHere, newKeys, passkeysPossible, rememberHere, unlockWithPasskey, unlockWithRecovery } from "./keys";
import { installVault, webApi } from "./shim";

// Before the app opens on locked records: the first time, the person
// locks their records and keeps their recovery key; on a new browser, they unlock with their passkey
// or that key. A browser that already holds the key opens straight away, with no screen at all.

export type VaultSessionInfo = { kind: "owner" | "account"; code: string | null; access?: string; email?: string; privacy?: boolean; vault?: boolean };
type Served = { meta: VaultMeta | null; version: number };

const whoOf = (s: VaultSessionInfo): Who => ({ owner: s.kind === "owner", code: s.code, access: s.kind === "owner" ? "owner" : s.access ?? "paid" });

/** Opens the vault with what this browser kept, or answers what the person must do first. */
export async function openKept(info: VaultSessionInfo): Promise<{ open: true } | { open: false; meta: VaultMeta | null; version: number }> {
  const served = await webApi.json<Served>("GET", "/api/vault");
  if (!served.meta) return { open: false, meta: null, version: served.version };
  const key = await keptHere(served.meta);
  if (!key) return { open: false, meta: served.meta, version: served.version };
  installVault(VaultSession.open(webApi, key, served.meta, whoOf(info)));
  return { open: true };
}

function Screen({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <main className="vault-gate">
      <span className="splash-mark" aria-hidden="true">MMM</span>
      <ds-text role="heading" aria-level={1} size="display" literal text={String(title)} />
      {children}
      <Toaster />
    </main>
  );
}

/** The first lock, or the unlock on a new browser; `onOpen` once the vault answers the app. */
export function Gate({ info, meta, onOpen }: { info: VaultSessionInfo; meta: VaultMeta | null; onOpen: () => void }) {
  const [step, setStep] = useState<"lock" | "locking" | "recovery" | "unlock">(meta ? "unlock" : "lock");
  const [error, setError] = useState("");
  const [made, setMade] = useState<Awaited<ReturnType<typeof newKeys>> | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const who = whoOf(info);

  async function open(vault: VaultMeta, key: Uint8Array) {
    await rememberHere(vault, key);
    installVault(VaultSession.open(webApi, key, vault, who));
    try {
      localStorage.setItem("money:vault", "1");
    } catch {}
    onOpen();
  }

  // The first lock: a passkey where the browser can make one, and always the recovery key.
  async function begin() {
    setBusy(true);
    setError("");
    try {
      const keys = await newKeys(info.email || "Money");
      setMade(keys);
      setStep("recovery");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not make your key");
    } finally {
      setBusy(false);
    }
  }
  // Once the recovery key is kept, the records are locked: read plain, locked here, swapped on the server.
  async function lock() {
    if (!made) return;
    const groups = made.recoveryText.split("-");
    if (typed.trim().toUpperCase() !== groups[groups.length - 1]) return setError("Type the last six letters of your recovery key, as written.");
    setStep("locking");
    setError("");
    try {
      const r = await fetch("/api/state");
      if (!r.ok) throw Error("Could not read your records to lock them. Try again.");
      const plain: State = validateState(await r.json());
      await lockFirst(webApi, made.recordsKey, made.meta, plain, async (id) => {
        const file = await fetch(`/api/receipt/${id}`);
        return file.ok ? new Uint8Array(await file.arrayBuffer()) : null;
      });
      await open(made.meta, made.recordsKey);
    } catch (e) {
      setStep("recovery");
      setError(e instanceof Error ? e.message : "Could not lock your records. Try again.");
    }
  }
  async function withPasskey() {
    if (!meta) return;
    setBusy(true);
    setError("");
    try {
      const key = await unlockWithPasskey(meta);
      if (!key) throw Error("That passkey does not open these records. Use your recovery key.");
      await open(meta, key);
    } catch (e) {
      setError(e instanceof Error && e.name !== "NotAllowedError" ? e.message : "");
    } finally {
      setBusy(false);
    }
  }
  async function withRecovery() {
    if (!meta) return;
    setError("");
    try {
      await open(meta, unlockWithRecovery(meta, typed));
    } catch (e) {
      setError(e instanceof Error ? e.message : "That recovery key does not open these records");
    }
  }
  useEffect(() => setError(""), [step]);

  if (step === "lock")
    return (
      <Screen title="Lock your records.">
        <p className="vault-lead">
          <ds-text literal wrap text="Only your devices hold the key. Money keeps them locked and cannot read them." />
        </p>
        <p className="vault-note">
          <ds-text tone="muted" literal wrap text="Reading a receipt and your assistant's sends pass through Money for a moment and are never kept readable." />
        </p>
        {error && <Notice tone="danger" text={error} />}
        <div className="vault-actions">
          <Button primary disabled={busy} onClick={() => void begin()}>
            <ds-text literal text={passkeysPossible() ? "Lock with a passkey" : "Lock my records"} />
          </Button>
        </div>
      </Screen>
    );
  if (step === "recovery" || step === "locking")
    return (
      <Screen title="Keep your recovery key.">
        <p className="vault-lead">
          <ds-text
            literal
            wrap
            text={`${made?.passkey ? "Your passkey opens Money on your devices. " : ""}This key opens your records anywhere. Keep it in your password manager or on paper.`}
          />
        </p>
        <code className="vault-key">{made?.recoveryText}</code>
        <div className="vault-actions">
          <Button secondary onClick={() => void copyText(made!.recoveryText, { toast: "Recovery key copied" })}>
            <ds-text literal text="Copy the key" />
          </Button>
        </div>
        <p className="vault-note">
          <ds-text tone="warning" literal wrap text="Lose your passkey and this key, and nobody can open your records. Not even Money." />
        </p>
        <form
          className="vault-form"
          onSubmit={(e) => {
            e.preventDefault();
            void lock();
          }}
        >
          <Input label="Its last six letters" value={typed} autoComplete="off" spellCheck={false} onChange={(e) => setTyped(e.target.value)} error={error || undefined} />
          <div className="vault-actions">
            {step === "locking" ? (
              <LoadingIndicator label="Locking your records" />
            ) : (
              <Button primary type="submit">
                <ds-text literal text="Lock my records" />
              </Button>
            )}
          </div>
        </form>
      </Screen>
    );
  const hasPasskey = !!meta?.wraps.some((w) => w.kind === "passkey") && passkeysPossible();
  return (
    <Screen title="Unlock your records.">
      <p className="vault-lead">
        <ds-text literal wrap text="They are locked with your key. This browser does not hold it yet." />
      </p>
      {hasPasskey && (
        <div className="vault-actions">
          <Button primary disabled={busy} onClick={() => void withPasskey()}>
            <ds-text literal text="Unlock with your passkey" />
          </Button>
        </div>
      )}
      <form
        className="vault-form"
        onSubmit={(e) => {
          e.preventDefault();
          void withRecovery();
        }}
      >
        <Input label="Recovery key" value={typed} autoComplete="off" spellCheck={false} onChange={(e) => setTyped(e.target.value)} error={error || undefined} />
        <div className="vault-actions">
          <Button secondary={hasPasskey} primary={!hasPasskey} type="submit">
            <ds-text literal text="Unlock with the key" />
          </Button>
        </div>
      </form>
    </Screen>
  );
}
