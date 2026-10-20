import { configureBrowser, forgetHere as forgetKeys } from "../../shared/private/browser.ts";

// Money's records key in a browser: Private's (shared/private/browser.ts, a copy of src/browser.ts),
// named for Money. Signing out forgets the key and that this browser opened locked records.
configureBrowser({ product: "Money, money, money", database: "money-vault" });
export { keptHere, newKeys, passkeysPossible, rememberHere, unlockWithPasskey, unlockWithRecovery } from "../../shared/private/browser.ts";

export async function forgetHere() {
  await forgetKeys();
  try {
    localStorage.removeItem("money:vault");
  } catch {}
}
