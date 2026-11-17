import { configureBrowser, forgetHere as forgetKeys } from "../../shared/private/browser.ts";

configureBrowser({ product: "Money, money, money", database: "money-vault" });
export { keptHere, newKeys, passkeysPossible, rememberHere, unlockWithPasskey, unlockWithRecovery } from "../../shared/private/browser.ts";

export async function forgetHere() {
  await forgetKeys();
  try {
    localStorage.removeItem("money:vault");
  } catch {}
}
