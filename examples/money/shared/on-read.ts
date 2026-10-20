import { foldWise } from "./banks";
import { appleSubscriptions } from "./apple";
import { atmsToCash, classifyAll, retireCategories } from "./classify";
import { dropZeroItems, repairItemCurrency } from "./feed";
import type { State } from "./model";

// What Money puts right each time the records are read. The Worker runs it on plain records; with the vault, the
// person's own device runs the same steps, since the server can no longer read what it would fix.

/**
 * Repairs, classifies and files the records in place, as a read always has: receipt lines in the
 * payment's currency, lines of nothing dropped, retired categories, classifying, Apple's lines,
 * ATMs to cash. A lapsed account's records are shown as they are. Answers the steps that changed
 * something, by name and count only.
 */
export function tidy(s: State, { lapsed = false } = {}) {
  const steps: string[] = [];
  if (lapsed) return steps;
  const repaired = repairItemCurrency(s) + dropZeroItems(s);
  if (repaired) steps.push(`items ${repaired}`);
  const retired = retireCategories(s);
  const classified = classifyAll(s);
  const apple = appleSubscriptions(s);
  if (apple) steps.push(`apple ${apple}`);
  const cashed = atmsToCash(s);
  if (retired) steps.push(`retire ${retired}`);
  if (classified) steps.push(`classify ${classified}`);
  if (cashed) steps.push(`atm ${cashed}`);
  return steps;
}


/** Wise as one account (shared/banks.ts), once the rates to add it up are there; a copy, or null when nothing changed. */
export function foldedWise(s: State, today: string) {
  const folded = structuredClone(s);
  return foldWise(folded, today) ? folded : null;
}
