import { foldWise } from "./banks";
import { appleSubscriptions } from "./apple";
import { atmsToCash, classifyAll, retireCategories } from "./classify";
import { dropZeroItems, repairItemCurrency } from "./feed";
import type { State } from "./model";

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


export function foldedWise(s: State, today: string) {
  const folded = structuredClone(s);
  return foldWise(folded, today) ? folded : null;
}
