// Shared shapes. Both the browser and the server import these, so there is
// exactly one definition of what a "finding" is.

export type Category =
  | "secret"
  | "customer_data"
  | "personal_data"
  | "internal_doc";

export type Severity = "high" | "medium" | "low";

/**
 * What we do with the paste. Decided by rules in lib/decide.ts, never by AI.
 * "override" is not a decision we make - it is the user overruling us, and it
 * is logged because override rate is the signal that says a rule is too strict.
 */
export type Action = "allow" | "redact" | "warn" | "block" | "override";

/**
 * Placeholder text per category. One map, so the browser can't invent a label
 * that contradicts what the classifier actually said.
 */
export const CATEGORY_LABELS: Record<Category, string> = {
  customer_data: "CUSTOMER",
  personal_data: "PERSONAL",
  internal_doc: "INTERNAL",
  secret: "SECRET",
};

export interface Finding {
  /** The literal text that broke the policy. */
  text: string;
  category: Category;
  severity: Severity;
  /** 0..1. Local pattern matches are always 1 - a regex either matched or it didn't. */
  confidence: number;
  reason: string;
  /** "local" never left the browser. "ai" came back from the classifier. */
  source: "local" | "ai";
  /** Placeholder we swap in, e.g. AWS_KEY -> [AWS_KEY_REMOVED]. */
  label: string;
}

export interface Decision {
  action: Action;
  /** Findings we remove outright. */
  redactions: Finding[];
  /** Findings we show but leave in - the user decides. */
  warnings: Finding[];
  /** True when the Claude call failed. We fail closed: never silently allow. */
  classifierFailed: boolean;
  /** Human sentence for the banner. */
  summary: string;
}

export interface AlertEvent {
  id: string;
  at: string;
  action: Action;
  categories: Category[];
  counts: Record<string, number>;
  /** Hash of the original text. Proves two pastes were identical without storing either. */
  hash: string;
  classifierFailed: boolean;
}
