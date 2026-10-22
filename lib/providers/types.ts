// One shape every AI provider must return. The rest of the app only knows
// about this, so swapping Gemini for Claude is a config change, not a rewrite.

export interface RawFinding {
  text: string;
  category: "customer_data" | "personal_data" | "internal_doc" | "secret";
  severity: "high" | "medium" | "low";
  confidence: number;
  reason: string;
}

export interface Classifier {
  /** Shown in the UI and logs so you always know who answered. */
  name: string;
  /** Throws on failure. The caller turns that into "fail closed". */
  classify(scrubbed: string): Promise<RawFinding[]>;
}

/** The JSON shape we ask every provider for. */
export const FINDING_FIELDS = [
  "text",
  "category",
  "severity",
  "confidence",
  "reason",
] as const;

export const CATEGORIES = [
  "customer_data",
  "personal_data",
  "internal_doc",
  "secret",
] as const;

export const SEVERITIES = ["high", "medium", "low"] as const;
