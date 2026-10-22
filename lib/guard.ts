import { decide } from "./decide";
import { applyRedactions, hashText, scanAndScrub } from "./scan";
import {
  CATEGORY_LABELS,
  type Action,
  type Category,
  type Decision,
  type Finding,
  type Severity,
} from "./types";

// The whole pipeline, in one place and free of React, so a test can run the
// real code path and inspect the exact bytes that leave the browser.
//
//   scan locally  ->  classify the scrubbed text  ->  decide by rule  ->  redact

const CATEGORIES: Category[] = [
  "customer_data",
  "personal_data",
  "internal_doc",
  "secret",
];
const SEVERITIES: Severity[] = ["high", "medium", "low"];

export interface GuardOutcome {
  decision: Decision;
  /** The text to send if the user accepts. */
  safeText: string;
  /** Exactly what was POSTed to the classifier. Tests assert on this. */
  sentToClassifier: string;
  classifierFailed: boolean;
  /** Findings the classifier returned that failed validation and were dropped. */
  rejectedFindings: number;
}

export interface GuardOptions {
  /** Injected so tests can spy on the request without a network. */
  fetchImpl?: typeof fetch;
  /** Overridden in tests to keep them fast. */
  endpoint?: string;
}

/**
 * A finding from the model is untrusted input. Anything that fails these
 * checks is discarded rather than acted on: we would otherwise be redacting
 * at offsets the model invented, or trusting a severity we do not recognise.
 */
function validateFinding(raw: unknown, scrubbed: string): Finding | null {
  if (typeof raw !== "object" || raw === null) return null;
  const f = raw as Record<string, unknown>;

  if (typeof f.text !== "string" || f.text.length === 0) return null;
  // The span must exist verbatim in the text we actually sent. This is what
  // stops an invented or hallucinated span from driving a redaction.
  if (!scrubbed.includes(f.text)) return null;

  if (typeof f.category !== "string") return null;
  if (!CATEGORIES.includes(f.category as Category)) return null;

  if (typeof f.severity !== "string") return null;
  if (!SEVERITIES.includes(f.severity as Severity)) return null;

  if (typeof f.confidence !== "number") return null;
  if (!Number.isFinite(f.confidence)) return null;
  if (f.confidence < 0 || f.confidence > 1) return null;

  const reason = typeof f.reason === "string" ? f.reason : "Flagged by the classifier.";

  return {
    text: f.text,
    category: f.category as Category,
    severity: f.severity as Severity,
    confidence: f.confidence,
    reason,
    source: "ai",
    label: CATEGORY_LABELS[f.category as Category] ?? "SENSITIVE",
  };
}

export async function runGuard(
  input: string,
  opts: GuardOptions = {}
): Promise<GuardOutcome> {
  const doFetch = opts.fetchImpl ?? fetch;
  const endpoint = opts.endpoint ?? "/api/classify";

  // STEP 1 - local scan, on this device. Known secrets never reach the network.
  const { scrubbed, findings: localFindings } = scanAndScrub(input);

  // STEP 2 - classify only what is left.
  let classified: Finding[] = [];
  let classifierFailed = false;
  let rejectedFindings = 0;

  try {
    const res = await doFetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ scrubbed }),
    });
    if (!res.ok) throw new Error("classifier returned " + res.status);

    const data = await res.json();
    const raw = Array.isArray(data?.findings) ? data.findings : [];

    for (const item of raw) {
      const valid = validateFinding(item, scrubbed);
      if (valid) classified.push(valid);
      else rejectedFindings++;
    }
  } catch {
    // Fail closed. decide() refuses to report "allow" when this is true.
    classifierFailed = true;
    classified = [];
  }

  // STEP 3 - fixed rules, not the model, choose the action.
  const decision = decide(localFindings, classified, classifierFailed);
  const safeText = applyRedactions(scrubbed, decision.redactions);

  return {
    decision,
    safeText,
    sentToClassifier: scrubbed,
    classifierFailed,
    rejectedFindings,
  };
}

/** Exactly what the admin is told. Metadata only - no text, no spans, no values. */
export interface AlertPayload {
  action: Action;
  categories: Category[];
  counts: Record<string, number>;
  hash: string;
  classifierFailed: boolean;
}

/**
 * Built here rather than inline in the UI so that one test can prove no
 * sensitive value ever reaches the admin layer, against the real code.
 *
 * Deliberately NOT included: the prompt, the safe text, finding.text,
 * finding.reason (a model-written sentence that can quote the input), and
 * provider payloads.
 */
export async function buildAlertPayload(
  findings: Finding[],
  action: Action,
  originalText: string,
  classifierFailed: boolean
): Promise<AlertPayload> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.category] = (counts[f.category] ?? 0) + 1;
  }
  return {
    action,
    categories: [...new Set(findings.map((f) => f.category))],
    counts,
    hash: await hashText(originalText),
    classifierFailed,
  };
}
