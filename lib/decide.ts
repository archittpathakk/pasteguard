import type { Decision, Finding } from "./types";

// Turning findings into an action is PLAIN CODE, on purpose. The thresholds
// below are the whole policy of the product: they must be predictable,
// auditable, and identical on every run. An AI deciding this would make the
// same paste behave differently on different days.

const REDACT_IF_HIGH_ABOVE = 0.7;
const REDACT_IF_MEDIUM_ABOVE = 0.8;

export function decide(
  local: Finding[],
  classified: Finding[],
  classifierFailed: boolean
): Decision {
  // Local pattern matches are never negotiable - a key is a key.
  const redactions: Finding[] = [...local];
  const warnings: Finding[] = [];

  for (const f of classified) {
    if (f.severity === "low") continue; // below the bar; let it through
    const bar =
      f.severity === "high" ? REDACT_IF_HIGH_ABOVE : REDACT_IF_MEDIUM_ABOVE;
    if (f.confidence >= bar) redactions.push(f);
    else warnings.push(f); // not sure enough to remove - show it, user decides
  }

  let action: Decision["action"] = "allow";
  if (redactions.length > 0) action = "redact";
  else if (warnings.length > 0) action = "warn";

  // Fail closed. If the classifier didn't answer we have NOT checked for
  // customer data, so we never report a clean bill of health.
  if (classifierFailed && action === "allow") action = "warn";

  return {
    action,
    redactions,
    warnings,
    classifierFailed,
    summary: buildSummary(redactions, warnings, classifierFailed),
  };
}

function buildSummary(
  redactions: Finding[],
  warnings: Finding[],
  classifierFailed: boolean
): string {
  const parts: string[] = [];
  const secrets = redactions.filter((f) => f.category === "secret").length;
  const emails = redactions.filter(
    (f) => f.category === "customer_data" || f.category === "personal_data"
  ).length;
  const other = redactions.length - secrets - emails;

  if (secrets) parts.push(plural(secrets, "API key", "API keys"));
  if (emails) parts.push(plural(emails, "customer detail", "customer details"));
  if (other) parts.push(plural(other, "item", "items"));

  let summary =
    parts.length > 0
      ? `Removed ${joinList(parts)} - sending the safe version.`
      : "Nothing sensitive found.";

  if (classifierFailed) {
    summary =
      parts.length > 0
        ? `Removed ${joinList(parts)}. Couldn't check for customer data - review before sending.`
        : "Couldn't check for customer data - review before sending.";
  } else if (warnings.length > 0) {
    summary += ` ${plural(warnings.length, "item needs", "items need")} your review.`;
  }

  return summary;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function joinList(parts: string[]): string {
  if (parts.length <= 1) return parts.join("");
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}
