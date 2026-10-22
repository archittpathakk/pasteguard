import { SECRET_PATTERNS } from "./patterns";
import type { Finding } from "./types";

interface Span {
  start: number;
  end: number;
  label: string;
  reason: string;
}

export interface ScanResult {
  /** The text with every known secret swapped for a placeholder. */
  scrubbed: string;
  findings: Finding[];
}

/**
 * Find every known secret format and replace it with a placeholder.
 * Runs in the BROWSER, before anything is sent anywhere.
 */
export function scanAndScrub(input: string): ScanResult {
  const spans: Span[] = [];

  for (const p of SECRET_PATTERNS) {
    // Fresh regex each time: /g regexes carry lastIndex between calls.
    // The "d" flag gives exact start/end for each capture group. Searching the
    // match text for the group instead would find the wrong copy whenever a
    // value repeats - e.g. postgres://admin:admin@host redacts the username.
    const flags = p.re.flags.includes("d") ? p.re.flags : p.re.flags + "d";
    const re = new RegExp(p.re.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(input)) !== null) {
      const groupIndex = p.group ?? 0;
      const value = m[groupIndex];
      if (!value) continue;

      const range =
        groupIndex === 0
          ? [m.index, m.index + m[0].length]
          : m.indices?.[groupIndex];
      if (!range) continue; // group didn't participate in this match

      spans.push({
        start: range[0],
        end: range[1],
        label: p.label,
        reason: p.reason,
      });
      if (m[0].length === 0) re.lastIndex++; // guard against zero-length loops
    }
  }

  // Longest match wins, then drop anything overlapping an already-kept span.
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Span[] = [];
  for (const s of spans) {
    if (kept.some((k) => s.start < k.end && s.end > k.start)) continue;
    kept.push(s);
  }

  // Rebuild back-to-front so earlier indexes stay valid.
  let scrubbed = input;
  const findings: Finding[] = [];
  for (const s of [...kept].sort((a, b) => b.start - a.start)) {
    scrubbed =
      scrubbed.slice(0, s.start) +
      `[${s.label}_REMOVED]` +
      scrubbed.slice(s.end);
  }
  for (const s of kept) {
    findings.push({
      text: input.slice(s.start, s.end),
      category: "secret",
      severity: "high",
      confidence: 1, // a pattern either matched or it didn't
      reason: s.reason,
      source: "local",
      label: s.label,
    });
  }

  return { scrubbed, findings };
}

/** Swap each finding's literal text for its placeholder. */
export function applyRedactions(text: string, findings: Finding[]): string {
  let out = text;
  for (const f of findings) {
    if (!f.text) continue;
    out = out.split(f.text).join(`[${f.label}_REMOVED]`);
  }
  return out;
}

/**
 * One-way correlation hash: SHA-256, truncated for display.
 *
 * This lets an admin see that two pastes were identical without either being
 * stored. It is NOT anonymisation. A hash of a short, low-entropy input (a
 * single email address, say) can be recovered by guessing, and truncation
 * raises the chance of collision. Treat a hash as pseudonymous at best, do
 * not publish it, and do not reason about it as if the content were gone.
 *
 * Async because SubtleCrypto is async in both the browser and Node.
 */
export async function hashText(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
