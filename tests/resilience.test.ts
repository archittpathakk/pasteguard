import { describe, expect, it, vi } from "vitest";
import { runGuard } from "@/lib/guard";
import { FAKE, SQL_PASTE, SUPPORT_TICKET_PASTE } from "./fixtures";

/**
 * Model output is untrusted input. A classifier that returns nonsense, or no
 * response at all, must never result in "all clear".
 */

function respondWith(payload: unknown, ok = true, status = 200): typeof fetch {
  return vi.fn(async () => ({
    ok,
    status,
    json: async () => payload,
  })) as unknown as typeof fetch;
}

function failWith(error: Error): typeof fetch {
  return vi.fn(async () => {
    throw error;
  }) as unknown as typeof fetch;
}

// The classifier is told to copy spans verbatim; a real one appears in SQL_PASTE.
const REAL_SPAN = "rohan.mehta@finserv-partners.in";

describe("malformed model output is rejected", () => {
  const bad: Array<[string, unknown]> = [
    ["not an object", "a string"],
    ["null entry", null],
    ["missing text", { category: "customer_data", severity: "high", confidence: 0.9 }],
    ["empty text", { text: "", category: "customer_data", severity: "high", confidence: 0.9 }],
    [
      "text that is not in the sent payload",
      { text: "value-the-model-invented", category: "customer_data", severity: "high", confidence: 0.9 },
    ],
    [
      "unknown category",
      { text: REAL_SPAN, category: "nuclear_codes", severity: "high", confidence: 0.9 },
    ],
    [
      "unknown severity",
      { text: REAL_SPAN, category: "customer_data", severity: "catastrophic", confidence: 0.9 },
    ],
    [
      "confidence above 1",
      { text: REAL_SPAN, category: "customer_data", severity: "high", confidence: 4.2 },
    ],
    [
      "negative confidence",
      { text: REAL_SPAN, category: "customer_data", severity: "high", confidence: -1 },
    ],
    [
      "confidence as a string",
      { text: REAL_SPAN, category: "customer_data", severity: "high", confidence: "0.9" },
    ],
    [
      "confidence NaN",
      { text: REAL_SPAN, category: "customer_data", severity: "high", confidence: NaN },
    ],
    [
      "text as a number",
      { text: 12345, category: "customer_data", severity: "high", confidence: 0.9 },
    ],
  ];

  it.each(bad)("drops a finding with %s", async (_label, finding) => {
    const out = await runGuard(SQL_PASTE, {
      fetchImpl: respondWith({ findings: [finding] }),
    });
    // Dropped, not acted on.
    expect(out.rejectedFindings).toBe(1);
    expect(out.decision.redactions.some((f) => f.source === "ai")).toBe(false);
  });

  it("keeps a valid finding alongside invalid ones", async () => {
    const out = await runGuard(SQL_PASTE, {
      fetchImpl: respondWith({
        findings: [
          { text: REAL_SPAN, category: "customer_data", severity: "high", confidence: 0.95, reason: "ok" },
          { text: "invented", category: "customer_data", severity: "high", confidence: 0.95 },
          "garbage",
        ],
      }),
    });
    expect(out.rejectedFindings).toBe(2);
    expect(out.decision.redactions.filter((f) => f.source === "ai")).toHaveLength(1);
  });

  it("survives findings that is not an array", async () => {
    const out = await runGuard(SQL_PASTE, {
      fetchImpl: respondWith({ findings: "nope" }),
    });
    expect(out.classifierFailed).toBe(false);
    expect(out.decision.redactions.some((f) => f.source === "ai")).toBe(false);
  });

  it("treats invalid JSON as a classifier failure, not as safe", async () => {
    const impl = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError("Unexpected token < in JSON");
      },
    })) as unknown as typeof fetch;

    const out = await runGuard(SQL_PASTE, { fetchImpl: impl });
    expect(out.classifierFailed).toBe(true);
    expect(out.decision.action).not.toBe("allow");
  });

  it("never lets an invalid finding suppress a local redaction", async () => {
    const out = await runGuard(SUPPORT_TICKET_PASTE, {
      fetchImpl: respondWith({ findings: ["garbage", null, 42] }),
    });
    expect(out.safeText).not.toContain(FAKE.stripeKey);
    expect(out.decision.redactions.some((f) => f.source === "local")).toBe(true);
  });
});

describe("provider failure fails closed", () => {
  const failures: Array<[string, typeof fetch]> = [
    ["timeout", failWith(Object.assign(new Error("timed out"), { name: "TimeoutError" }))],
    ["network error", failWith(new TypeError("fetch failed"))],
    ["503 unavailable", respondWith({ error: "high demand" }, false, 503)],
    ["429 rate limited", respondWith({ error: "rate limited" }, false, 429)],
    ["401 bad credentials", respondWith({ error: "invalid key" }, false, 401)],
    ["500 server error", respondWith({ error: "boom" }, false, 500)],
  ];

  it.each(failures)("%s results in an unverified state, not allow", async (_label, impl) => {
    const out = await runGuard(SQL_PASTE, { fetchImpl: impl });
    expect(out.classifierFailed).toBe(true);
    expect(out.decision.action).not.toBe("allow");
    expect(out.decision.summary.toLowerCase()).toContain("couldn't check");
  });

  it.each(failures)("%s still applies local redactions", async (_label, impl) => {
    const out = await runGuard(SUPPORT_TICKET_PASTE, { fetchImpl: impl });
    expect(out.safeText).not.toContain(FAKE.stripeKey);
    expect(out.safeText).toContain("[STRIPE_KEY_REMOVED]");
  });

  it("a clean prompt with a dead classifier is still not declared safe", async () => {
    const out = await runGuard("just some ordinary text about the weather", {
      fetchImpl: respondWith({}, false, 503),
    });
    expect(out.decision.action).toBe("warn");
    expect(out.decision.action).not.toBe("allow");
  });
});

describe("empty and trivial input", () => {
  it("handles empty input without calling the classifier", async () => {
    const impl = respondWith({ findings: [] });
    const out = await runGuard("", { fetchImpl: impl });
    expect(out.decision.redactions).toHaveLength(0);
    expect(out.sentToClassifier).toBe("");
  });
});
