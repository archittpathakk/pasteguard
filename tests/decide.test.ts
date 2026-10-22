import { describe, expect, it } from "vitest";
import { decide } from "@/lib/decide";
import type { Finding } from "@/lib/types";

/**
 * The thresholds are the product's policy. They must be exact, and they must
 * not drift quietly - a loosened threshold is a silent reduction in protection.
 */

function aiFinding(severity: Finding["severity"], confidence: number): Finding {
  return {
    text: "jane.roe@acme-widgets.example",
    category: "customer_data",
    severity,
    confidence,
    reason: "test fixture",
    source: "ai",
    label: "CUSTOMER",
  };
}

function localFinding(): Finding {
  return {
    text: "AKIAIOSFODNN7EXAMPLE",
    category: "secret",
    severity: "high",
    confidence: 1,
    reason: "AWS access key ID",
    source: "local",
    label: "AWS_KEY",
  };
}

describe("threshold matrix", () => {
  const cases: Array<[Finding["severity"], number, "redact" | "warn" | "allow"]> = [
    // high: redact at or above 0.70
    ["high", 1.0, "redact"],
    ["high", 0.71, "redact"],
    ["high", 0.7, "redact"],
    ["high", 0.699, "warn"],
    ["high", 0.5, "warn"],
    // medium: redact at or above 0.80
    ["medium", 1.0, "redact"],
    ["medium", 0.81, "redact"],
    ["medium", 0.8, "redact"],
    ["medium", 0.799, "warn"],
    ["medium", 0.5, "warn"],
    // low: never acted on
    ["low", 1.0, "allow"],
    ["low", 0.2, "allow"],
  ];

  it.each(cases)("%s severity at confidence %f -> %s", (severity, confidence, expected) => {
    const d = decide([], [aiFinding(severity, confidence)], false);
    expect(d.action).toBe(expected);
  });

  it("puts above-threshold findings in redactions, below-threshold in warnings", () => {
    const d = decide([], [aiFinding("high", 0.9), aiFinding("high", 0.4)], false);
    expect(d.redactions).toHaveLength(1);
    expect(d.warnings).toHaveLength(1);
    expect(d.redactions[0].confidence).toBe(0.9);
  });

  it("boundary values are inclusive, not exclusive", () => {
    expect(decide([], [aiFinding("high", 0.7)], false).redactions).toHaveLength(1);
    expect(decide([], [aiFinding("medium", 0.8)], false).redactions).toHaveLength(1);
  });
});

describe("local matches are never negotiable", () => {
  it("always redacts a local pattern match", () => {
    const d = decide([localFinding()], [], false);
    expect(d.action).toBe("redact");
    expect(d.redactions).toHaveLength(1);
  });

  it("redacts a local match even when the classifier failed", () => {
    const d = decide([localFinding()], [], true);
    expect(d.redactions).toHaveLength(1);
    expect(d.classifierFailed).toBe(true);
  });
});

describe("fail closed", () => {
  it("never reports allow when the classifier failed", () => {
    const d = decide([], [], true);
    expect(d.action).not.toBe("allow");
    expect(d.action).toBe("warn");
  });

  it("says the text was not checked", () => {
    const d = decide([], [], true);
    expect(d.summary.toLowerCase()).toContain("couldn't check");
  });

  it("does not claim a clean bill of health with findings present", () => {
    const d = decide([localFinding()], [], true);
    expect(d.summary.toLowerCase()).toContain("couldn't check");
    expect(d.summary.toLowerCase()).not.toContain("nothing sensitive");
  });

  it("allows only when the classifier succeeded and nothing was found", () => {
    const d = decide([], [], false);
    expect(d.action).toBe("allow");
    expect(d.classifierFailed).toBe(false);
  });
});

describe("decision summary", () => {
  it("counts match the actual redactions", () => {
    const d = decide([localFinding()], [aiFinding("high", 0.95), aiFinding("high", 0.95)], false);
    expect(d.redactions).toHaveLength(3);
    expect(d.summary).toContain("1 API key");
    expect(d.summary).toContain("2 customer details");
  });

  it("uses singular wording for one item", () => {
    const d = decide([], [aiFinding("high", 0.95)], false);
    expect(d.summary).toContain("1 customer detail");
    expect(d.summary).not.toContain("1 customer details");
  });

  it("reports nothing found when there is nothing", () => {
    expect(decide([], [], false).summary.toLowerCase()).toContain("nothing sensitive");
  });
});
