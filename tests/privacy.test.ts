import { describe, expect, it, vi } from "vitest";
import { buildAlertPayload, runGuard } from "@/lib/guard";
import { hashText } from "@/lib/scan";
import {
  AUTH_HEADER_PASTE,
  CUSTOMER,
  INJECTION_PASTE,
  REPEATED_CREDENTIAL_PASTE,
  SENSITIVE_VALUES,
  SQL_PASTE,
  SUPPORT_TICKET_PASTE,
} from "./fixtures";

/**
 * The admin must be able to see that something happened without being able to
 * see what. These tests sweep the admin payload for every sensitive value in
 * the fixtures; the expected result is always zero hits.
 */

const ALL_PASTES = [
  SUPPORT_TICKET_PASTE,
  SQL_PASTE,
  INJECTION_PASTE,
  REPEATED_CREDENTIAL_PASTE,
  AUTH_HEADER_PASTE,
];

function classifierFinding(text: string) {
  return {
    text,
    category: "customer_data",
    severity: "high",
    confidence: 0.95,
    reason: `Contains ${text}, which identifies a customer`, // deliberately quotes the value
  };
}

function respondWith(findings: unknown[]): typeof fetch {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ findings }),
  })) as unknown as typeof fetch;
}

describe("admin payload carries no sensitive values", () => {
  it.each(ALL_PASTES.map((p, i) => [i + 1, p] as const))(
    "fixture %i leaks nothing to the admin",
    async (_n, paste) => {
      const out = await runGuard(paste, { fetchImpl: respondWith([]) });
      const payload = await buildAlertPayload(
        out.decision.redactions,
        out.decision.action,
        paste,
        out.classifierFailed
      );
      const serialized = JSON.stringify(payload);

      const leaked = SENSITIVE_VALUES.filter((v) => serialized.includes(v));
      expect(leaked, `leaked: ${leaked.join(", ")}`).toHaveLength(0);
    }
  );

  it("does not carry the prompt, the safe text, or any finding text", async () => {
    const out = await runGuard(SQL_PASTE, {
      fetchImpl: respondWith([classifierFinding(CUSTOMER.emailB)]),
    });
    const payload = await buildAlertPayload(
      out.decision.redactions,
      out.decision.action,
      SQL_PASTE,
      out.classifierFailed
    );
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain("SELECT");
    expect(serialized).not.toContain(CUSTOMER.emailB);
    expect(serialized).not.toContain("[DB_PASSWORD_REMOVED]");
    expect(serialized).not.toContain("connection string");
  });

  it("does not carry the model's reason text, which can quote the input", async () => {
    // A reason like "Contains rohan.mehta@... which identifies a customer"
    // would smuggle the value into the admin log through the back door.
    const out = await runGuard(SQL_PASTE, {
      fetchImpl: respondWith([classifierFinding(CUSTOMER.emailB)]),
    });
    expect(out.decision.redactions.some((f) => f.reason.includes(CUSTOMER.emailB))).toBe(true);

    const payload = await buildAlertPayload(
      out.decision.redactions,
      out.decision.action,
      SQL_PASTE,
      out.classifierFailed
    );
    expect(JSON.stringify(payload)).not.toContain(CUSTOMER.emailB);
  });

  it("carries only the permitted field names", async () => {
    const payload = await buildAlertPayload([], "allow", SQL_PASTE, false);
    expect(Object.keys(payload).sort()).toEqual([
      "action",
      "categories",
      "classifierFailed",
      "counts",
      "hash",
    ]);
  });

  it("counts are numbers, categories are category names, nothing else", async () => {
    const out = await runGuard(SUPPORT_TICKET_PASTE, { fetchImpl: respondWith([]) });
    const payload = await buildAlertPayload(
      out.decision.redactions,
      out.decision.action,
      SUPPORT_TICKET_PASTE,
      false
    );
    for (const v of Object.values(payload.counts)) expect(typeof v).toBe("number");
    for (const c of payload.categories) {
      expect(["customer_data", "personal_data", "internal_doc", "secret"]).toContain(c);
    }
  });
});

describe("correlation hash", () => {
  it("is stable for identical input", async () => {
    expect(await hashText("same text")).toBe(await hashText("same text"));
  });

  it("differs for different input", async () => {
    expect(await hashText("text a")).not.toBe(await hashText("text b"));
  });

  it("does not contain the input", async () => {
    const h = await hashText(CUSTOMER.emailA);
    expect(h).not.toContain("okonkwo");
    expect(h).toMatch(/^[0-9a-f]{16}$/);
  });

  it("correlates an override with the decision it overrode", async () => {
    const decisionPayload = await buildAlertPayload([], "redact", SQL_PASTE, false);
    const overridePayload = await buildAlertPayload([], "override", SQL_PASTE, false);
    expect(overridePayload.hash).toBe(decisionPayload.hash);
    expect(overridePayload.action).toBe("override");
  });
});
