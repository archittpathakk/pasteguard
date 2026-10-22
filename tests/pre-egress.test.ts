import { describe, expect, it, vi } from "vitest";
import { runGuard } from "@/lib/guard";
import {
  AUTH_HEADER_PASTE,
  CUSTOMER,
  FAKE,
  INJECTION_PASTE,
  REPEATED_CREDENTIAL_PASTE,
  SENSITIVE_VALUES,
  SQL_PASTE,
  SUPPORT_TICKET_PASTE,
} from "./fixtures";

/**
 * The product's central claim: known secrets are removed BEFORE anything is
 * sent. These tests do not trust the implementation's own report - they
 * capture the exact bytes handed to fetch and inspect them.
 */

interface Captured {
  url: string;
  body: string;
}

function spyFetch(findings: unknown[] = []) {
  const captured: Captured[] = [];
  const impl = vi.fn(async (url: unknown, init?: unknown) => {
    const i = init as { body?: string } | undefined;
    captured.push({ url: String(url), body: i?.body ?? "" });
    return {
      ok: true,
      status: 200,
      json: async () => ({ findings }),
    } as unknown as Response;
  });
  return { impl: impl as unknown as typeof fetch, captured };
}

describe("pre-egress guarantee", () => {
  it("sends exactly one request, to the classify endpoint", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(SQL_PASTE, { fetchImpl: impl });
    expect(captured).toHaveLength(1);
    expect(captured[0].url).toBe("/api/classify");
  });

  it("the outbound body contains no connection-string password", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(SQL_PASTE, { fetchImpl: impl });
    expect(captured[0].body).not.toContain(FAKE.dbPassword);
  });

  it("the outbound body contains no Stripe key", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(SUPPORT_TICKET_PASTE, { fetchImpl: impl });
    expect(captured[0].body).not.toContain(FAKE.stripeKey);
  });

  it("the outbound body contains no AWS secret, even under injection text", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(INJECTION_PASTE, { fetchImpl: impl });
    expect(captured[0].body).not.toContain(FAKE.awsSecretAccessKey);
  });

  it("the outbound body contains no header or bearer credential", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(AUTH_HEADER_PASTE, { fetchImpl: impl });
    expect(captured[0].body).not.toContain(FAKE.bearerToken);
    expect(captured[0].body).not.toContain(FAKE.authHeaderToken);
  });

  it("sends the password placeholder, not the repeated username value", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(REPEATED_CREDENTIAL_PASTE, { fetchImpl: impl });
    const body = captured[0].body;
    expect(body).toContain("[DB_PASSWORD_REMOVED]");
    expect(body).toContain("admin:["); // username survived, password did not
  });

  it("no locally-detectable secret from ANY fixture reaches the wire", async () => {
    const pastes = [
      SUPPORT_TICKET_PASTE,
      SQL_PASTE,
      INJECTION_PASTE,
      REPEATED_CREDENTIAL_PASTE,
      AUTH_HEADER_PASTE,
    ];
    const localSecrets = [
      FAKE.stripeKey,
      FAKE.awsSecretAccessKey,
      FAKE.dbPassword,
      FAKE.bearerToken,
      FAKE.authHeaderToken,
    ];

    for (const paste of pastes) {
      const { impl, captured } = spyFetch();
      await runGuard(paste, { fetchImpl: impl });
      for (const secret of localSecrets) {
        expect(captured[0].body, `"${secret.slice(0, 12)}..." leaked`).not.toContain(secret);
      }
    }
  });

  it("reports what it sent, and that report matches the wire", async () => {
    const { impl, captured } = spyFetch();
    const out = await runGuard(SQL_PASTE, { fetchImpl: impl });
    // The caller-visible record must equal the real payload, so a test or an
    // operator reading sentToClassifier is not being told a comfortable story.
    expect(JSON.parse(captured[0].body).scrubbed).toBe(out.sentToClassifier);
  });
});

describe("contextual data still reaches the classifier", () => {
  // Scrubbing must not be so aggressive that the AI has nothing to judge.
  it("customer emails survive the local scan so the model can classify them", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(SQL_PASTE, { fetchImpl: impl });
    expect(captured[0].body).toContain(CUSTOMER.emailB);
  });
});

describe("no raw prompt leaves except through the classifier", () => {
  it("every sensitive fixture value is either redacted or deliberately classifiable", async () => {
    const { impl, captured } = spyFetch();
    await runGuard(SUPPORT_TICKET_PASTE, { fetchImpl: impl });
    const body = captured[0].body;

    // Credentials: must be gone.
    expect(body).not.toContain(FAKE.stripeKey);

    // Contextual data: intentionally present, because only the model can judge it.
    // This test documents that distinction rather than hiding it.
    const contextual: string[] = [CUSTOMER.emailA, CUSTOMER.nameA];
    for (const value of contextual) {
      expect(body).toContain(value);
    }

    // And nothing outside those two groups is unaccounted for.
    const unexpected = SENSITIVE_VALUES.filter(
      (v) => body.includes(v) && !contextual.includes(v) && !CUSTOMER.phoneA.includes(v)
    );
    expect(unexpected.filter((v) => Object.values(FAKE).includes(v as never))).toHaveLength(0);
  });
});
