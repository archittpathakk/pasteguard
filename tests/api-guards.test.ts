import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GET as alertGet, POST as alertPost } from "@/app/api/alert/route";
import { POST as classifyPost } from "@/app/api/classify/route";
import { createSessionToken, SESSION_COOKIE } from "@/lib/auth";
import { MAX_BODY_BYTES } from "@/lib/http";
import { resetRateLimits } from "@/lib/ratelimit";
import { CUSTOMER, FAKE, SQL_PASTE } from "./fixtures";

const PASSWORD = "test-admin-password";

function post(url: string, body: unknown, headers: Record<string, string> = {}) {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

beforeEach(() => {
  resetRateLimits();
  process.env.ADMIN_PASSWORD = PASSWORD;
  delete process.env.GEMINI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
});
afterEach(() => {
  delete process.env.ADMIN_PASSWORD;
});

describe("admin event reads are authorized", () => {
  it("refuses an anonymous read with 401", async () => {
    const res = await alertGet(new Request("https://x.test/api/alert"));
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.events).toBeUndefined();
  });

  it("refuses a read with a forged cookie", async () => {
    const res = await alertGet(
      new Request("https://x.test/api/alert", {
        headers: { cookie: `${SESSION_COOKIE}=9999999999999.deadbeef` },
      })
    );
    expect(res.status).toBe(401);
  });

  it("allows a read with a valid session", async () => {
    const token = await createSessionToken();
    const res = await alertGet(
      new Request("https://x.test/api/alert", {
        headers: { cookie: `${SESSION_COOKIE}=${token}` },
      })
    );
    expect(res.status).toBe(200);
    expect(Array.isArray((await res.json()).events)).toBe(true);
  });

  it("fails closed when no admin password is configured", async () => {
    // An unset password must never mean "no password required". An anonymous
    // caller is refused before the config is even consulted, so this also
    // avoids telling an attacker whether admin auth is set up at all.
    delete process.env.ADMIN_PASSWORD;
    const res = await alertGet(new Request("https://x.test/api/alert"));
    expect(res.status).toBe(401);
    expect((await res.json()).events).toBeUndefined();
  });

  it("refuses a previously valid session once the password is removed", async () => {
    const token = await createSessionToken();
    delete process.env.ADMIN_PASSWORD;
    const res = await alertGet(
      new Request("https://x.test/api/alert", {
        headers: { cookie: `${SESSION_COOKIE}=${token}` },
      })
    );
    expect(res.status).toBe(503);
    expect((await res.json()).events).toBeUndefined();
  });

  it("does not claim the in-memory store is durable", async () => {
    const token = await createSessionToken();
    const res = await alertGet(
      new Request("https://x.test/api/alert", {
        headers: { cookie: `${SESSION_COOKIE}=${token}` },
      })
    );
    expect((await res.json()).durable).toBe(false);
  });
});

describe("admin event writes are sanitized", () => {
  it("drops unknown fields a caller tries to smuggle in", async () => {
    const res = await alertPost(
      post("https://x.test/api/alert", {
        action: "redact",
        categories: ["secret"],
        counts: { secret: 1 },
        hash: "0123456789abcdef",
        promptText: SQL_PASTE, // not a permitted field
        note: CUSTOMER.emailA,
      })
    );
    const { event } = await res.json();
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain("SELECT");
    expect(serialized).not.toContain(CUSTOMER.emailA);
    expect(serialized).not.toContain(FAKE.dbPassword);
    expect(event.promptText).toBeUndefined();
    expect(event.note).toBeUndefined();
  });

  it("rejects a hash that is not 16 hex characters", async () => {
    const res = await alertPost(
      post("https://x.test/api/alert", { action: "allow", hash: CUSTOMER.emailA })
    );
    expect((await res.json()).event.hash).toBe("");
  });

  it("rejects unknown actions and categories", async () => {
    const res = await alertPost(
      post("https://x.test/api/alert", {
        action: "exfiltrate",
        categories: ["secret", "something_else"],
        counts: { secret: 2, made_up: 9 },
      })
    );
    const { event } = await res.json();
    expect(event.action).toBe("allow");
    expect(event.categories).toEqual(["secret"]);
    expect(event.counts).toEqual({ secret: 2 });
  });

  it("stamps server time, so a client cannot backdate an event", async () => {
    const res = await alertPost(
      post("https://x.test/api/alert", { action: "allow", at: "1999-01-01T00:00:00.000Z" })
    );
    expect((await res.json()).event.at).not.toContain("1999");
  });

  it("rejects a non-JSON content type", async () => {
    const res = await alertPost(
      new Request("https://x.test/api/alert", {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "hello",
      })
    );
    expect(res.status).toBe(415);
  });
});

describe("classify is not an open proxy", () => {
  it("rate limits after the configured number of calls", async () => {
    let last = 0;
    for (let i = 0; i < 25; i++) {
      const res = await classifyPost(post("https://x.test/api/classify", { scrubbed: "hello" }));
      last = res.status;
    }
    expect(last).toBe(429);
  });

  it("returns retry-after when limited", async () => {
    for (let i = 0; i < 21; i++) {
      await classifyPost(post("https://x.test/api/classify", { scrubbed: "hi" }));
    }
    const res = await classifyPost(post("https://x.test/api/classify", { scrubbed: "hi" }));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBeTruthy();
  });

  it("counts each client separately", async () => {
    for (let i = 0; i < 21; i++) {
      await classifyPost(
        post("https://x.test/api/classify", { scrubbed: "hi" }, { "x-forwarded-for": "1.1.1.1" })
      );
    }
    const other = await classifyPost(
      post("https://x.test/api/classify", { scrubbed: "hi" }, { "x-forwarded-for": "2.2.2.2" })
    );
    expect(other.status).not.toBe(429);
  });

  it("rejects an oversized body", async () => {
    const huge = JSON.stringify({ scrubbed: "x".repeat(MAX_BODY_BYTES + 10) });
    const res = await classifyPost(post("https://x.test/api/classify", huge));
    expect(res.status).toBe(413);
  });

  it("rejects a non-JSON content type", async () => {
    const res = await classifyPost(
      new Request("https://x.test/api/classify", {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "scrubbed=hello",
      })
    );
    expect(res.status).toBe(415);
  });

  it("rejects a wrong type for scrubbed", async () => {
    const res = await classifyPost(post("https://x.test/api/classify", { scrubbed: { a: 1 } }));
    expect(res.status).toBe(400);
  });

  it("short-circuits empty input without calling a provider", async () => {
    const res = await classifyPost(post("https://x.test/api/classify", { scrubbed: "   " }));
    expect(res.status).toBe(200);
    expect((await res.json()).findings).toEqual([]);
  });

  it("returns 503, not 500, when no provider key is configured", async () => {
    const res = await classifyPost(post("https://x.test/api/classify", { scrubbed: "real text" }));
    expect(res.status).toBe(503);
  });

  it("never echoes the submitted text back in an error", async () => {
    const res = await classifyPost(post("https://x.test/api/classify", { scrubbed: SQL_PASTE }));
    const body = JSON.stringify(await res.json());
    expect(body).not.toContain(CUSTOMER.emailB);
    expect(body).not.toContain("SELECT");
  });
});

describe("health endpoint reports status without leaking values", () => {
  it("never contains a configured secret value", async () => {
    process.env.GEMINI_API_KEY = "AIza-this-is-a-fake-key-value-000000";
    process.env.ADMIN_PASSWORD = "a-very-distinctive-password";
    try {
      const { buildHealth } = await import("@/lib/health");
      const body = JSON.stringify(buildHealth());
      expect(body).not.toContain("AIza-this-is-a-fake-key-value-000000");
      expect(body).not.toContain("a-very-distinctive-password");
      // It reports THAT they are configured, not WHAT they are.
      expect(body).toContain("configured");
    } finally {
      delete process.env.GEMINI_API_KEY;
    }
  });

  it("reports degraded, not ok, when the classifier is unconfigured", async () => {
    delete process.env.GEMINI_API_KEY;
    delete process.env.GOOGLE_API_KEY;
    const { buildHealth } = await import("@/lib/health");
    const body = buildHealth();
    expect(body.ok).toBe(false);
    expect(body.status).toBe("degraded");
  });
});
