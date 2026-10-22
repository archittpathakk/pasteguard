import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AdminNotConfigured,
  SESSION_COOKIE,
  checkPassword,
  clearCookie,
  createSessionToken,
  isAuthenticated,
  sessionCookie,
  verifySessionToken,
} from "@/lib/auth";

const PASSWORD = "correct-horse-battery-staple";

beforeEach(() => {
  process.env.ADMIN_PASSWORD = PASSWORD;
});
afterEach(() => {
  delete process.env.ADMIN_PASSWORD;
});

function requestWithCookie(value: string | null): Request {
  return new Request("https://example.test/api/alert", {
    headers: value === null ? {} : { cookie: `${SESSION_COOKIE}=${encodeURIComponent(value)}` },
  });
}

describe("password check", () => {
  it("accepts the configured password", async () => {
    expect(await checkPassword(PASSWORD)).toBe(true);
  });

  it("rejects a wrong password", async () => {
    expect(await checkPassword("hunter2")).toBe(false);
  });

  it("rejects a password that is a prefix of the real one", async () => {
    expect(await checkPassword(PASSWORD.slice(0, -1))).toBe(false);
  });

  it("rejects non-strings and empty values", async () => {
    expect(await checkPassword(undefined)).toBe(false);
    expect(await checkPassword(null)).toBe(false);
    expect(await checkPassword("")).toBe(false);
    expect(await checkPassword(123)).toBe(false);
    expect(await checkPassword({ toString: () => PASSWORD })).toBe(false);
  });

  it("fails closed when no password is configured", async () => {
    delete process.env.ADMIN_PASSWORD;
    await expect(checkPassword("anything")).rejects.toBeInstanceOf(AdminNotConfigured);
  });
});

describe("session tokens", () => {
  it("accepts a token it just issued", async () => {
    expect(await verifySessionToken(await createSessionToken())).toBe(true);
  });

  it("rejects a token whose expiry has been edited", async () => {
    const token = await createSessionToken();
    const [, mac] = token.split(".");
    const forged = `${Date.now() + 999_999_999}.${mac}`;
    expect(await verifySessionToken(forged)).toBe(false);
  });

  it("rejects a token with a tampered signature", async () => {
    const token = await createSessionToken();
    const [exp, mac] = token.split(".");
    const flipped = mac[0] === "a" ? "b" : "a";
    expect(await verifySessionToken(`${exp}.${flipped}${mac.slice(1)}`)).toBe(false);
  });

  it("rejects an expired token", async () => {
    const issued = await createSessionToken(0);
    expect(await verifySessionToken(issued, 0)).toBe(true);
    expect(await verifySessionToken(issued, 9 * 60 * 60 * 1000)).toBe(false);
  });

  it("rejects malformed tokens", async () => {
    for (const bad of ["", "abc", ".", "123.", ".abc", "notanumber.deadbeef", "123.ZZZZ"]) {
      expect(await verifySessionToken(bad), bad).toBe(false);
    }
    expect(await verifySessionToken(undefined)).toBe(false);
    expect(await verifySessionToken(null)).toBe(false);
  });

  it("rejects a token signed with a different password", async () => {
    const token = await createSessionToken();
    process.env.ADMIN_PASSWORD = "a-different-password";
    expect(await verifySessionToken(token)).toBe(false);
  });
});

describe("request authentication", () => {
  it("rejects a request with no cookie", async () => {
    expect(await isAuthenticated(requestWithCookie(null))).toBe(false);
  });

  it("rejects a request with a junk cookie", async () => {
    expect(await isAuthenticated(requestWithCookie("not-a-token"))).toBe(false);
  });

  it("accepts a request carrying a valid token", async () => {
    expect(await isAuthenticated(requestWithCookie(await createSessionToken()))).toBe(true);
  });

  it("ignores other cookies on the request", async () => {
    const token = await createSessionToken();
    const req = new Request("https://example.test/", {
      headers: { cookie: `theme=dark; ${SESSION_COOKIE}=${token}; other=1` },
    });
    expect(await isAuthenticated(req)).toBe(true);
  });
});

describe("cookie attributes", () => {
  it("is httpOnly and SameSite, and Secure over https", () => {
    const c = sessionCookie("t", true);
    expect(c).toContain("HttpOnly");
    expect(c).toContain("SameSite=Lax");
    expect(c).toContain("Secure");
  });

  it("omits Secure on plain http so local development works", () => {
    expect(sessionCookie("t", false)).not.toContain("Secure");
  });

  it("clearing expires the cookie immediately", () => {
    expect(clearCookie(false)).toContain("Max-Age=0");
  });
});
