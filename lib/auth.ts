// Admin session handling.
//
// Scope, stated plainly: this is a single shared admin password, not a user
// system. There are no accounts, roles or organisations yet, so there is
// nothing to scope per-tenant. It exists to stop the admin event log being
// readable by anyone who knows the URL, which it currently is.
//
// The session is a signed, expiring token in an httpOnly cookie. The cookie
// carries no secret of its own: it carries an expiry and an HMAC over that
// expiry, so a client cannot extend its own session.

const COOKIE = "pg_admin";
const SESSION_MS = 8 * 60 * 60 * 1000; // 8 hours

export const SESSION_COOKIE = COOKIE;

export class AdminNotConfigured extends Error {}

function secret(): string {
  const s = process.env.ADMIN_PASSWORD;
  if (!s) {
    // Fail closed. An unset password must not mean "no password required".
    throw new AdminNotConfigured(
      "ADMIN_PASSWORD is not set, so the admin view is unavailable. Set it in .env.local (local) or in the host's environment settings (deployed), then restart or redeploy."
    );
  }
  return s;
}

async function sign(payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Length-independent comparison, so a wrong guess leaks no timing signal. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function checkPassword(candidate: unknown): Promise<boolean> {
  if (typeof candidate !== "string" || candidate.length === 0) return false;
  // Read the configured password first: if it is missing this throws before
  // any promise exists, rather than leaving a second rejection unhandled.
  const expected = secret();
  // Compare hashes rather than raw strings so lengths cannot differ.
  const [a, b] = await Promise.all([sign(candidate), sign(expected)]);
  return constantTimeEqual(a, b);
}

export async function createSessionToken(now = Date.now()): Promise<string> {
  const exp = String(now + SESSION_MS);
  return `${exp}.${await sign(exp)}`;
}

export async function verifySessionToken(
  token: string | undefined | null,
  now = Date.now()
): Promise<boolean> {
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0) return false;

  const exp = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  if (!/^\d+$/.test(exp) || !/^[0-9a-f]+$/.test(mac)) return false;

  // Signature first, so an attacker cannot learn anything from expiry alone.
  if (!constantTimeEqual(mac, await sign(exp))) return false;
  return Number(exp) > now;
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return undefined;
}

export async function isAuthenticated(req: Request): Promise<boolean> {
  return verifySessionToken(readCookie(req.headers.get("cookie"), COOKIE));
}

export function sessionCookie(token: string, secure: boolean): string {
  const attrs = [
    `${COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly", // unreadable from JavaScript, so XSS cannot exfiltrate it
    "SameSite=Lax", // not sent on cross-site POSTs
    `Max-Age=${Math.floor(SESSION_MS / 1000)}`,
  ];
  if (secure) attrs.push("Secure");
  return attrs.join("; ");
}

export function clearCookie(secure: boolean): string {
  const attrs = [`${COOKIE}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (secure) attrs.push("Secure");
  return attrs.join("; ");
}
