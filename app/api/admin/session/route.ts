import {
  AdminNotConfigured,
  checkPassword,
  clearCookie,
  createSessionToken,
  isAuthenticated,
  sessionCookie,
} from "@/lib/auth";
import { BadRequest, errorResponse, isSecureRequest, readJson } from "@/lib/http";
import { clientKey, rateLimit } from "@/lib/ratelimit";

// Admin sign-in. Deliberately slow to brute force: five attempts per minute
// per client, and a single shared password that lives only on the server.

const ATTEMPTS = 5;
const WINDOW_MS = 60_000;

/** Is there a live session? Used by the UI to decide what to render. */
export async function GET(req: Request) {
  try {
    return Response.json({ authenticated: await isAuthenticated(req) });
  } catch (err) {
    if (err instanceof AdminNotConfigured) {
      return Response.json({ authenticated: false, configured: false });
    }
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  const limit = rateLimit(`login:${clientKey(req)}`, ATTEMPTS, WINDOW_MS);
  if (!limit.allowed) {
    return Response.json(
      { error: "Too many sign-in attempts. Wait a minute and try again." },
      { status: 429, headers: { "retry-after": String(limit.retryAfterSeconds) } }
    );
  }

  try {
    const body = await readJson(req);
    if (typeof body !== "object" || body === null) {
      throw new BadRequest("Expected an object.");
    }
    const password = (body as Record<string, unknown>).password;

    if (!(await checkPassword(password))) {
      // One message for both "no such password" and "wrong password".
      return Response.json({ error: "Incorrect password." }, { status: 401 });
    }

    const token = await createSessionToken();
    return Response.json(
      { authenticated: true },
      { headers: { "set-cookie": sessionCookie(token, isSecureRequest(req)) } }
    );
  } catch (err) {
    if (err instanceof AdminNotConfigured) {
      return Response.json({ error: err.message }, { status: 503 });
    }
    return errorResponse(err, "Could not sign in.");
  }
}

/** Sign out. */
export async function DELETE(req: Request) {
  return Response.json(
    { authenticated: false },
    { headers: { "set-cookie": clearCookie(isSecureRequest(req)) } }
  );
}
