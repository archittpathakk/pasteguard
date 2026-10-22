// Shared request validation for the API routes.

export const MAX_BODY_BYTES = 100_000; // ~100 KB; the composer caps well below this

export class BadRequest extends Error {
  constructor(
    message: string,
    readonly status = 400
  ) {
    super(message);
  }
}

/**
 * Read a JSON body with a hard size cap and a content-type check.
 *
 * The cap is enforced on the actual bytes read, not on a Content-Length
 * header, because that header is client-supplied and may be absent or lie.
 */
export async function readJson(req: Request): Promise<unknown> {
  const type = req.headers.get("content-type") ?? "";
  if (!type.toLowerCase().includes("application/json")) {
    throw new BadRequest("Content-Type must be application/json.", 415);
  }

  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    throw new BadRequest("Request body is too large.", 413);
  }

  const text = await req.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) {
    throw new BadRequest("Request body is too large.", 413);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new BadRequest("Body was not valid JSON.");
  }
}

/** A safe error response: a sentence the user can act on, no internals. */
export function errorResponse(err: unknown, fallback = "Request failed."): Response {
  if (err instanceof BadRequest) {
    return Response.json({ error: err.message }, { status: err.status });
  }
  return Response.json({ error: fallback }, { status: 500 });
}

export function tooManyRequests(retryAfterSeconds: number): Response {
  return Response.json(
    { error: "Too many requests. Please wait a moment and try again." },
    { status: 429, headers: { "retry-after": String(retryAfterSeconds) } }
  );
}

/** True when the request arrived over HTTPS, so cookies can be marked Secure. */
export function isSecureRequest(req: Request): boolean {
  if (req.headers.get("x-forwarded-proto") === "https") return true;
  try {
    return new URL(req.url).protocol === "https:";
  } catch {
    return false;
  }
}
