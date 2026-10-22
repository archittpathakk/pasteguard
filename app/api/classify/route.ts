import { BadRequest, errorResponse, readJson, tooManyRequests } from "@/lib/http";
import { ClassifierUnavailable, getClassifier } from "@/lib/providers";
import { clientKey, rateLimit } from "@/lib/ratelimit";

// THE ONLY PLACE AN AI IS CALLED.
//
// What arrives here is ALREADY SCRUBBED - the browser removed every known
// secret format before this request was made. The AI never sees a raw key.
// Its job is the part a regex cannot do: deciding whether what is left is
// real customer data or harmless sample data, in context.
//
// This route spends money on every call, so it is rate limited and size
// capped. Without that it is an open proxy to a paid API key.

const LIMIT = 20;
const WINDOW_MS = 60_000;
const MAX_CHARS = 20_000;

export async function POST(req: Request) {
  const limit = rateLimit(`classify:${clientKey(req)}`, LIMIT, WINDOW_MS);
  if (!limit.allowed) return tooManyRequests(limit.retryAfterSeconds);

  let scrubbed: string;
  try {
    const body = await readJson(req);
    if (typeof body !== "object" || body === null) {
      throw new BadRequest("Expected an object.");
    }
    const value = (body as Record<string, unknown>).scrubbed;
    if (value !== undefined && typeof value !== "string") {
      throw new BadRequest("Field 'scrubbed' must be a string.");
    }
    scrubbed = typeof value === "string" ? value : "";
  } catch (err) {
    return errorResponse(err);
  }

  if (!scrubbed.trim()) {
    return Response.json({ findings: [] });
  }

  let classifier;
  try {
    classifier = getClassifier();
  } catch (err) {
    if (err instanceof ClassifierUnavailable) {
      // The actionable detail goes to the operator, via the log and
      // /api/health. A public endpoint should not hand out configuration
      // guidance about its own deployment.
      console.error("[classify] not configured:", err.message);
      return Response.json(
        { error: "The classifier is not configured. See /api/health." },
        { status: 503 }
      );
    }
    return errorResponse(err);
  }

  // Don't silently truncate past this: say so, and let the UI warn.
  const truncated = scrubbed.length > MAX_CHARS;
  const text = truncated ? scrubbed.slice(0, MAX_CHARS) : scrubbed;

  try {
    const findings = await classifier.classify(text);

    // Keep only findings whose text actually appears - a span we can't locate
    // can't be redacted, and reporting it would overstate what we removed.
    // The client validates again; both sides check, neither trusts the model.
    const usable = Array.isArray(findings)
      ? findings.filter((f) => f?.text && text.includes(f.text))
      : [];

    return Response.json({
      findings: usable,
      truncated,
      model: classifier.name,
      remaining: limit.remaining,
    });
  } catch (err) {
    // Log the failure reason for operators, but never the text we were given.
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error(`[classify] ${classifier.name} failed:`, message);

    // The client fails closed on any non-200; it does not need the detail.
    return Response.json(
      { error: "The classifier could not be reached." },
      { status: 502 }
    );
  }
}
