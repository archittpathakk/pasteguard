import { AdminNotConfigured, isAuthenticated } from "@/lib/auth";
import { BadRequest, errorResponse, readJson, tooManyRequests } from "@/lib/http";
import { clientKey, rateLimit } from "@/lib/ratelimit";
import { boundLimit, getStore } from "@/lib/store";
import type { AlertEvent, Action, Category } from "@/lib/types";

// The admin alert log. METADATA ONLY - no raw prompt text ever reaches here,
// so the guard itself cannot become the leak.
//
// Reads are authenticated; writes are not, because the writer is the browser
// and any secret shipped to the browser is not a secret. Writes are instead
// rate limited, size capped and strictly validated, and they can only ever
// append a fixed-shape metadata record.

const WRITE_LIMIT = 60;
const WRITE_WINDOW_MS = 60_000;

const ACTIONS: Action[] = ["allow", "redact", "warn", "block", "override"];
const CATEGORIES: Category[] = [
  "customer_data",
  "personal_data",
  "internal_doc",
  "secret",
];

/**
 * Build an event from untrusted input by copying only known fields with known
 * shapes. Anything else the caller sends is dropped - this is what stops a
 * crafted POST from smuggling prompt text into the admin log.
 */
function sanitize(body: unknown): AlertEvent {
  if (typeof body !== "object" || body === null) {
    throw new BadRequest("Expected an object.");
  }
  const b = body as Record<string, unknown>;

  const action = ACTIONS.includes(b.action as Action) ? (b.action as Action) : "allow";

  const categories = Array.isArray(b.categories)
    ? [...new Set(b.categories.filter((c): c is Category => CATEGORIES.includes(c as Category)))]
    : [];

  const counts: Record<string, number> = {};
  if (typeof b.counts === "object" && b.counts !== null) {
    for (const [k, v] of Object.entries(b.counts as Record<string, unknown>)) {
      if (!CATEGORIES.includes(k as Category)) continue;
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) continue;
      counts[k] = Math.min(Math.floor(v), 10_000);
    }
  }

  // A hash is 16 lowercase hex characters. Anything else is discarded rather
  // than stored, so this field cannot be used to carry arbitrary text.
  const hash =
    typeof b.hash === "string" && /^[0-9a-f]{16}$/.test(b.hash) ? b.hash : "";

  return {
    id: crypto.randomUUID(),
    at: new Date().toISOString(), // server time; a client cannot backdate an event
    action,
    categories,
    counts,
    hash,
    classifierFailed: b.classifierFailed === true,
  };
}

export async function POST(req: Request) {
  const limit = rateLimit(`alert:${clientKey(req)}`, WRITE_LIMIT, WRITE_WINDOW_MS);
  if (!limit.allowed) return tooManyRequests(limit.retryAfterSeconds);

  let event: AlertEvent;
  try {
    event = sanitize(await readJson(req));
  } catch (err) {
    return errorResponse(err, "Could not record the event.");
  }

  // Append-only: the store exposes no update or delete.
  //
  // A failed write is reported, not swallowed. The UI must never tell someone
  // their override was logged when it was not - that would make the audit
  // trail quietly incomplete, which is worse than visibly broken.
  const store = getStore();
  try {
    await store.append(event);
  } catch (err) {
    console.error("[alert] could not store event:", err instanceof Error ? err.message : err);
    return Response.json(
      {
        ok: false,
        stored: false,
        error: "The event could not be recorded. It is not in the audit log.",
      },
      { status: 503 }
    );
  }

  // Best-effort notification. The event is already stored, so a dead webhook
  // must not fail the request or block the user's send.
  const webhook = process.env.N8N_WEBHOOK_URL;
  if (webhook) {
    try {
      await fetch(webhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(event), // the sanitized event, never the raw body
        signal: AbortSignal.timeout(5000),
      });
    } catch (err) {
      console.error("[alert] webhook failed:", err instanceof Error ? err.message : err);
    }
  }

  return Response.json({ ok: true, stored: true, event });
}

export async function GET(req: Request) {
  try {
    if (!(await isAuthenticated(req))) {
      return Response.json(
        { error: "Sign in to view admin events." },
        { status: 401 }
      );
    }
  } catch (err) {
    if (err instanceof AdminNotConfigured) {
      return Response.json({ error: err.message }, { status: 503 });
    }
    return errorResponse(err);
  }

  const url = new URL(req.url);
  const limit = boundLimit(url.searchParams.get("limit"));
  const before = url.searchParams.get("before") ?? undefined;

  const store = getStore();
  try {
    const page = await store.list(limit, before);
    return Response.json({
      events: page.events,
      total: page.total,
      nextBefore: page.nextBefore,
      // The UI reads this and says so on screen, rather than letting the
      // absence of a warning imply persistence.
      durable: store.durable,
      store: store.name,
    });
  } catch (err) {
    console.error("[alert] could not read events:", err instanceof Error ? err.message : err);
    return Response.json({ error: "Could not read the event log." }, { status: 503 });
  }
}
