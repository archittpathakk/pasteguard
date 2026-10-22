import type { AlertEvent } from "@/lib/types";

// The admin alert. METADATA ONLY - no raw prompt text ever reaches here, so
// the guard itself can't become the leak. If N8N_WEBHOOK_URL is set we forward
// the same payload to n8n, which emails or Slacks the admin.

// In-memory ring buffer. Good enough for a demo; a real deployment writes to a
// database, since serverless instances are recycled and don't share memory.
const events: AlertEvent[] = [];
const MAX_EVENTS = 50;

export async function POST(req: Request) {
  let body: Partial<AlertEvent>;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Body was not valid JSON." }, { status: 400 });
  }

  const event: AlertEvent = {
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    action: body.action ?? "allow",
    categories: body.categories ?? [],
    counts: body.counts ?? {},
    hash: body.hash ?? "",
    classifierFailed: Boolean(body.classifierFailed),
  };

  events.unshift(event);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;

  const webhook = process.env.N8N_WEBHOOK_URL;
  if (webhook) {
    try {
      await fetch(webhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(event),
      });
    } catch (err) {
      // A dead webhook must not break the user's send.
      console.error("[alert] webhook failed:", err);
    }
  }

  return Response.json({ ok: true, event });
}

export async function GET() {
  return Response.json({ events });
}
