import { getClassifier, ClassifierUnavailable } from "@/lib/providers";

// THE ONLY PLACE AN AI IS CALLED.
//
// What arrives here is ALREADY SCRUBBED - the browser removed every known
// secret format before this request was made. The AI never sees a raw key.
// Its job is the part a regex cannot do: deciding whether what is left is
// real customer data or harmless sample data, in context.
//
// Which AI answers is set by AI_PROVIDER in .env.local. This file doesn't know.

const MAX_CHARS = 20000;

export async function POST(req: Request) {
  let scrubbed: string;
  try {
    const body = await req.json();
    scrubbed = typeof body?.scrubbed === "string" ? body.scrubbed : "";
  } catch {
    return Response.json({ error: "Body was not valid JSON." }, { status: 400 });
  }

  if (!scrubbed.trim()) {
    return Response.json({ findings: [] });
  }

  let classifier;
  try {
    classifier = getClassifier();
  } catch (err) {
    if (err instanceof ClassifierUnavailable) {
      return Response.json({ error: err.message }, { status: 503 });
    }
    throw err;
  }

  // Don't silently truncate past this: say so, and let the UI warn.
  const truncated = scrubbed.length > MAX_CHARS;
  const text = truncated ? scrubbed.slice(0, MAX_CHARS) : scrubbed;

  try {
    const findings = await classifier.classify(text);

    // Keep only findings whose text actually appears - a span we can't locate
    // can't be redacted, and reporting it would overstate what we removed.
    const usable = findings.filter((f) => f?.text && text.includes(f.text));

    return Response.json({ findings: usable, truncated, model: classifier.name });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error(`[classify] ${classifier.name} failed:`, message);
    return Response.json({ error: message }, { status: 502 });
  }
}
