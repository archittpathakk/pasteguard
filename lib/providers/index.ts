import { anthropicClassifier } from "./anthropic";
import { geminiClassifier } from "./gemini";
import type { Classifier } from "./types";

// Which AI answers is decided here, from environment variables only.
//
//   AI_PROVIDER=gemini     (default - has a free tier)
//   AI_PROVIDER=anthropic  (Claude - what the product ships with)
//
// Nothing else in the app knows or cares which one is in use.

// Verified against this key's own model list on 22 Oct 2026. gemini-2.5-flash
// is retired for new keys; gemini-3.8-flash exists but was returning 503s and
// 30s hangs on the free tier, while 3.1-flash-lite answered in ~3s.
const DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite";
const DEFAULT_ANTHROPIC_MODEL = "claude-haiku-5-5";

export class ClassifierUnavailable extends Error {}

export function getClassifier(): Classifier {
  const provider = (process.env.AI_PROVIDER ?? "gemini").toLowerCase().trim();

  if (provider === "anthropic" || provider === "claude") {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new ClassifierUnavailable(
        "AI_PROVIDER is anthropic but ANTHROPIC_API_KEY is not set in .env.local"
      );
    }
    return anthropicClassifier(
      process.env.ANTHROPIC_MODEL ?? DEFAULT_ANTHROPIC_MODEL
    );
  }

  if (provider === "gemini" || provider === "google") {
    const key = process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY;
    if (!key) {
      throw new ClassifierUnavailable(
        "AI_PROVIDER is gemini but GEMINI_API_KEY is not set in .env.local"
      );
    }
    return geminiClassifier(key, process.env.GEMINI_MODEL ?? DEFAULT_GEMINI_MODEL);
  }

  throw new ClassifierUnavailable(
    `Unknown AI_PROVIDER "${provider}". Use "gemini" or "anthropic".`
  );
}
