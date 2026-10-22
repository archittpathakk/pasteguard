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

/**
 * A missing key is the most common setup failure, and "not set" alone doesn't
 * say where to set it. This reports which variable NAMES the server can see -
 * never their values - and gives the fix for wherever it is running.
 */
function missingKeyMessage(varName: string): string {
  const visible = (
    [
      "AI_PROVIDER",
      "GEMINI_API_KEY",
      "GOOGLE_API_KEY",
      "ANTHROPIC_API_KEY",
    ] as const
  ).filter((name) => Boolean(process.env[name]));

  const where = process.env.VERCEL
    ? "On Vercel: Settings -> Environment Variables -> add it with the Production box ticked -> then Deployments -> Redeploy. Environment variables only reach a build created AFTER they were added, so adding one without redeploying changes nothing."
    : "Locally: add it to .env.local in the project root, then restart the dev server.";

  return `${varName} is not set. ${where} Variables the server can currently see: ${
    visible.length ? visible.join(", ") : "none of the expected ones"
  }.`;
}

export function getClassifier(): Classifier {
  const provider = (process.env.AI_PROVIDER ?? "gemini").toLowerCase().trim();

  if (provider === "anthropic" || provider === "claude") {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new ClassifierUnavailable(missingKeyMessage("ANTHROPIC_API_KEY"));
    }
    return anthropicClassifier(
      process.env.ANTHROPIC_MODEL ?? DEFAULT_ANTHROPIC_MODEL
    );
  }

  if (provider === "gemini" || provider === "google") {
    const key = process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY;
    if (!key) {
      throw new ClassifierUnavailable(missingKeyMessage("GEMINI_API_KEY"));
    }
    return geminiClassifier(key, process.env.GEMINI_MODEL ?? DEFAULT_GEMINI_MODEL);
  }

  throw new ClassifierUnavailable(
    `Unknown AI_PROVIDER "${provider}". Use "gemini" or "anthropic".`
  );
}
