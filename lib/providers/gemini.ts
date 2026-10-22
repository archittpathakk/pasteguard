import { CLASSIFIER_SYSTEM } from "../policy";
import { CATEGORIES, SEVERITIES, type Classifier, type RawFinding } from "./types";

// Google Gemini, called over plain HTTPS - no SDK to install or keep in sync.
// Gemini's free tier covers the Flash models, which is plenty for a classifier.

const ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models";

// Gemini uses an OpenAPI-flavoured schema: uppercase type names.
const RESPONSE_SCHEMA = {
  type: "OBJECT",
  properties: {
    findings: {
      type: "ARRAY",
      items: {
        type: "OBJECT",
        properties: {
          text: { type: "STRING" },
          category: { type: "STRING", enum: [...CATEGORIES] },
          severity: { type: "STRING", enum: [...SEVERITIES] },
          confidence: { type: "NUMBER" },
          reason: { type: "STRING" },
        },
        required: ["text", "category", "severity", "confidence", "reason"],
      },
    },
  },
  required: ["findings"],
};

// The free tier is busy: models return 503 "high demand" or simply hang.
// A 503 means THAT model is swamped, so trying a different one beats retrying
// the same one. Each attempt is hard-capped so a hang can't stall the UI.
const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const ATTEMPT_TIMEOUT_MS = 7000;

// Measured on 22 Oct 2026: 3.1-flash-lite answered in ~3s while 3.8-flash was
// returning 503s and 30s hangs. Re-check if responses get slow.
const FALLBACK_MODELS = ["gemini-flash-lite-latest", "gemini-3.5-flash-lite"];

export function geminiClassifier(apiKey: string, model: string): Classifier {
  const chain = [model, ...FALLBACK_MODELS].filter(
    (m, i, all) => all.indexOf(m) === i
  );

  return {
    name: `gemini:${model}`,

    async classify(scrubbed: string): Promise<RawFinding[]> {
      const body = JSON.stringify({
        systemInstruction: { parts: [{ text: CLASSIFIER_SYSTEM }] },
        contents: [
          {
            role: "user",
            parts: [
              {
                text: `Check this text against the policy and return the findings.\n\n<text_to_check>\n${scrubbed}\n</text_to_check>`,
              },
            ],
          },
        ],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: RESPONSE_SCHEMA,
          temperature: 0, // same paste, same answer
        },
      });

      let lastError = "";

      for (const candidate of chain) {
        try {
          const res = await fetch(
            `${ENDPOINT}/${encodeURIComponent(candidate)}:generateContent`,
            {
              method: "POST",
              headers: {
                "content-type": "application/json",
                "x-goog-api-key": apiKey, // header, not the URL - keys don't belong in query strings
              },
              body,
              signal: AbortSignal.timeout(ATTEMPT_TIMEOUT_MS),
            }
          );

          if (res.ok) return await readFindings(res);

          const text = await res.text();
          lastError = `${candidate} returned ${res.status}: ${text.slice(0, 160)}`;

          // A 4xx that isn't rate limiting is our bug, not congestion.
          if (!RETRYABLE.has(res.status)) break;
        } catch (err) {
          // Timed out or the connection dropped - move on to the next model.
          lastError = `${candidate}: ${err instanceof Error ? err.message : "request failed"}`;
        }
      }

      throw new Error(`Gemini unavailable. Last error: ${lastError}`);
    },
  };
}

async function readFindings(res: Response): Promise<RawFinding[]> {
  const data = await res.json();

  // Gemini can decline to answer; that is a failure, not an empty result.
  const blocked = data?.promptFeedback?.blockReason;
  if (blocked) throw new Error(`Gemini blocked the request: ${blocked}`);

  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (typeof text !== "string") {
    throw new Error("Gemini returned no text to parse.");
  }

  const parsed = JSON.parse(text);
  return Array.isArray(parsed?.findings) ? parsed.findings : [];
}
