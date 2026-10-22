import Anthropic from "@anthropic-ai/sdk";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";
import { z } from "zod";
import { CLASSIFIER_SYSTEM } from "../policy";
import { CATEGORIES, SEVERITIES, type Classifier, type RawFinding } from "./types";

// Claude. Kept intact so switching back is AI_PROVIDER=anthropic and nothing else.

const ResultSchema = z.object({
  findings: z.array(
    z.object({
      text: z.string().describe("Exact substring from the input, copied verbatim"),
      category: z.enum(CATEGORIES),
      severity: z.enum(SEVERITIES),
      confidence: z.number().min(0).max(1),
      reason: z.string().describe("One short sentence a non-technical person understands"),
    })
  ),
});

export function anthropicClassifier(model: string): Classifier {
  return {
    name: `anthropic:${model}`,

    async classify(scrubbed: string): Promise<RawFinding[]> {
      const client = new Anthropic();
      const response = await client.messages.parse({
        model,
        max_tokens: 2000,
        system: CLASSIFIER_SYSTEM,
        messages: [
          {
            role: "user",
            content: `Check this text against the policy and return the findings.\n\n<text_to_check>\n${scrubbed}\n</text_to_check>`,
          },
        ],
        output_config: {
          effort: "low", // a classification, not a reasoning problem - keep it fast
          format: zodOutputFormat(ResultSchema),
        },
      });

      if (!response.parsed_output) {
        throw new Error("Claude returned an unreadable answer.");
      }
      return response.parsed_output.findings;
    },
  };
}
