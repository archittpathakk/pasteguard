import { describe, expect, it } from "vitest";
import { scanAndScrub } from "@/lib/scan";
import { SECRET_PATTERNS } from "@/lib/patterns";
import {
  AUTH_HEADER_PASTE,
  CLEAN_PROSE,
  FAKE,
  REPEATED_CREDENTIAL_PASTE,
  SAFE_CONTACT,
  SQL_PASTE,
  SUPPORT_TICKET_PASTE,
} from "./fixtures";

describe("local secret scanning", () => {
  it("defines a pattern for every documented family", () => {
    // The briefing said 13; the implementation carries 16. This test pins the
    // real number so a silent deletion is caught.
    expect(SECRET_PATTERNS).toHaveLength(16);
    const names = SECRET_PATTERNS.map((p) => p.name);
    expect(new Set(names).size).toBe(names.length); // no duplicate names
  });

  // ---- positive coverage, one case per family ----

  const positives: Array<[string, string, string]> = [
    ["aws_access_key_id", `AWS_ACCESS_KEY_ID=${FAKE.awsAccessKeyId}`, FAKE.awsAccessKeyId],
    [
      "aws_secret_access_key",
      `aws_secret_access_key=${FAKE.awsSecretAccessKey}`,
      FAKE.awsSecretAccessKey,
    ],
    ["github_token", `token: ${FAKE.githubToken}`, FAKE.githubToken],
    ["github_pat_fine_grained", `use ${FAKE.githubFineGrained} here`, FAKE.githubFineGrained],
    ["stripe_key", `STRIPE_SECRET=${FAKE.stripeKey}`, FAKE.stripeKey],
    ["openai_key", `OPENAI=${FAKE.openaiKey}`, FAKE.openaiKey],
    ["anthropic_key", `ANTHROPIC=${FAKE.anthropicKey}`, FAKE.anthropicKey],
    ["google_api_key", `key ${FAKE.googleKey} here`, FAKE.googleKey],
    ["slack_token", `slack ${FAKE.slackToken}`, FAKE.slackToken],
    ["slack_webhook", `post to ${FAKE.slackWebhook}`, FAKE.slackWebhook],
    ["jwt", `bearerless jwt ${FAKE.jwt}`, FAKE.jwt],
    ["private_key", FAKE.privateKey, "MIIEowIBAAKCAQEAfakefakefake"],
    [
      "url_credentials",
      `postgres://app_rw:${FAKE.dbPassword}@db-prod.internal:5432/billing`,
      FAKE.dbPassword,
    ],
    [
      "auth_header",
      `Authorization: Basic ${FAKE.authHeaderToken}`,
      FAKE.authHeaderToken,
    ],
    ["bearer_token", `Bearer ${FAKE.bearerToken}`, FAKE.bearerToken],
    ["generic_assignment", `password = ${FAKE.genericSecret}`, FAKE.genericSecret],
  ];

  it.each(positives)("catches %s", (_name, input, secret) => {
    const { scrubbed, findings } = scanAndScrub(input);
    expect(scrubbed).not.toContain(secret);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.source === "local")).toBe(true);
    expect(findings.every((f) => f.confidence === 1)).toBe(true);
  });

  // ---- negative coverage: these must NOT fire ----

  it("does not flag prose that merely mentions secret-ish words", () => {
    const { scrubbed, findings } = scanAndScrub(CLEAN_PROSE);
    expect(findings).toHaveLength(0);
    expect(scrubbed).toBe(CLEAN_PROSE);
  });

  it("leaves a public support address alone", () => {
    const { scrubbed } = scanAndScrub(SUPPORT_TICKET_PASTE);
    expect(scrubbed).toContain(SAFE_CONTACT.supportEmail);
  });

  it("returns input unchanged when there is nothing to find", () => {
    const text = "SELECT id, created_at FROM orders WHERE status = 'open';";
    const { scrubbed, findings } = scanAndScrub(text);
    expect(scrubbed).toBe(text);
    expect(findings).toHaveLength(0);
  });

  it("handles empty input without throwing", () => {
    expect(scanAndScrub("")).toEqual({ scrubbed: "", findings: [] });
  });
});

describe("connection string regression", () => {
  // The defect that broke the pre-egress claim: a password with no preceding
  // keyword was shipped to the classifier verbatim.
  it("redacts a password inside a postgres:// connection string", () => {
    const { scrubbed } = scanAndScrub(SQL_PASTE);
    expect(scrubbed).not.toContain(FAKE.dbPassword);
    expect(scrubbed).toContain("[DB_PASSWORD_REMOVED]");
  });

  it("keeps the surrounding connection string readable", () => {
    const { scrubbed } = scanAndScrub(SQL_PASTE);
    expect(scrubbed).toContain("postgres://app_rw:[DB_PASSWORD_REMOVED]@db-prod.internal:5432/billing");
  });

  it("redacts a mongodb+srv:// password too", () => {
    const { scrubbed } = scanAndScrub(
      "mongodb+srv://svc:S3cretValue99@cluster0.mongodb.net/prod"
    );
    expect(scrubbed).not.toContain("S3cretValue99");
  });
});

describe("repeated value regression", () => {
  // Searching the match text for the captured value found the FIRST copy -
  // the username - and left the password in place. Exact match indices fixed it.
  it("removes the password, not the identical username", () => {
    const { scrubbed } = scanAndScrub(REPEATED_CREDENTIAL_PASTE);
    expect(scrubbed).toBe(
      "mongodb+srv://admin:[DB_PASSWORD_REMOVED]@cluster0.mongodb.net/prod"
    );
  });

  it("places the redaction at the password offset, not the username offset", () => {
    const { scrubbed } = scanAndScrub(REPEATED_CREDENTIAL_PASTE);
    const marker = scrubbed.indexOf("[DB_PASSWORD_REMOVED]");
    // "mongodb+srv://admin:" is 20 characters; the password starts there.
    expect(marker).toBe(20);
    expect(scrubbed.slice(14, 19)).toBe("admin"); // username still intact
  });
});

describe("authorization header regression", () => {
  it("catches both bearer and basic credentials in headers", () => {
    const { scrubbed } = scanAndScrub(AUTH_HEADER_PASTE);
    expect(scrubbed).not.toContain(FAKE.bearerToken);
    expect(scrubbed).not.toContain(FAKE.authHeaderToken);
  });

  it("does not fire on the word bearer in prose", () => {
    const { findings } = scanAndScrub("The bearer of this note may enter.");
    expect(findings).toHaveLength(0);
  });
});

describe("overlapping findings", () => {
  it("does not double-redact a value two patterns both match", () => {
    // "password=AKIA..." matches both generic_assignment and aws_access_key_id.
    const { scrubbed, findings } = scanAndScrub(`password=${FAKE.awsAccessKeyId}`);
    expect(scrubbed).not.toContain(FAKE.awsAccessKeyId);
    expect(findings).toHaveLength(1);
    expect(scrubbed.match(/\[/g) ?? []).toHaveLength(1);
  });

  it("is deterministic across repeated runs", () => {
    const a = scanAndScrub(SQL_PASTE).scrubbed;
    const b = scanAndScrub(SQL_PASTE).scrubbed;
    const c = scanAndScrub(SQL_PASTE).scrubbed;
    expect(a).toBe(b);
    expect(b).toBe(c);
  });
});
