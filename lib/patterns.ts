// Known secret formats. These are PLAIN CODE, not AI: an API key has a fixed
// shape, so a regex catches it instantly and for free. Running this in the
// browser is what keeps raw secrets off the network entirely.

export interface SecretPattern {
  name: string;
  /** Goes into the placeholder: AWS_KEY -> [AWS_KEY_REMOVED] */
  label: string;
  re: RegExp;
  /** Which capture group holds the secret itself. 0 = the whole match. */
  group?: number;
  reason: string;
}

// Order matters: more specific patterns first, so that a generic
// "token = ..." rule doesn't claim a span a precise rule would have matched.
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "private_key",
    label: "PRIVATE_KEY",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    reason: "Private key block",
  },
  {
    name: "aws_access_key_id",
    label: "AWS_KEY",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    reason: "AWS access key ID",
  },
  {
    name: "aws_secret_access_key",
    label: "AWS_SECRET",
    re: /(aws_secret_access_key\s*[=:]\s*["']?)([A-Za-z0-9/+=]{40})/gi,
    group: 2,
    reason: "AWS secret access key",
  },
  {
    name: "github_pat_fine_grained",
    label: "GITHUB_TOKEN",
    re: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
    reason: "GitHub fine-grained token",
  },
  {
    name: "github_token",
    label: "GITHUB_TOKEN",
    re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    reason: "GitHub personal access token",
  },
  {
    name: "anthropic_key",
    label: "ANTHROPIC_KEY",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    reason: "Anthropic API key",
  },
  {
    name: "stripe_key",
    label: "STRIPE_KEY",
    re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,99}\b/g,
    reason: "Stripe secret key",
  },
  {
    name: "openai_key",
    label: "OPENAI_KEY",
    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g,
    reason: "OpenAI API key",
  },
  {
    name: "google_api_key",
    label: "GOOGLE_KEY",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    reason: "Google API key",
  },
  {
    name: "slack_token",
    label: "SLACK_TOKEN",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    reason: "Slack token",
  },
  {
    name: "slack_webhook",
    label: "SLACK_WEBHOOK",
    re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/+]{20,}/g,
    reason: "Slack incoming webhook",
  },
  {
    name: "jwt",
    label: "JWT",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    reason: "JSON Web Token",
  },
  // Credentials identified by POSITION rather than by a preceding keyword.
  // The keyword rule below only fires on "password = x"; real pastes carry
  // secrets in URLs and headers, where nothing announces them.
  {
    name: "url_credentials",
    label: "DB_PASSWORD",
    // scheme://user:SECRET@host - the password sits between ":" and "@".
    re: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/g,
    group: 1,
    reason: "Password inside a connection string",
  },
  {
    name: "auth_header",
    label: "AUTH_TOKEN",
    re: /\bauthorization\s*:\s*(?:bearer|basic|token|apikey)\s+([A-Za-z0-9._~+/=-]{8,})/gi,
    group: 1,
    reason: "Credential in an Authorization header",
  },
  {
    name: "bearer_token",
    label: "BEARER_TOKEN",
    re: /\bbearer\s+([A-Za-z0-9._~+/=-]{16,})/gi,
    group: 1,
    reason: "Bearer token",
  },
  {
    name: "generic_assignment",
    label: "SECRET",
    re: /((?:api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*["']?)([^\s"'\n]{8,})/gi,
    group: 2,
    reason: "Value assigned to a secret-looking name",
  },
];
