# PasteGuard

Checks a prompt for secrets and customer data **before** it reaches a public AI tool.

---

## The job to be done

> When someone on my team pastes work into ChatGPT to get help, I want API keys and
> customer data stripped out before it is sent, so I can let people use AI without
> leaking things I can never un-leak.

**Who, specifically:** the solo IT or security owner at a 40-person company. No security
team, no budget for ChatGPT Enterprise, and a policy that staff already ignore. In their
own words: *"40 people, no security team, just me."*

They aren't trying to block AI. Blocking pushes people onto their personal laptops, where
nothing is visible at all. They want the paste to go through — just safely.

### The 3 tests this has to pass

| # | Test | Result |
|---|---|---|
| 1 | Paste a config with a live API key and a customer's contact details → within seconds, both are removed and a banner says what went | **PASS** (3.4s) |
| 2 | The admin sees that it happened, without the admin seeing the data itself | **PASS** — metadata only, verified by searching the admin store for all 16 sensitive values |
| 3 | Bad input: a paste that tries to talk the classifier out of doing its job → it is ignored, and the data is still caught | **PASS** (6.5s) |

Test 3 also covers the infrastructure case: if the classifier cannot be reached, local
redactions still apply, the banner says the text was **not** checked, and nothing is sent
automatically. A guard that goes quiet when its AI is down is worse than no guard, because
people keep trusting it.

---

## Current workflow → future workflow

**Today**, this work is a policy nobody reads and a discovery after the fact:

1. Announce a policy in a meeting.
2. Find out months later that staff bought ChatGPT licences without telling IT.
3. Escalate to leadership. Nothing happens.
4. Reach for a blunt control — block everything — which pushes people to personal devices.
5. Evaluate enterprise vendors alone, and find they cost more than the whole IT budget.

Nobody ever sees the pastes themselves. At a 40-person company the evidence suggests
roughly **750 sensitive pastes a week** that are invisible today.

**With PasteGuard**, steps 2, 3 and 4 disappear:

1. The admin writes the policy once, in plain language.
2. Every paste is scanned on the device before it is sent.
3. Anything sensitive is removed, and the user is told exactly what and why.
4. The user can still send — overrides are logged, not blocked.
5. The admin sees a running record of what was caught, without seeing the content.

The policy stays. The guesswork goes.

---

## Architecture

```
INPUT     Text typed or pasted into the composer
            │
            ▼
  [ LOCAL SCAN ]  ── regex, in the browser ──▶  secrets replaced with placeholders
            │                                    raw keys never touch the network
            ▼
AI        Classifier endpoint → Gemini (or Claude)
            │   receives ALREADY-SCRUBBED text
            │   returns JSON: span, category, severity, confidence, reason
            ▼
LOGIC     Fixed threshold rules (lib/decide.ts)
            │   high ≥ 0.70 → redact      medium ≥ 0.80 → redact
            │   below bar   → warn        classifier failed → never "allow"
            ▼
ACTION    Flagged spans removed from the text; the send is held for the user
            │
            ├──▶ OUTPUT  Banner: what was removed and why
            │            Safe version + Send / Edit / Send anyway
            │
            └──▶ OUTPUT  Admin event: category, action, count, hash
                         No prompt text, ever
```

### Where AI is used, and where it isn't

| Step | Who does it | Why |
|---|---|---|
| Write the policy | **Human** | A business decision the admin owns. |
| Detect known secrets | **Code** | API keys have fixed shapes. A regex catches them instantly, for free, and locally — so the raw secret never leaves the device. |
| Judge everything else | **AI** | Whether text is real customer data or harmless sample data depends on context. This is the one thing a pattern cannot do, and it is why rule-based tools generate the false positives reviewers complain about. |
| Decide the action | **Code** | Severity and confidence map to actions through fixed thresholds. It must be predictable and auditable — the same paste must behave the same way every time. |
| Final say on sending | **Human** | The user can always override. Blocking real work is how a tool gets uninstalled. |
| Act on an alert | **Human** | The admin decides what matters. |

The rule of thumb: **AI judges, code decides.** If an outcome needs to be explainable to
someone later, a human or a fixed rule owns it.

### Why these tools

- **Local regex first** — the only way to honestly claim secrets never leave the device.
  Everything the AI sees has already been scrubbed.
- **Gemini / Claude for the judgement call** — the classifier applies a policy written in
  plain English, which is exactly what a small IT team can maintain. The provider sits
  behind one interface (`lib/providers/`) and is chosen by an environment variable, so
  switching costs one line.
- **Next.js on Vercel** — one deployable app, and the API key lives on the server where
  the browser can never read it.
- **GitHub** — the policy is a file under version control, so every change to what counts
  as sensitive is reviewed and dated.

### Failure cases, and the human check for each

| What goes wrong | Why it matters | The check |
|---|---|---|
| **False positives** push users away | Over-blocking test data trains people to click "Send anyway" by reflex, or to switch to a personal device the guard can't see. | Overrides are logged. A rule with a high override rate is too strict and gets loosened. |
| **The classifier is fooled** | Pasted text may contain instructions aimed at the classifier, or data in an unusual shape. | The classifier is told the input is data, not instructions — verified by test 3. Spans it reports are checked against the real text before anything is removed. |
| **The guard becomes the leak** | If local scrubbing misses something, the guard itself ships it to a third party. | Admin events carry metadata only. This was a real bug: passwords inside connection strings bypassed the keyword-based scan, so credentials are now matched by position in URLs and headers too. |

**Known limits.** Scanning is pattern-based plus one model call, so an unusual encoding or
a secret split across two pastes can get through. File uploads and screenshots are not
scanned. The admin log is in memory and resets when the server restarts.

---

## Run it locally

Requires Node.js 20+ and a free Google AI Studio key.

```bash
git clone https://github.com/archittpathakk/pasteguard.git
cd pasteguard
npm install
cp .env.example .env.local
```

Open `.env.local` and paste your key after `GEMINI_API_KEY=`. Get one free at
[aistudio.google.com/apikey](https://aistudio.google.com/apikey).

```bash
npm run dev
```

Open <http://localhost:3000> and click **Load example paste**.

### Switching the AI provider

`.env.local` controls which model answers. Nothing else changes.

```bash
AI_PROVIDER=gemini      # default — free tier, no cost to run
AI_PROVIDER=anthropic   # Claude — set ANTHROPIC_API_KEY as well
```

Defaults are `gemini-3.1-flash-lite` and `claude-haiku-5-5`; override with `GEMINI_MODEL`
or `ANTHROPIC_MODEL`.

> **Note on the free tier:** Gemini's free models are shared and can be slow or briefly
> unavailable. The classifier tries three models in turn and caps each attempt at 7
> seconds. If all three fail it fails closed rather than pretending the text is clean.

**`.env.local` is gitignored and must never be committed.** `.env.example` holds the
variable names with no values.

---

## Scope

**Built:** local secret scanning, AI classification against a plain-language policy,
threshold-based actions, the user banner with override, and metadata-only admin events.

**Not built:** the Chrome extension that would intercept pastes on chatgpt.com — this app
is the guard engine behind it. Also out: file uploads, key rotation, the weekly digest,
and an admin dashboard.
