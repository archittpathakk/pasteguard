"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { scanAndScrub, applyRedactions, hashText } from "@/lib/scan";
import { decide } from "@/lib/decide";
import { CATEGORY_LABELS, type AlertEvent, type Decision, type Finding } from "@/lib/types";

const EXAMPLE_PASTE = `# staging .env - help me debug this
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DB_HOST=db.internal.acme.io

# failing orders
priya.sharma@acme-retail.com - order 4471 stuck in processing
m.okafor@northwind.co.uk - refund pending since Tuesday`;

type Status = "idle" | "checking" | "done";

interface GuardResult {
  decision: Decision;
  safeText: string;
}

export default function Home() {
  const [text, setText] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<GuardResult | null>(null);
  const [events, setEvents] = useState<AlertEvent[]>([]);
  const [sent, setSent] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const runId = useRef(0);

  const loadEvents = useCallback(async () => {
    try {
      const res = await fetch("/api/alert");
      const data = await res.json();
      setEvents(data.events ?? []);
    } catch {
      /* the admin panel is not worth breaking the page over */
    }
  }, []);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  // One path for every admin event, so an override is recorded the same way
  // a block is. Metadata only - never the text itself.
  const postAlert = useCallback(
    async (findings: Finding[], action: Decision["action"], source: string, failed: boolean) => {
      const counts: Record<string, number> = {};
      for (const f of findings) {
        counts[f.category] = (counts[f.category] ?? 0) + 1;
      }
      try {
        await fetch("/api/alert", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            action,
            categories: [...new Set(findings.map((f) => f.category))],
            counts,
            hash: hashText(source),
            classifierFailed: failed,
          }),
        });
        loadEvents();
      } catch {
        /* alerting must never block the user */
      }
    },
    [loadEvents]
  );

  const runGuard = useCallback(
    async (input: string) => {
      const id = ++runId.current;
      const started = performance.now();

      if (!input.trim()) {
        setResult(null);
        setStatus("idle");
        return;
      }

      setStatus("checking");
      setSent(null);

      // STEP 1 - local scan, in this browser. Secrets never leave the device.
      const { scrubbed, findings: localFindings } = scanAndScrub(input);

      // STEP 2 - ask Claude about what is left.
      let classified: Finding[] = [];
      let classifierFailed = false;
      try {
        const res = await fetch("/api/classify", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ scrubbed }),
        });
        if (!res.ok) throw new Error("classifier returned " + res.status);
        const data = await res.json();
        classified = (data.findings ?? []).map(
          (f: Omit<Finding, "source" | "label">) => ({
            ...f,
            source: "ai" as const,
            // Label from the category the classifier actually returned, so a
            // leaked credential can't be reported as personal data.
            label: CATEGORY_LABELS[f.category] ?? "SENSITIVE",
          })
        );
      } catch {
        classifierFailed = true; // fail closed - handled in decide()
      }

      if (id !== runId.current) return; // a newer keystroke won

      // STEP 3 - fixed rules turn findings into an action.
      const decision = decide(localFindings, classified, classifierFailed);
      const safeText = applyRedactions(scrubbed, decision.redactions);

      setResult({ decision, safeText });
      setStatus("done");
      setElapsed(Math.round(performance.now() - started));

      // STEP 4 - tell the admin. Metadata only.
      postAlert(decision.redactions, decision.action, input, classifierFailed);
    },
    [postAlert]
  );

  /**
   * The user overruling us. Logged deliberately: override rate per rule is how
   * you find the rules that are too strict, before people route around the tool.
   */
  function sendAnyway() {
    if (!result) return;
    setSent(text);
    postAlert(
      result.decision.redactions,
      "override",
      text,
      result.decision.classifierFailed
    );
  }

  function onChange(value: string) {
    setText(value);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => runGuard(value), 400);
  }

  const d = result?.decision;
  const tone =
    d?.classifierFailed || d?.action === "warn"
      ? "amber"
      : d?.action === "redact"
        ? "emerald"
        : "slate";

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-6xl px-6 py-8">
        <header className="mb-6 flex items-baseline justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">PasteGuard</h1>
            <p className="text-sm text-slate-400">
              Checks a prompt before it reaches a public AI tool.
            </p>
          </div>
          <button
            onClick={() => {
              setText(EXAMPLE_PASTE);
              runGuard(EXAMPLE_PASTE);
            }}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Load example paste
          </button>
        </header>

        <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
          {/* ---------------- composer ---------------- */}
          <section className="space-y-3">
            <label className="block text-xs font-medium uppercase tracking-wide text-slate-500">
              Your prompt
            </label>
            <textarea
              value={text}
              onChange={(e) => onChange(e.target.value)}
              placeholder="Paste something here, the way you would into ChatGPT..."
              spellCheck={false}
              className="h-56 w-full resize-y rounded-lg border border-slate-800 bg-slate-900 p-4 font-mono text-sm leading-relaxed outline-none transition focus:border-slate-600"
            />

            {status === "checking" && (
              <div className="flex items-center gap-2 text-sm text-slate-400">
                <span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />
                Scanning locally, then checking against the policy...
              </div>
            )}

            {d && result && status === "done" && (
              <div
                className={[
                  "rounded-lg border p-4",
                  tone === "emerald" ? "border-emerald-800 bg-emerald-950/40" : "",
                  tone === "amber" ? "border-amber-800 bg-amber-950/40" : "",
                  tone === "slate" ? "border-slate-800 bg-slate-900" : "",
                ]
                  .filter(Boolean)
                  .join(" ")}
              >
                <div className="flex items-start justify-between gap-3">
                  <p className="font-medium">{d.summary}</p>
                  {elapsed !== null && (
                    <span className="shrink-0 text-xs text-slate-500">
                      {elapsed} ms
                    </span>
                  )}
                </div>

                {d.redactions.length > 0 && (
                  <ul className="mt-3 space-y-1 text-sm text-slate-300">
                    {d.redactions.map((f, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-400">
                          {f.source}
                        </span>
                        <span>
                          {f.reason}
                          <span className="text-slate-500"> - removed</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}

                {d.warnings.length > 0 && (
                  <ul className="mt-3 space-y-1 text-sm text-amber-200">
                    {d.warnings.map((f, i) => (
                      <li key={i}>
                        Not sure about: {f.reason} (
                        {Math.round(f.confidence * 100)}% confident) - left in,
                        your call
                      </li>
                    ))}
                  </ul>
                )}

                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    onClick={() => setSent(result.safeText)}
                    className="rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-emerald-500"
                  >
                    Send safe version
                  </button>
                  <button
                    onClick={() => setText(result.safeText)}
                    className="rounded-md border border-slate-700 px-3 py-1.5 text-sm transition hover:bg-slate-800"
                  >
                    Edit
                  </button>
                  <button
                    onClick={sendAnyway}
                    className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-400 transition hover:bg-slate-800"
                  >
                    Send anyway
                  </button>
                </div>
              </div>
            )}

            {d && result && status === "done" && d.action !== "allow" && (
              <div>
                <label className="block text-xs font-medium uppercase tracking-wide text-slate-500">
                  Safe version
                </label>
                <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-900 p-4 font-mono text-sm text-slate-300">
                  {result.safeText}
                </pre>
              </div>
            )}

            {sent && (
              <div className="rounded-lg border border-sky-800 bg-sky-950/40 p-4">
                <p className="text-sm font-medium text-sky-200">
                  Sent to ChatGPT:
                </p>
                <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-xs text-slate-300">
                  {sent}
                </pre>
              </div>
            )}
          </section>

          {/* ---------------- admin ---------------- */}
          <section>
            <div className="mb-3 flex items-baseline justify-between">
              <h2 className="text-xs font-medium uppercase tracking-wide text-slate-500">
                Admin view
              </h2>
              <span className="text-xs text-slate-600">metadata only</span>
            </div>

            {events.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-800 p-4 text-sm text-slate-600">
                No events yet.
              </p>
            ) : (
              <ul className="space-y-2">
                {events.map((e) => (
                  <li
                    key={e.id}
                    className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={
                          e.action === "override"
                            ? "font-medium text-rose-400"
                            : e.classifierFailed
                              ? "font-medium text-amber-400"
                              : "font-medium text-emerald-400"
                        }
                      >
                        {e.action === "override"
                          ? "override - sent anyway"
                          : e.classifierFailed
                            ? "unverified"
                            : e.action}
                      </span>
                      <span className="font-mono text-xs text-slate-600">
                        {e.hash}
                      </span>
                    </div>
                    <p className="mt-1 text-slate-400">
                      {Object.entries(e.counts)
                        .map(([k, v]) => v + " " + k.replace(/_/g, " "))
                        .join(", ") || "nothing removed"}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-600">
                      {new Date(e.at).toLocaleTimeString()}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
