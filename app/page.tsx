"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { buildAlertPayload, runGuard } from "@/lib/guard";
import type { AlertEvent, Decision, Finding } from "@/lib/types";

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

interface AdminState {
  /** True when the server refused the read because nobody has signed in. */
  locked: boolean;
  events: AlertEvent[];
  /** The server tells us whether these events survive a restart. */
  durable: boolean;
  /** A configuration problem worth showing the operator. */
  problem?: string;
}

export default function Home() {
  const [text, setText] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<GuardResult | null>(null);
  const [admin, setAdmin] = useState<AdminState>({
    locked: false,
    events: [],
    durable: false,
  });
  const [password, setPassword] = useState("");
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const runId = useRef(0);

  // Fetching is separated from state so the mount effect can drop a result
  // that arrives after unmount, and so nothing calls setState in an effect body.
  // Reads are authenticated server-side. A 401 here is expected, not an error:
  // it means nobody has unlocked the admin view in this browser yet.
  const fetchEvents = useCallback(async (): Promise<AdminState> => {
    try {
      const res = await fetch("/api/alert");
      if (res.status === 401) return { locked: true, events: [], durable: false };
      if (res.status === 503) {
        const body = await res.json().catch(() => ({}));
        return { locked: true, events: [], durable: false, problem: body?.error };
      }
      if (!res.ok) return { locked: false, events: [], durable: false };
      const data = await res.json();
      return {
        locked: false,
        events: Array.isArray(data?.events) ? data.events : [],
        durable: data?.durable === true,
      };
    } catch {
      return { locked: false, events: [], durable: false };
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setAdmin(await fetchEvents());
  }, [fetchEvents]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const initial = await fetchEvents();
      if (!cancelled) setAdmin(initial);
    })();
    return () => {
      cancelled = true;
    };
  }, [fetchEvents]);

  async function unlockAdmin(e: React.FormEvent) {
    e.preventDefault();
    setUnlockError(null);
    const res = await fetch("/api/admin/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setUnlockError(body?.error ?? "Could not sign in.");
      return;
    }
    setPassword("");
    await loadEvents();
  }

  // One path for every admin event, so an override is recorded the same way
  // a block is. Metadata only - never the text itself.
  const postAlert = useCallback(
    async (findings: Finding[], action: Decision["action"], source: string, failed: boolean) => {
      try {
        const payload = await buildAlertPayload(findings, action, source, failed);
        await fetch("/api/alert", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        });
        await loadEvents();
      } catch {
        /* alerting must never block the user */
      }
    },
    [loadEvents]
  );

  const runCheck = useCallback(
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

      // Scan locally, classify the scrubbed text, then decide by rule.
      // The whole pipeline lives in lib/guard.ts so the tests exercise the
      // same code this page runs - see tests/pre-egress.test.ts.
      const out = await runGuard(input);

      if (id !== runId.current) return; // a newer keystroke won

      setResult({ decision: out.decision, safeText: out.safeText });
      setStatus("done");
      setElapsed(Math.round(performance.now() - started));

      // Tell the admin. Metadata only.
      void postAlert(
        out.decision.redactions,
        out.decision.action,
        input,
        out.classifierFailed
      );
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
    timer.current = setTimeout(() => runCheck(value), 400);
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
              runCheck(EXAMPLE_PASTE);
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

            {!admin.locked && !admin.durable && admin.events.length > 0 && (
              <p className="mb-2 rounded-md border border-amber-900/60 bg-amber-950/30 px-3 py-2 text-xs text-amber-300">
                Demo storage: these events are held in memory and are lost when
                the server restarts. Not an audit trail yet.
              </p>
            )}

            {admin.locked ? (
              <form
                onSubmit={unlockAdmin}
                className="space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
              >
                <p className="text-sm text-slate-400">
                  The event log is only readable after signing in. The server
                  refuses it otherwise &mdash; hiding the panel would not be
                  protection.
                </p>
                <label htmlFor="admin-password" className="sr-only">
                  Admin password
                </label>
                <input
                  id="admin-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Admin password"
                  autoComplete="current-password"
                  className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-slate-500"
                />
                <button
                  type="submit"
                  className="rounded-md bg-slate-700 px-3 py-1.5 text-sm font-medium transition hover:bg-slate-600"
                >
                  Unlock admin view
                </button>
                {(unlockError ?? admin.problem) && (
                  <p role="alert" className="text-sm text-amber-300">
                    {unlockError ?? admin.problem}
                  </p>
                )}
              </form>
            ) : admin.events.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-800 p-4 text-sm text-slate-600">
                No events yet.
              </p>
            ) : (
              <ul className="space-y-2">
                {admin.events.map((e) => (
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
