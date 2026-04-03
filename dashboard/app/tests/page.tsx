"use client";

import { useState } from "react";

interface TestResult {
  module: string;
  status: "passed" | "failed" | "skipped";
  plan: string;
  apply: string;
  destroy: string;
  error?: string;
  duration?: string;
}

function parseTestOutput(raw: string): TestResult[] {
  // Parse terraform test JSON output or simple plan/apply logs
  const results: TestResult[] = [];

  try {
    const data = JSON.parse(raw);
    if (Array.isArray(data)) {
      return data as TestResult[];
    }
    if (data.modules) {
      return data.modules;
    }
  } catch {
    // Not JSON — try line-by-line parsing
  }

  // Simple text parsing: look for module names and pass/fail patterns
  const lines = raw.split("\n");
  let current: Partial<TestResult> | null = null;

  for (const line of lines) {
    const moduleMatch = line.match(/^(?:module|Module|=+)\s*[:\s]*(\S+)/);
    if (moduleMatch) {
      if (current?.module) results.push(current as TestResult);
      current = {
        module: moduleMatch[1],
        status: "passed",
        plan: "",
        apply: "",
        destroy: "",
      };
      continue;
    }
    if (line.includes("Error") || line.includes("FAIL")) {
      if (current) {
        current.status = "failed";
        current.error = line.trim();
      }
    }
  }
  if (current?.module) results.push(current as TestResult);

  return results;
}

export default function TestResultsPage() {
  const [results, setResults] = useState<TestResult[]>([]);
  const [rawInput, setRawInput] = useState("");

  function handleParse() {
    const parsed = parseTestOutput(rawInput);
    setResults(parsed);
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-4">Terraform Test Results</h1>

      <div className="mb-6">
        <p className="text-sm text-[var(--text-muted)] mb-2">
          Paste terraform test output or upload a JSON results file:
        </p>
        <textarea
          value={rawInput}
          onChange={(e) => setRawInput(e.target.value)}
          placeholder={`Paste terraform test output here, or JSON like:
[
  {"module": "networking", "status": "passed", "plan": "3 to add", "apply": "3 added", "destroy": "3 destroyed"},
  {"module": "compute", "status": "failed", "plan": "2 to add", "apply": "", "destroy": "", "error": "Error: AMI not found"}
]`}
          className="w-full h-40 bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 text-sm font-mono text-[var(--text)] resize-y focus:border-[var(--blue)] focus:outline-none"
        />
        <button
          onClick={handleParse}
          className="mt-2 px-4 py-2 bg-[var(--blue)] text-white text-sm rounded hover:bg-[var(--blue)]/80 transition-colors"
        >
          Parse Results
        </button>
      </div>

      {results.length > 0 && (
        <div className="space-y-3">
          {results.map((r, i) => (
            <div
              key={i}
              className={`rounded-lg border p-4 ${
                r.status === "passed"
                  ? "border-[var(--green)]/30 bg-[var(--green)]/5"
                  : r.status === "failed"
                  ? "border-[var(--red)]/30 bg-[var(--red)]/5"
                  : "border-[var(--border)] bg-[var(--card)]"
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-semibold text-sm">{r.module}</h3>
                <span
                  className={`text-xs font-medium px-2 py-0.5 rounded ${
                    r.status === "passed"
                      ? "bg-[var(--green)]/20 text-[var(--green)]"
                      : r.status === "failed"
                      ? "bg-[var(--red)]/20 text-[var(--red)]"
                      : "bg-[var(--text-muted)]/20 text-[var(--text-muted)]"
                  }`}
                >
                  {r.status.toUpperCase()}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs text-[var(--text-muted)]">
                <div>
                  <span className="font-medium">Plan:</span> {r.plan || "—"}
                </div>
                <div>
                  <span className="font-medium">Apply:</span> {r.apply || "—"}
                </div>
                <div>
                  <span className="font-medium">Destroy:</span>{" "}
                  {r.destroy || "—"}
                </div>
              </div>
              {r.error && (
                <pre className="mt-2 text-xs text-[var(--red)] bg-[var(--red)]/10 rounded p-2 overflow-x-auto">
                  {r.error}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}

      {results.length === 0 && rawInput && (
        <p className="text-sm text-[var(--text-muted)]">
          No test results parsed. Try pasting JSON or terraform output.
        </p>
      )}
    </div>
  );
}
