/**
 * Regulatory Clock: the demo's signature screen. Drop into CyberGRC-AI's React/Vite app.
 *
 *   <RegulatoryClock apiBase="/vartija" caseId={id} headers={authHeaders} />
 *
 * Polls GET {apiBase}/cases/{caseId}/clock every 15 s and ticks locally every second.
 * No dependencies beyond React. Style it to the challenge company's look at the event.
 */
import { useEffect, useState } from "react";

type Stage = {
  stage: string;
  label: string;
  due_at: string | null;
  seconds_remaining: number | null;
  completed_at: string | null;
  status: "running" | "due_soon" | "overdue" | "done" | "done_late" | "waiting" | "not_applicable";
};
type Regime = { regime: string; name: string; authority: string; applies: boolean | null; stages: Stage[] };
type Clock = {
  now: string;
  detected_at: string;
  undetermined: boolean;
  next_due: { regime: string; label: string; due_at: string; status: string } | null;
  regimes: Regime[];
};

const STATUS_COLOR: Record<Stage["status"], string> = {
  running: "#2f6fde",
  due_soon: "#c77700",
  overdue: "#c62828",
  done: "#2e7d32",
  done_late: "#8d6e00",
  waiting: "#7a7a7a",
  not_applicable: "#b0b0b0",
};

function fmt(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
}

export default function RegulatoryClock({
  apiBase,
  caseId,
  headers = {},
  pollMs = 15000,
}: {
  apiBase: string;
  caseId: string;
  headers?: Record<string, string>;
  pollMs?: number;
}) {
  const [clock, setClock] = useState<Clock | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const headerKey = JSON.stringify(headers);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await fetch(`${apiBase}/cases/${caseId}/clock`, { headers: JSON.parse(headerKey) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: Clock = await res.json();
        if (alive) {
          setClock(data);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(String(e));
      }
    };
    load();
    const poll = setInterval(load, pollMs);
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      alive = false;
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [apiBase, caseId, headerKey, pollMs]);

  // Count down from the server's due_at, not a local timer, so every screen agrees.
  const remaining = (dueAt: string | null) => (dueAt ? (Date.parse(dueAt) - now) / 1000 : null);
  const headline = clock?.next_due ? remaining(clock.next_due.due_at) : null;

  if (error && !clock) return <div role="alert">Clock unavailable: {error}</div>;
  if (!clock) return <div>Loading clock…</div>;

  const urgent = headline !== null && headline < 6 * 3600;
  return (
    <section aria-label="Regulatory clock" style={{ fontFamily: "system-ui, sans-serif", maxWidth: 720 }}>
      <div style={{ fontSize: 14, color: "#555" }}>
        {clock.next_due ? `${clock.next_due.label} · ${clock.next_due.regime.toUpperCase()}` : "No open reporting deadline"}
        {clock.undetermined && " · assessment pending, all in-scope clocks running"}
      </div>
      <div
        aria-live="polite"
        style={{
          fontSize: 72,
          fontWeight: 700,
          fontVariantNumeric: "tabular-nums",
          color: headline !== null && headline < 0 ? STATUS_COLOR.overdue : urgent ? STATUS_COLOR.due_soon : "#111",
        }}
      >
        {headline === null ? "--:--:--" : headline < 0 ? `-${fmt(-headline)}` : fmt(headline)}
      </div>
      <div style={{ fontSize: 13, color: "#777", marginBottom: 16 }}>
        Detected {new Date(clock.detected_at).toLocaleString()}
      </div>

      {clock.regimes.map((r) => (
        <div key={r.regime} style={{ borderTop: "1px solid #e5e5e5", padding: "12px 0", opacity: r.applies === false ? 0.45 : 1 }}>
          <div style={{ fontWeight: 600 }}>
            {r.name}{" "}
            <span style={{ fontWeight: 400, fontSize: 12, color: "#777" }}>
              {r.applies === null ? "may apply" : r.applies ? "applies" : "does not apply"} · {r.authority}
            </span>
          </div>
          <ol style={{ display: "flex", gap: 8, listStyle: "none", padding: 0, margin: "8px 0 0" }}>
            {r.stages.map((s) => {
              const left = s.status === "running" || s.status === "due_soon" || s.status === "overdue" ? remaining(s.due_at) : null;
              return (
                <li
                  key={s.stage}
                  style={{
                    flex: 1,
                    border: `2px solid ${STATUS_COLOR[s.status]}`,
                    borderRadius: 8,
                    padding: "6px 8px",
                    fontSize: 13,
                  }}
                >
                  <div>{s.label}</div>
                  <div style={{ fontVariantNumeric: "tabular-nums", color: STATUS_COLOR[s.status], fontWeight: 600 }}>
                    {left !== null ? (left < 0 ? `overdue ${fmt(-left)}` : fmt(left)) : s.status.replace("_", " ")}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      ))}
      {error && <div style={{ fontSize: 12, color: STATUS_COLOR.overdue }}>Last refresh failed: {error}</div>}
    </section>
  );
}
