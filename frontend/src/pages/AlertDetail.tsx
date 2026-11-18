import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Layout } from "../components/Layout";
import { SeverityBadge, VerdictPill } from "../components/Badge";
import { apiGet, apiSend } from "../lib/api";
import type { Alert, SecurityEvent } from "../lib/types";

interface Note { id: number; author: string; body: string; created_at: string; }

export default function AlertDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const a = await apiGet<Alert>(`/api/alerts/${id}`);
    setAlert(a);
    setNotes(await apiGet<Note[]>(`/api/alerts/${id}/notes`));
    if (a.source_ip) {
      setEvents(await apiGet<SecurityEvent[]>("/api/events", { source_ip: a.source_ip, limit: 50 }));
    }
  };

  useEffect(() => { load().catch(() => {}); }, [id]);

  const update = async (patch: Partial<Alert>) => {
    setBusy(true);
    try { setAlert(await apiSend<Alert>("PATCH", `/api/alerts/${id}`, patch)); }
    finally { setBusy(false); }
  };

  const rerunAI = async () => {
    setBusy(true);
    try { setAlert(await apiSend<Alert>("POST", `/api/alerts/${id}/triage`)); }
    finally { setBusy(false); }
  };

  const addNote = async () => {
    if (!note.trim()) return;
    await apiSend("POST", `/api/alerts/${id}/notes`, { body: note });
    setNote("");
    setNotes(await apiGet<Note[]>(`/api/alerts/${id}/notes`));
  };

  if (!alert) return <Layout title="Alert"><div className="muted">Loading…</div></Layout>;
  const ai = alert.ai_analysis;

  return (
    <Layout title={`Alert #${alert.id}`} right={<button className="btn ghost" onClick={() => nav(-1)}>← Back</button>}>
      <div className="grid" style={{ gridTemplateColumns: "1.4fr 1fr" }}>
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h3 style={{ margin: 0 }}>{alert.title}</h3>
            <SeverityBadge severity={alert.severity} />
          </div>
          <p className="muted">{alert.description}</p>
          <div className="kv" style={{ marginTop: 10 }}>
            <span className="k">Rule</span><span className="mono">{alert.rule_id} · {alert.rule_name}</span>
            <span className="k">Risk score</span><span>{alert.risk_score} / 100</span>
            <span className="k">Source IP</span><span className="mono">{alert.source_ip ?? "—"}</span>
            <span className="k">User</span><span className="mono">{alert.username ?? "—"}</span>
            <span className="k">Events folded</span><span>{alert.event_count}</span>
            <span className="k">First seen</span><span>{new Date(alert.first_seen).toLocaleString()}</span>
            <span className="k">Last seen</span><span>{new Date(alert.last_seen).toLocaleString()}</span>
            <span className="k">Status</span><span className="pill">{alert.status}</span>
            <span className="k">Verdict</span><span><VerdictPill verdict={alert.analyst_verdict} /></span>
          </div>

          <div className="section-title">Evidence</div>
          <pre className="mono" style={{ background: "#0b0f17", padding: 12, borderRadius: 8, overflowX: "auto" }}>
            {JSON.stringify(alert.evidence, null, 2)}
          </pre>

          <div className="section-title">Analyst actions</div>
          <div className="row">
            <button className="btn tp" disabled={busy} onClick={() => update({ analyst_verdict: "true_positive", status: "investigating" } as any)}>
              Confirm True Positive
            </button>
            <button className="btn fp" disabled={busy} onClick={() => update({ analyst_verdict: "false_positive", status: "closed" } as any)}>
              Mark False Positive
            </button>
            <select value={alert.status} disabled={busy} onChange={(e) => update({ status: e.target.value } as any)}>
              <option value="open">open</option>
              <option value="investigating">investigating</option>
              <option value="closed">closed</option>
            </select>
          </div>
        </div>

        <div>
          <div className="ai-box">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h3 style={{ margin: 0 }}>AI Triage Assist</h3>
              <button className="btn ghost" disabled={busy} onClick={rerunAI}>Re-run</button>
            </div>
            {ai ? (
              <>
                <div className="kv" style={{ marginTop: 10 }}>
                  <span className="k">Suggestion</span><span><b>{ai.classification}</b></span>
                  <span className="k">Confidence</span><span>{Math.round(ai.confidence * 100)}%</span>
                  <span className="k">Provider</span><span className="mono">{ai.provider}</span>
                </div>
                <p style={{ marginTop: 10 }}>{ai.explanation}</p>
                {ai.investigation_steps?.length > 0 && <>
                  <div className="section-title">Suggested investigation</div>
                  <ul className="tight">{ai.investigation_steps.map((s, i) => <li key={i}>{s}</li>)}</ul>
                </>}
                {ai.response_actions?.length > 0 && <>
                  <div className="section-title">Recommended response</div>
                  <ul className="tight">{ai.response_actions.map((s, i) => <li key={i}>{s}</li>)}</ul>
                </>}
                <div className="disclaimer">⚠ {ai.disclaimer}</div>
              </>
            ) : <p className="muted">No AI analysis yet.</p>}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>Investigation notes</h3>
            {notes.map((n) => (
              <div key={n.id} style={{ borderBottom: "1px solid var(--border)", padding: "6px 0" }}>
                <div className="muted" style={{ fontSize: 11 }}>{n.author} · {new Date(n.created_at).toLocaleString()}</div>
                <div>{n.body}</div>
              </div>
            ))}
            <div className="row" style={{ marginTop: 10 }}>
              <input style={{ flex: 1 }} placeholder="Add a note…" value={note}
                     onChange={(e) => setNote(e.target.value)} onKeyDown={(e) => e.key === "Enter" && addNote()} />
              <button className="btn" onClick={addNote}>Add</button>
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Related events — {alert.source_ip ?? "n/a"}</h3>
        <div className="stream">
          <table>
            <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Outcome</th><th>User</th><th>Message</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td>{e.source}</td><td>{e.event_type}</td><td>{e.outcome ?? "—"}</td>
                  <td className="mono">{e.username ?? "—"}</td>
                  <td className="muted" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.message}</td>
                </tr>
              ))}
              {events.length === 0 && <tr><td colSpan={6} className="muted">No correlated events.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
