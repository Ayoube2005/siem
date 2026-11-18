import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { SeverityBadge, VerdictPill } from "../components/Badge";
import { apiGet } from "../lib/api";
import { useLiveStream } from "../lib/ws";
import type { Alert } from "../lib/types";

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [verdict, setVerdict] = useState("");
  const nav = useNavigate();

  const load = async () => {
    const data = await apiGet<Alert[]>("/api/alerts", {
      severity: severity || undefined,
      status: status || undefined,
      verdict: verdict || undefined,
      limit: 200,
    });
    setAlerts(data);
  };

  useEffect(() => { load().catch(() => {}); }, [severity, status, verdict]);

  useLiveStream((m) => {
    if (m.type === "alert") setAlerts((prev) => [{ ...m.data, _new: true }, ...prev]);
  });

  return (
    <Layout title="Alerts">
      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {["Critical", "High", "Medium", "Low", "Informational"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="closed">Closed</option>
          </select>
          <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="">All verdicts</option>
            <option value="unconfirmed">Unconfirmed</option>
            <option value="true_positive">True Positive</option>
            <option value="false_positive">False Positive</option>
          </select>
          <button className="btn ghost" onClick={() => load()}>Refresh</button>
          <span className="muted" style={{ marginLeft: "auto" }}>{alerts.length} alerts</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Severity</th><th>Risk</th><th>Rule</th><th>Title</th>
              <th>Source IP</th><th>Count</th><th>AI</th><th>Status</th><th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a: any) => (
              <tr key={a.id} className={a._new ? "flash" : ""} onClick={() => nav(`/alerts/${a.id}`)}>
                <td><SeverityBadge severity={a.severity} /></td>
                <td>{a.risk_score}</td>
                <td className="mono">{a.rule_id}</td>
                <td>{a.title}</td>
                <td className="mono">{a.source_ip ?? "—"}</td>
                <td>{a.event_count}</td>
                <td className="muted" style={{ fontSize: 12 }}>{a.ai_classification ?? "—"}</td>
                <td><span className="pill">{a.status}</span></td>
                <td><VerdictPill verdict={a.analyst_verdict} /></td>
              </tr>
            ))}
            {alerts.length === 0 && <tr><td colSpan={9} className="muted">No alerts match.</td></tr>}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
