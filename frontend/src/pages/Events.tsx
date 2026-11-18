import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { SeverityBadge } from "../components/Badge";
import { apiGet } from "../lib/api";
import { useLiveStream } from "../lib/ws";
import type { SecurityEvent } from "../lib/types";

export default function Events() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [q, setQ] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");
  const [outcome, setOutcome] = useState("");
  const [live, setLive] = useState(true);

  const load = async () => {
    const data = await apiGet<SecurityEvent[]>("/api/events", {
      q: q || undefined, source: source || undefined,
      severity: severity || undefined, outcome: outcome || undefined, limit: 300,
    });
    setEvents(data);
  };

  useEffect(() => { load().catch(() => {}); }, [q, source, severity, outcome]);

  useLiveStream((m) => {
    if (live && m.type === "event") setEvents((prev) => [{ ...m.data, _new: true }, ...prev].slice(0, 300));
  });

  return (
    <Layout title="Event Search">
      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <input placeholder="Search message…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 220 }} />
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">All sources</option>
            {["windows", "linux", "syslog", "firewall", "web", "custom"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {["Critical", "High", "Medium", "Low", "Informational"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">Any outcome</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
          </select>
          <label className="row" style={{ gap: 6 }}>
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live
          </label>
          <span className="muted" style={{ marginLeft: "auto" }}>{events.length} events</span>
        </div>
        <table>
          <thead>
            <tr><th>Time</th><th>Sev</th><th>Source</th><th>Type</th><th>Outcome</th><th>Source IP</th><th>User</th><th>Message</th></tr>
          </thead>
          <tbody>
            {events.map((e: any) => (
              <tr key={e.id} className={e._new ? "flash" : ""}>
                <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                <td><SeverityBadge severity={e.severity} /></td>
                <td>{e.source}</td>
                <td>{e.event_type}</td>
                <td>{e.outcome ?? "—"}</td>
                <td className="mono">{e.source_ip ?? "—"}</td>
                <td className="mono">{e.username ?? "—"}</td>
                <td className="muted" style={{ maxWidth: 480, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.message}</td>
              </tr>
            ))}
            {events.length === 0 && <tr><td colSpan={8} className="muted">No events.</td></tr>}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
