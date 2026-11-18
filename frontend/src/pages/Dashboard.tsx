import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import { Layout } from "../components/Layout";
import { SeverityBadge } from "../components/Badge";
import { apiGet } from "../lib/api";
import { useLiveStream } from "../lib/ws";
import type { Alert, Overview, SecurityEvent, Severity } from "../lib/types";

const SEV_COLOR: Record<string, string> = {
  Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#38bdf8", Informational: "#64748b",
};

interface TimelinePoint { t: string; count: number; }
interface SevCount { severity: Severity; count: number; }
interface IpCount { source_ip: string; count: number; }
interface RuleCount { rule_id: string; rule_name: string; count: number; }

export default function Dashboard() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [sev, setSev] = useState<SevCount[]>([]);
  const [ips, setIps] = useState<IpCount[]>([]);
  const [rules, setRules] = useState<RuleCount[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const nav = useNavigate();

  const loadAll = async () => {
    const [o, tl, s, ip, r, ev, al] = await Promise.all([
      apiGet<Overview>("/api/stats/overview"),
      apiGet<{ series: TimelinePoint[] }>("/api/stats/events-timeline", { minutes: 60, buckets: 30 }),
      apiGet<SevCount[]>("/api/stats/alerts-by-severity"),
      apiGet<IpCount[]>("/api/stats/top-source-ips", { limit: 8 }),
      apiGet<RuleCount[]>("/api/stats/top-rules", { limit: 8 }),
      apiGet<SecurityEvent[]>("/api/events", { limit: 25 }),
      apiGet<Alert[]>("/api/alerts", { limit: 12 }),
    ]);
    setOv(o); setTimeline(tl.series); setSev(s); setIps(ip); setRules(r);
    setEvents(ev); setAlerts(al);
  };

  useEffect(() => {
    loadAll().catch(() => {});
    const id = setInterval(() => loadAll().catch(() => {}), 15000);
    return () => clearInterval(id);
  }, []);

  const { connected } = useLiveStream((m) => {
    if (m.type === "event") {
      setEvents((prev) => [{ ...m.data, _new: true }, ...prev].slice(0, 25));
      setOv((p) => p && { ...p, total_events: p.total_events + 1, events_last_hour: p.events_last_hour + 1 });
    } else if (m.type === "alert") {
      setAlerts((prev) => [{ ...m.data, _new: true }, ...prev].slice(0, 12));
      setOv((p) => p && {
        ...p,
        total_alerts: p.total_alerts + 1,
        open_alerts: p.open_alerts + 1,
        critical_alerts: p.critical_alerts + (m.data.severity === "Critical" ? 1 : 0),
        high_alerts: p.high_alerts + (m.data.severity === "High" ? 1 : 0),
      });
    }
  });

  return (
    <Layout title="Dashboard" right={<ConnDot connected={connected} />}>
      <div className="grid cards">
        <Stat label="Total Events" value={ov?.total_events} />
        <Stat label="Events / last hour" value={ov?.events_last_hour} />
        <Stat label="Total Alerts" value={ov?.total_alerts} />
        <Stat label="Open Alerts" value={ov?.open_alerts} />
        <Stat label="Critical" value={ov?.critical_alerts} cls="crit" />
        <Stat label="High" value={ov?.high_alerts} cls="high" />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "2fr 1fr", marginTop: 16 }}>
        <div className="card">
          <h3>Events over time (last hour)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={timeline}>
              <CartesianGrid stroke="#243043" strokeDasharray="3 3" />
              <XAxis dataKey="t" tick={false} stroke="#8b9bb4" />
              <YAxis allowDecimals={false} stroke="#8b9bb4" width={30} />
              <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => new Date(l).toLocaleTimeString()} />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h3>Alerts by severity</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={sev}>
              <CartesianGrid stroke="#243043" strokeDasharray="3 3" />
              <XAxis dataKey="severity" stroke="#8b9bb4" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} stroke="#8b9bb4" width={30} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2233" }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {sev.map((s) => <Cell key={s.severity} fill={SEV_COLOR[s.severity]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", marginTop: 16 }}>
        <div className="card">
          <h3>Live alerts</h3>
          <div className="stream">
            <table>
              <tbody>
                {alerts.map((a: any) => (
                  <tr key={a.id} className={a._new ? "flash" : ""} onClick={() => nav(`/alerts/${a.id}`)}>
                    <td style={{ width: 90 }}><SeverityBadge severity={a.severity} /></td>
                    <td>{a.title}</td>
                    <td className="mono" style={{ width: 120 }}>{a.source_ip ?? "—"}</td>
                  </tr>
                ))}
                {alerts.length === 0 && <tr><td className="muted">No alerts yet. Run the simulator.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <h3>Live event stream</h3>
          <div className="stream">
            {events.map((e: any) => (
              <div key={e.id} className={`line ${e._new ? "flash" : ""}`}>
                <SeverityBadge severity={e.severity} />
                <span className="muted">{e.source}/{e.event_type}</span>
                <span>{e.source_ip ?? ""}</span>
                <span className="muted" style={{ marginLeft: "auto" }}>{e.outcome ?? ""}</span>
              </div>
            ))}
            {events.length === 0 && <div className="muted">Waiting for events…</div>}
          </div>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", marginTop: 16 }}>
        <div className="card">
          <h3>Top source IPs</h3>
          <table>
            <thead><tr><th>Source IP</th><th>Events</th></tr></thead>
            <tbody>
              {ips.map((i) => <tr key={i.source_ip}><td className="mono">{i.source_ip}</td><td>{i.count}</td></tr>)}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>Most frequent detection rules</h3>
          <table>
            <thead><tr><th>Rule</th><th>Name</th><th>Count</th></tr></thead>
            <tbody>
              {rules.map((r) => <tr key={r.rule_id}><td className="mono">{r.rule_id}</td><td>{r.rule_name}</td><td>{r.count}</td></tr>)}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}

const tooltipStyle = { background: "#121826", border: "1px solid #243043", borderRadius: 8, color: "#e6edf6" };

function Stat({ label, value, cls = "" }: { label: string; value?: number; cls?: string }) {
  return (
    <div className={`card stat ${cls}`}>
      <div className="value">{value ?? "—"}</div>
      <div className="label">{label}</div>
    </div>
  );
}

function ConnDot({ connected }: { connected: boolean }) {
  return (
    <div className="conn">
      <span className={`dot ${connected ? "on" : "off"}`} />
      {connected ? "Live" : "Reconnecting…"}
    </div>
  );
}
