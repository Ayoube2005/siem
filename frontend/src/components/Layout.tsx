import type { ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { clearAuth, getUser } from "../lib/api";

export function Layout({ title, right, children }: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
}) {
  const user = getUser();
  const nav = useNavigate();
  const logout = () => { clearAuth(); nav("/login"); };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand"><span className="dot" /> AI-SIEM</div>
        <nav className="nav">
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/events">Events</NavLink>
        </nav>
        <div className="spacer" />
        <div className="userbox">
          <b>{user?.username ?? "—"}</b>
          <span>role: {user?.role ?? "—"}</span>
          <div style={{ marginTop: 10 }}>
            <button className="btn ghost" style={{ width: "100%" }} onClick={logout}>Sign out</button>
          </div>
        </div>
      </aside>
      <div className="main">
        <div className="topbar">
          <h1>{title}</h1>
          <div className="row">{right}</div>
        </div>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
