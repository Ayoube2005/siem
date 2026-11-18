import type { FormEvent } from "react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../lib/api";

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      await login(username, password);
      nav("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h2>AI-SIEM</h2>
        <p>Security Operations Console</p>
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button className="btn" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        {error && <div className="error">{error}</div>}
        <p className="muted" style={{ marginTop: 18, fontSize: 12 }}>
          First run uses the seeded admin account from your <code>.env</code>. Change the password after signing in.
        </p>
      </form>
    </div>
  );
}
