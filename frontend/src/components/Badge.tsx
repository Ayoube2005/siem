import type { Severity } from "../lib/types";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

export function VerdictPill({ verdict }: { verdict: string }) {
  const label: Record<string, string> = {
    unconfirmed: "Unconfirmed",
    true_positive: "True Positive",
    false_positive: "False Positive",
  };
  return <span className="pill">{label[verdict] ?? verdict}</span>;
}
