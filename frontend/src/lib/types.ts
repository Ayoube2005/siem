export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export interface SecurityEvent {
  id: number;
  timestamp: string;
  ingested_at?: string;
  source: string;
  event_type: string;
  outcome?: string | null;
  severity: Severity;
  source_ip?: string | null;
  dest_ip?: string | null;
  username?: string | null;
  hostname?: string | null;
  message: string;
}

export interface AIAnalysis {
  classification: string;
  confidence: number;
  explanation: string;
  supporting_evidence: string[];
  investigation_steps: string[];
  response_actions: string[];
  provider: string;
  disclaimer: string;
}

export interface Alert {
  id: number;
  created_at: string;
  updated_at: string;
  rule_id: string;
  rule_name: string;
  title: string;
  description: string;
  severity: Severity;
  risk_score: number;
  source_ip?: string | null;
  dest_ip?: string | null;
  username?: string | null;
  evidence: Record<string, unknown>;
  event_count: number;
  first_seen: string;
  last_seen: string;
  status: "open" | "investigating" | "closed";
  analyst_verdict: "unconfirmed" | "true_positive" | "false_positive";
  assigned_to?: string | null;
  ai_classification?: string | null;
  ai_confidence?: number | null;
  ai_analysis?: AIAnalysis | null;
}

export interface Overview {
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  events_last_hour: number;
}
