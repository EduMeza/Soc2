export interface Event {
  id: number;
  event_uid: string;
  timestamp: string;
  agent: string;
  hostname: string;
  source: string;
  event_type: string;
  rule_id: string;
  rule_description: string;
  severity: string;
  original_severity: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  username: string;
  process: string;
  command: string;
  file_path: string;
  cve: string;
  mitre_tactic: string;
  mitre_technique: string;
  raw_event: string;
  risk_score: number;
  correlation_id: string;
  status: string;
  import_batch_id: string;
}

export interface SummaryData {
  total_events: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  agents: number;
  hosts: number;
  external_ips: number;
  internal_ips: number;
  rules: number;
  cves: number;
  correlations: number;
  overall_risk: number;
}

export interface TimelineEvent {
  timestamp: string;
  severity: string;
  host: string;
  agent: string;
  source_ip: string;
  rule: string;
  description: string;
  mitre_tactic: string;
  mitre_technique: string;
  correlation_id: string;
}

export interface SeverityDistribution {
  [key: string]: number;
}

export interface TopItem {
  agent?: string;
  host?: string;
  rule?: string;
  ip?: string;
  count: number;
}

export interface MitreDistribution {
  tactics: Array<{ tactic: string; count: number }>;
  techniques: Array<{ technique: string; count: number }>;
}

export interface Correlation {
  id: string;
  title: string;
  severity: string;
  risk: number;
  first_seen: string;
  last_seen: string;
  hosts: string[];
  agents: string[];
  ips: string[];
  events: number;
  evidence: string[];
  confidence: number;
}

export interface RiskAnalysis {
  overall_risk: number;
  per_agent: Record<string, number>;
  factors: Record<string, number>;
}

export interface IocsData {
  ips: string[];
}

export interface ReportRequest {
  format: 'pdf' | 'txt' | 'json';
  report_type: 'ejecutivo' | 'tecnico' | 'auditoria';
  include_timeline?: boolean;
}

export interface GenerateReportResponse {
  status: string;
  message: string;
  report_id: string;
  files: Record<string, string>;
}

export interface ReportRecord {
  id: string;
  timestamp: string;
  analyst: string;
  entity: string;
  period: string;
  total_events: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number;
  file_paths: Record<string, string>;
  summary: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  force_change: boolean;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface User {
  username: string;
  force_change: boolean;
}

export interface CsvImportResult {
  message: string;
  inserted: number;
  batch_id: string;
}

export interface CsvImportProgress {
  status: 'uploading' | 'parsing' | 'analyzing' | 'storing' | 'completed' | 'error';
  progress: number;
  message: string;
  inserted?: number;
  batch_id?: string;
  error?: string;
}

export interface MitreTactic {
  tactic: string;
  count: number;
  technique: string[];
  tactic_id: string;
}

export interface MitreTechnique {
  technique: string;
  count: number;
}