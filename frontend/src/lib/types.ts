// Shapes returned by the Himaak API (backend/modules/*/schemas.py).

export interface User {
  id: number;
  email: string;
  name: string;
}

export type Role = 'owner' | 'member';

export interface Organization {
  id: number;
  name: string;
  role: Role;
}

export interface Member {
  user_id: number;
  email: string;
  name: string;
  role: Role;
}

export interface VerificationInstructions {
  dns_record_name: string | null;
  dns_record_value: string;
  file_url: string;
  file_content: string;
}

export interface Target {
  id: number;
  url: string;
  host: string;
  verified: boolean;
  verification_method: 'dns' | 'file' | null;
  verified_at: string | null;
  created_at: string;
  verification: VerificationInstructions | null;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';
export type ReleaseStatus = 'blocked' | 'conditional' | 'approved';
export type RiskCode = 0 | 1 | 2 | 3;

export interface Scan {
  id: number;
  target_id: number;
  target_url: string;
  scan_type: 'baseline';
  status: ScanStatus;
  error: string | null;
  zap_version: string | null;
  score: number | null;
  release_status: ReleaseStatus | null;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  total_instances: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface FindingSummary {
  id: number;
  scan_id: number;
  fingerprint: string;
  plugin_id: string;
  name: string;
  name_ar: string;
  risk_code: RiskCode;
  cwe_id: string;
  instance_count: number;
}

export interface FindingInstance {
  uri: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
}

export interface Finding extends FindingSummary {
  owasp: string;
  description: string;
  solution: string;
  reference: string;
  other_info: string;
  remediation_title: string;
  remediation_code: string;
  instances: FindingInstance[];
}

export interface Comparison {
  head_scan_id: number;
  base_scan_id: number | null;
  new: FindingSummary[];
  fixed: FindingSummary[];
  persisting: FindingSummary[];
}
