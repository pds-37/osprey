export type Ecosystem = 'npm' | 'pypi' | 'debian' | 'rpm' | 'golang' | 'maven' | 'docker' | 'cargo' | 'generic';

export type DependencyState = 'UNKNOWN' | 'DECLARED' | 'LOCKED' | 'INSTALLED' | 'RUNNING';

export interface ComponentItem {
  id: string;
  name: string;
  ecosystem: Ecosystem;
  version: string;
  declared_version?: string | null;
  locked_version?: string | null;
  installed_version?: string | null;
  running_version?: string | null;
  purl: string;
  source?: string;
  checksum?: string;
  parent_purls: string[];
  environment: string;
  application: string;
  deployment?: string;
  owner?: string;
  state: DependencyState;
  first_seen: string;
  last_seen: string;
  licenses: string[];
  properties: Record<string, any>;
}

export interface SBOMDocument {
  id: string;
  format: string;
  spec_version: string;
  application: string;
  environment: string;
  created_at: string;
  component_count: number;
  raw_metadata: Record<string, any>;
}

export interface IngestionResult {
  sbom_id: string;
  format: string;
  spec_version: string;
  application: string;
  environment: string;
  components_count: number;
  relationships_count: number;
  components: ComponentItem[];
  relationships: any[];
  summary: Record<string, any>;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  color: string;
  version?: string;
  ecosystem?: string;
  state?: DependencyState;
  properties: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
  properties: Record<string, any>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: Record<string, any>;
}

export interface VulnerabilityFinding {
  id: string;
  vulnerability_id: string;
  component_purl: string;
  component_name: string;
  observed_version?: string;
  installed_version: string | null;
  declared_version?: string | null;
  locked_version?: string | null;
  runtime_state?: Record<string, 'OBSERVED' | 'UNKNOWN'>;
  runtime_evidence_ids?: string[];
  runtime_limitations?: string[];
  fixed_version?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  is_fix_available: boolean;
  application: string;
  environment: string;
  discovered_at: string;
  vulnerability?: {
    summary: string;
    details: string;
    cvss_score?: number;
    affected_version_ranges: string[];
    fixed_versions: string[];
  };
}

export interface CommitRecord {
  id: string;
  commit_sha: string;
  repository: string;
  component_name: string;
  author: string;
  timestamp: string;
  message: string;
  diff_summary?: string;
  classification: string;
  confidence: number;
  detected_signals: string[];
  reasoning: string;
  potential_fixed_version?: string;
}

export interface PatchPropagationRecord {
  id: string;
  component_name: string;
  installed_version: string;
  vulnerability_id: string;
  fixed_version: string;
  application: string;
  environment: string;
  bottleneck_stage?: string | null;
  is_production_exposed?: boolean | null;
  fixture?: boolean;
  summary_explanation: string;
  stages: Record<string, {
    stage: string;
    status: string;
    evidence: string;
    version_or_tag?: string;
  }>;
}

export interface AttackPathNode {
  id: string;
  label: string;
  role: string;
  description: string;
  evidence: Record<string, any>;
}

export interface AttackPath {
  id: string;
  name: string;
  entry_point: string;
  vulnerable_component: string;
  vulnerability_id: string;
  target_resource: string;
  nodes: AttackPathNode[];
  step_edges: { source: string; target: string; label: string }[];
  exploitation_condition: string;
  privilege_transitions: string[];
  evidence: string[];
  confidence: number;
  status: 'OPEN' | 'CLOSED';
  fixture?: boolean;
  recommended_remediation: string;
}

export interface ContextualRiskScore {
  id: string;
  finding_id: string;
  component_purl: string;
  component_name: string;
  vulnerability_id: string;
  risk_level: 'UNKNOWN' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  decision: 'ACT NOW' | 'PLAN' | 'MONITOR' | 'IGNORE' | 'UNKNOWN';
  composite_score?: number | null;
  evidence_coverage: number;
  fixture?: boolean;
  cvss_score?: number;
  reasons: string[];
  limitations: string[];
  factors: { name: string; weight: number; score: number | null; description: string }[];
  attack_path_id?: string;
  potential_impact: string;
  evidence: string[];
}

export interface RemediationTask {
  id: string;
  vulnerability_id: string;
  component_name: string;
  current_version: string;
  target_version: string;
  action_type: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'VERIFIED_CLOSED' | 'VERIFIED_RESOLVED' | 'UNVERIFIED';
  pull_request: {
    title: string;
    body: string;
    branch_name?: string | null;
    target_file?: string | null;
    diff_content?: string | null;
  };
  approval_actor?: string;
  approved_at?: string;
  verified_at?: string;
  verification_evidence?: Record<string, any>;
  fixture?: boolean;
}

export interface AIAnalysisReport {
  query: string;
  target_component: string;
  executive_summary: string;
  lineage_explanation: string;
  exposure_verdict: string;
  attack_path_summary: string;
  upstream_change_summary: string;
  remediation_recommendation: string;
  evidence_citations: string[];
  evidence_ids: string[];
  analysis_mode: string;
}

export interface CopilotResponse {
  request_id: string;
  finding_id: string;
  deterministic_finding: {
    vulnerability_id: string;
    package: string;
    severity: string;
    reachability: string;
    runtime_state: Record<string, string>;
  };
  answer: string;
  claims: { text: string; evidence_ids: string[] }[];
  evidence_ids: string[];
  unknowns: string[];
  limitations: string[];
  recommended_next_steps: string[];
  security_confidence: Record<string, string | number>;
  ai_explanation_confidence: string;
  provider: string;
  validation_status: string;
  context_hash: string;
  analyzer_version: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  details: Record<string, any>;
  status: string;
}
