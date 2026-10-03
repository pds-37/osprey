import {
  AIAnalysisReport,
  AttackPath,
  AuditEvent,
  CommitRecord,
  ComponentItem,
  ContextualRiskScore,
  GraphData,
  IngestionResult,
  PatchPropagationRecord,
  RemediationTask,
  SBOMDocument,
  VulnerabilityFinding,
} from './types';

const BASE_URL = '/api/v1';

export async function fetchHealth(): Promise<{ status: string; version: string }> {
  const res = await fetch('/health');
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function fetchComponents(ecosystem?: string, search?: string): Promise<ComponentItem[]> {
  const params = new URLSearchParams();
  if (ecosystem && ecosystem !== 'all') params.append('ecosystem', ecosystem);
  if (search) params.append('search', search);
  const res = await fetch(`${BASE_URL}/components?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch components');
  return res.json();
}

export async function fetchSboms(): Promise<SBOMDocument[]> {
  const res = await fetch(`${BASE_URL}/sboms`);
  if (!res.ok) throw new Error('Failed to fetch SBOMs');
  return res.json();
}

export async function fetchGraphData(): Promise<GraphData> {
  const res = await fetch(`${BASE_URL}/graph/data`);
  if (!res.ok) throw new Error('Failed to fetch graph data');
  return res.json();
}

export async function fetchComponentLineage(purl: string): Promise<any> {
  const res = await fetch(`${BASE_URL}/components/lineage?purl=${encodeURIComponent(purl)}`);
  if (!res.ok) throw new Error('Failed to fetch lineage');
  return res.json();
}

export async function uploadSbomJson(payload: {
  content: any;
  application: string;
  environment: string;
  state: string;
}): Promise<IngestionResult> {
  const res = await fetch(`${BASE_URL}/sboms/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Upload failed');
  }
  return res.json();
}

export async function scanLocalWorkspace(path?: string, appName?: string): Promise<IngestionResult> {
  const res = await fetch(`${BASE_URL}/sboms/scan-local-manifests`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, app_name: appName }),
  });
  if (!res.ok) throw new Error('Failed to scan workspace manifests');
  return res.json();
}

export async function fetchVulnerabilities(): Promise<VulnerabilityFinding[]> {
  const res = await fetch(`${BASE_URL}/vulnerabilities`);
  if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
  return res.json();
}

export async function triggerVulnerabilityScan(): Promise<VulnerabilityFinding[]> {
  const res = await fetch(`${BASE_URL}/vulnerabilities/scan`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to run vulnerability scan');
  return res.json();
}

export async function fetchUpstreamChanges(): Promise<CommitRecord[]> {
  const res = await fetch(`${BASE_URL}/upstream-changes`);
  if (!res.ok) throw new Error('Failed to fetch upstream changes');
  return res.json();
}

export async function fetchPatchPropagation(): Promise<PatchPropagationRecord[]> {
  const res = await fetch(`${BASE_URL}/patches/propagation`);
  if (!res.ok) throw new Error('Failed to fetch patch propagation');
  return res.json();
}

export async function fetchAttackPaths(): Promise<AttackPath[]> {
  const res = await fetch(`${BASE_URL}/attack-paths`);
  if (!res.ok) throw new Error('Failed to fetch attack paths');
  return res.json();
}

export async function recalculateAttackPaths(): Promise<AttackPath[]> {
  const res = await fetch(`${BASE_URL}/attack-paths/recalculate`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to recalculate attack paths');
  return res.json();
}

export async function fetchRisks(): Promise<ContextualRiskScore[]> {
  const res = await fetch(`${BASE_URL}/risks`);
  if (!res.ok) throw new Error('Failed to fetch risks');
  return res.json();
}

export async function fetchRiskSummary(): Promise<any> {
  const res = await fetch(`${BASE_URL}/risks/summary`);
  if (!res.ok) throw new Error('Failed to fetch risk summary');
  return res.json();
}

export async function fetchRemediationTasks(): Promise<RemediationTask[]> {
  const res = await fetch(`${BASE_URL}/remediation/tasks`);
  if (!res.ok) throw new Error('Failed to fetch remediation tasks');
  return res.json();
}

export async function approveRemediationTask(taskId: string, actor: string = 'secops-lead'): Promise<RemediationTask> {
  const res = await fetch(`${BASE_URL}/remediation/tasks/${taskId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ actor }),
  });
  if (!res.ok) throw new Error('Approval failed');
  return res.json();
}

export async function verifyRemediationTask(taskId: string): Promise<RemediationTask> {
  const res = await fetch(`${BASE_URL}/remediation/tasks/${taskId}/verify`, { method: 'POST' });
  if (!res.ok) throw new Error('Verification failed');
  return res.json();
}

export async function queryAIAnalyst(componentName: string, question: string): Promise<AIAnalysisReport> {
  const res = await fetch(`${BASE_URL}/ai/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ component_name: componentName, question }),
  });
  if (!res.ok) throw new Error('AI query failed');
  return res.json();
}

export async function fetchAuditEvents(): Promise<AuditEvent[]> {
  const res = await fetch(`${BASE_URL}/audit/events`);
  if (!res.ok) throw new Error('Failed to fetch audit events');
  return res.json();
}

export async function runFlagshipDemo(): Promise<any> {
  const res = await fetch(`${BASE_URL}/demo/run`, { method: 'POST' });
  if (!res.ok) throw new Error('Demo execution failed');
  return res.json();
}
