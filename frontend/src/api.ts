import { ComponentItem, GraphData, IngestionResult, SBOMDocument } from './types';

const BASE_URL = '/api/v1';

export async function fetchHealth(): Promise<{ status: string; version: string }> {
  const res = await fetch('/health');
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function fetchComponents(ecosystem?: string, search?: string): Promise<ComponentItem[]> {
  const params = new URLSearchParams();
  if (ecosystem) params.append('ecosystem', ecosystem);
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
