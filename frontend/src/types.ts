export type Ecosystem = 'npm' | 'pypi' | 'debian' | 'rpm' | 'golang' | 'maven' | 'docker' | 'cargo' | 'generic';

export type DependencyState = 'DECLARED' | 'INSTALLED' | 'RUNNING';

export interface ComponentItem {
  id: string;
  name: string;
  ecosystem: Ecosystem;
  version: string;
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

export interface IngestionResult {
  sbom_id: string;
  format: string;
  spec_version: string;
  application: string;
  environment: string;
  components_count: number;
  relationships_count: number;
  components: ComponentItem[];
}
