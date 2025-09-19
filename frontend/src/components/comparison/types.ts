/**
 * Types for the comparison feature
 */

// Project and Version Types
export interface AnalysisProject {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
}

export interface AnalysisVersion {
  id: string;
  project_id: string;
  version_name: string;
  description?: string;
  binary_path: string;
  created_at: string;
}

// Change types
export type ChangeType = 'ADDED' | 'REMOVED' | 'MODIFIED' | 'RENAMED' | 'UNCHANGED';

// Function and Structure Changes
export interface FunctionChange {
  id: string;
  function_name: string;
  base_address?: string;
  target_address?: string;
  change_type: ChangeType;
  similarity?: number;
  comments?: string;
  base_decompiled_code?: string;
  target_decompiled_code?: string;
}

export interface StructureChange {
  id: string;
  structure_name: string;
  base_definition?: string;
  target_definition?: string;
  change_type: ChangeType;
  similarity?: number;
  field_changes?: {
    field_name: string;
    change_type: ChangeType;
    base_type?: string;
    target_type?: string;
  }[];
}

export interface MetricChange {
  function_name: string;
  metric_name: string;
  base_value: number;
  target_value: number;
  change_percentage: number;
}

// Call Graph Types
export interface CallGraphNode {
  id: string;
  name: string;
  type: 'function' | 'external';
  change_type: ChangeType;
}

export interface CallGraphEdge {
  source: string;
  target: string;
  change_type: ChangeType;
}

// Comparison Result
export interface ComparisonResult {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  base_project_id: string;
  base_version_id: string;
  target_project_id: string;
  target_version_id: string;
  created_at: string;
  updated_at?: string;
  overall_similarity: number;
  function_similarity: number;
  structure_similarity: number;
  call_graph_similarity: number;
}

// State Types
export interface ComparisonState {
  projects: AnalysisProject[];
  versions: AnalysisVersion[];
  comparisons: ComparisonResult[];
  functionChanges: FunctionChange[];
  structureChanges: StructureChange[];
  metricChanges: MetricChange[];
  baseProjectId: string | null;
  baseVersionId: string | null;
  targetProjectId: string | null;
  targetVersionId: string | null;
  selectedComparisonId: string | null;
  loading: boolean;
  error: string | null;
}