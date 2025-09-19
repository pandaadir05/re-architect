/**
 * API service for communicating with the backend
 */

// Base API URL from environment variable or default
export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Types
export interface Metadata {
  file_path: string;
  file_format: string;
  architecture: string;
  entry_point: string;
  size: number;
  sections: Section[];
  symbols: number;
  imports: Import[];
  timestamp: string;
}

export interface Section {
  name: string;
  address: string;
  size: number;
}

export interface Import {
  name: string;
  functions: number;
}

export interface Function {
  id: string;
  name: string;
  address: string;
  size: number;
  complexity: string;
  decompiled_code: string;
  summary: string;
  parameters: Parameter[];
  returns: ReturnType;
  calls: string[];
  called_by: string[];
  confidence: number;
  vulnerabilities: Vulnerability[];
}

export interface Parameter {
  name: string;
  type: string;
  description: string;
}

export interface ReturnType {
  type: string;
  description: string;
}

export interface Vulnerability {
  type: string;
  severity: string;
  description: string;
  location: {
    line: number;
    column: number;
  };
}

export interface DataStructure {
  id: string;
  name: string;
  size: number;
  fields: Field[];
  description: string;
  references: string[];
  confidence: number;
}

export interface Field {
  name: string;
  type: string;
  offset: number;
  size: number;
  description: string;
}

export interface TestHarness {
  function_id: string;
  function_name: string;
  test_code: string;
  test_cases: TestCase[];
  coverage: number;
  execution_result: string;
  confidence: number;
}

export interface TestCase {
  inputs: Record<string, any>;
  expected_output: any;
  description: string;
}

export interface Summary {
  total_functions: number;
  total_data_structures: number;
  total_tests: number;
  total_vulnerabilities: number;
  binary_name: string;
  analysis_time: number;
}

export interface PerformanceMetrics {
  loading_time: number;
  decompilation_time: number;
  analysis_time: number;
  summarization_time: number;
  test_generation_time: number;
  total_time: number;
}

export interface AnalysisResults {
  static: AnalysisResult;
  dynamic: AnalysisResult;
  symbolic: AnalysisResult;
}

export interface AnalysisResult {
  executed: boolean;
  findings: number;
  execution_time: number;
}

/**
 * Fetch API wrapper with error handling
 */
async function fetchApi<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.error || `API error: ${response.status} ${response.statusText}`
      );
    }

    return await response.json();
  } catch (error) {
    console.error(`Error fetching ${endpoint}:`, error);
    throw error;
  }
}

/**
 * API services for the RE-Architect backend
 */
const api = {
  /**
   * Get summary information
   */
  getSummary: (): Promise<Summary> => {
    return fetchApi<Summary>('/summary');
  },

  /**
   * Get binary metadata
   */
  getMetadata: (): Promise<Metadata> => {
    return fetchApi<Metadata>('/metadata');
  },

  /**
   * Get all functions
   */
  getFunctions: (): Promise<Record<string, Function>> => {
    return fetchApi<Record<string, Function>>('/functions');
  },

  /**
   * Get function details by ID
   */
  getFunction: (functionId: string): Promise<Function> => {
    return fetchApi<Function>(`/function/${functionId}`);
  },

  /**
   * Get all data structures
   */
  getDataStructures: (): Promise<Record<string, DataStructure>> => {
    return fetchApi<Record<string, DataStructure>>('/data_structures');
  },

  /**
   * Get data structure details by ID
   */
  getDataStructure: (structureId: string): Promise<DataStructure> => {
    return fetchApi<DataStructure>(`/data_structure/${structureId}`);
  },

  /**
   * Get all test harnesses
   */
  getTestHarnesses: (): Promise<Record<string, TestHarness>> => {
    return fetchApi<Record<string, TestHarness>>('/test_harnesses');
  },

  /**
   * Get test harness for a function by ID
   */
  getTestHarness: (functionId: string): Promise<TestHarness> => {
    return fetchApi<TestHarness>(`/test_harness/${functionId}`);
  },

  /**
   * Get performance metrics
   */
  getPerformanceMetrics: (): Promise<PerformanceMetrics> => {
    return fetchApi<PerformanceMetrics>('/performance');
  },

  /**
   * Get analysis results
   */
  getAnalysis: (analysisId: string): Promise<any> => {
    return fetchApi<any>(`/analysis/${analysisId}`);
  },
};

export default api;
