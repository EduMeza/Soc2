declare global {
  interface ImportMetaEnv {
    readonly VITE_API_BASE_URL: string;
  }

  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api';

class ApiClient {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem('access_token');
  }

  setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem('access_token', token);
    } else {
      localStorage.removeItem('access_token');
    }
  }

  getToken(): string | null {
    return this.token;
  }

  isAuthenticated(): boolean {
    return !!this.token;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: HeadersInit = {
      ...(options.headers || {}),
    };

    const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
    if (!isFormData) {
      (headers as Record<string, string>)['Content-Type'] = 'application/json';
    }

    if (this.token) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      this.setToken(null);
      window.location.href = '/login';
      throw new Error('Sesión expirada');
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Error desconocido' }));
      throw new Error(error.detail || `Error ${response.status}`);
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json();
  }

  // Auth
  async login(username: string, password: string) {
    const data = await this.request<{
      access_token: string;
      token_type: string;
      force_change: boolean;
    }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    this.setToken(data.access_token);
    return data;
  }

  async logout() {
    this.setToken(null);
  }

  async getCurrentUser() {
    return this.request<{ username: string; force_change: boolean }>('/auth/me');
  }

  async changePassword(current_password: string, new_password: string) {
    return this.request('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    });
  }

  // Events
  async importCsv(file: File): Promise<{ message: string; inserted: number; batch_id: string }> {
    const formData = new FormData();
    formData.append('file', file);
    return this.request('/events/import', {
      method: 'POST',
      body: formData,
      headers: {},
    });
  }

  async getEvents(page = 1, limit = 50) {
    return this.request<{ items: any[]; total: number; page: number; limit: number }>(
      `/events/?page=${page}&limit=${limit}`
    );
  }

  // Analytics
  async getSummary() {
    return this.request<{
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
    }>('/analytics/summary');
  }

  async getTimeline(limit = 100) {
    return this.request<any[]>(`/analytics/timeline?limit=${limit}`);
  }

  async getSeverityDistribution() {
    return this.request<Record<string, number>>('/analytics/severity');
  }

  async getTopAgents(limit = 10) {
    return this.request<Array<{ agent: string; count: number }>>(`/analytics/agents?limit=${limit}`);
  }

  async getTopHosts(limit = 10) {
    return this.request<Array<{ host: string; count: number }>>(`/analytics/hosts?limit=${limit}`);
  }

  async getTopRules(limit = 10) {
    return this.request<Array<{ rule: string; count: number }>>(`/analytics/rules?limit=${limit}`);
  }

  async getTopIps(limit = 10) {
    return this.request<Array<{ ip: string; count: number }>>(`/analytics/ips?limit=${limit}`);
  }

  async getMitreDistribution() {
    return this.request<{
      tactics: Array<{ tactic: string; count: number }>;
      techniques: Array<{ technique: string; count: number }>;
    }>('/analytics/mitre');
  }

  async getGraph() {
    return this.request<{
      nodes: Array<{
        id: string;
        type: string;
        position: { x: number; y: number };
        data: any;
      }>;
      edges: Array<{
        id: string;
        source: string;
        target: string;
        type?: string;
        data: any;
      }>;
    }>('/analytics/graph');
  }

  async getCorrelations() {
    return this.request<Array<{
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
    }>>('/analytics/correlations');
  }

  async getRiskAnalysis() {
    return this.request<{
      overall_risk: number;
      per_agent: Record<string, number>;
      factors: Record<string, number>;
    }>('/analytics/risk');
  }

  async getIocs() {
    return this.request<{ ips: string[] }>('/analytics/iocs');
  }

  // GeoIP
  async getGeoip(ips: string[]) {
    if (!ips.length) return this.request<Record<string, any>>('/geoip/');
    return this.request<Record<string, any>>('/geoip/batch', {
      method: 'POST',
      body: JSON.stringify(ips),
    });
  }

  // Reports
  async generateReport(format: 'pdf' | 'txt' | 'json' | 'stx', reportType: string, includeTimeline = true, entity = '', analyst = '') {
    return this.request<{
      status: string;
      message: string;
      report_id: string;
      files: Record<string, string>;
    }>('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ format, report_type: reportType, include_timeline: includeTimeline, entity, analyst }),
    });
  }

  async getReports(limit = 50) {
    return this.request<Array<{
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
    }>>(`/reports?limit=${limit}`);
  }

  async getReport(reportId: string) {
    return this.request<any>(`/reports/${reportId}`);
  }

  async downloadReport(format: 'pdf' | 'txt' | 'json', reportId: string): Promise<Blob> {
    const response = await fetch(`${API_BASE_URL}/reports/download/${format}/${encodeURIComponent(reportId)}`, {
      headers: {
        Authorization: `Bearer ${this.token}`,
      },
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || `No se pudo descargar el reporte (HTTP ${response.status})`);
    }
    return response.blob();
  }
}

export const api = new ApiClient();
