import axios, { AxiosInstance, AxiosResponse } from "axios";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScanLog {
  id: string;
  level: "info" | "warning" | "error";
  message: string;
  created_at: string;
}

export interface Scan {
  id: string;
  target: string;
  status: "pending" | "running" | "completed" | "failed";
  progress: number;
  risk_score: number | null;
  created_at: string;
  updated_at: string;
  shodan_data: Record<string, unknown> | null;
  virustotal_data: Record<string, unknown> | null;
  abuseipdb_data: Record<string, unknown> | null;
  nmap_data: Record<string, unknown> | null;
  ai_analysis: string | null;
  error_message: string | null;
  logs?: ScanLog[];
}

export interface ScanListResponse {
  total: number;
  items: Scan[];
}

export interface CreateScanPayload {
  target: string;
}

export interface User {
  id: string;
  email: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE}/api`,
  headers: { "Content-Type": "application/json" },
  timeout: 30_000,
});

// Inject auth token from localStorage if available
apiClient.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("auditscan_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error) => {
    const message =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      "An unexpected error occurred";
    return Promise.reject(new Error(message));
  }
);

// ---------------------------------------------------------------------------
// Auth API
// ---------------------------------------------------------------------------

export const authApi = {
  login: async (email: string, password: string): Promise<TokenResponse> => {
    const response = await apiClient.post<TokenResponse>("/auth/login", { email, password });
    return response.data;
  },

  register: async (email: string, password: string): Promise<User> => {
    const response = await apiClient.post<User>("/auth/register", { email, password });
    return response.data;
  },

  me: async (token?: string): Promise<User> => {
    const response = await apiClient.get<User>("/auth/me", {
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    });
    return response.data;
  },
};

// ---------------------------------------------------------------------------
// Scans API
// ---------------------------------------------------------------------------

export const scansApi = {
  create: async (payload: CreateScanPayload): Promise<Scan> => {
    const response = await apiClient.post<Scan>("/scans", payload);
    return response.data;
  },

  list: async (skip = 0, limit = 50): Promise<ScanListResponse> => {
    const response = await apiClient.get<ScanListResponse>("/scans", {
      params: { skip, limit },
    });
    return response.data;
  },

  get: async (id: string): Promise<Scan> => {
    const response = await apiClient.get<Scan>(`/scans/${id}`);
    return response.data;
  },

  getLogs: async (id: string): Promise<ScanLog[]> => {
    const response = await apiClient.get<ScanLog[]>(`/scans/${id}/logs`);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/scans/${id}`);
  },

  retry: async (id: string): Promise<Scan> => {
    const response = await apiClient.post<Scan>(`/scans/${id}/retry`);
    return response.data;
  },
};
