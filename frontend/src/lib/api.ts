import axios, { AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from "axios";

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
  current_phase: string | null;
  // v1 scanners
  shodan_data: Record<string, unknown> | null;
  virustotal_data: Record<string, unknown> | null;
  abuseipdb_data: Record<string, unknown> | null;
  nmap_data: Record<string, unknown> | null;
  nuclei_data: Record<string, unknown> | null;
  zap_data: Record<string, unknown> | null;
  // v2 scanners
  subfinder_data: Record<string, unknown> | null;
  dalfox_data: Record<string, unknown> | null;
  fp_reduction_data: Record<string, unknown> | null;
  // v3 scanners (Phase 3)
  ffuf_data: Record<string, unknown> | null;
  sqlmap_data: Record<string, unknown> | null;
  gitleaks_data: Record<string, unknown> | null;
  katana_data: Record<string, unknown> | null;
  // correlation + SOC
  correlated_data: Record<string, unknown> | null;
  soc_report: Record<string, unknown> | null;
  // AI
  ai_analysis: string | null;
  ai_analysis_data: Record<string, unknown> | null;
  // Auth detection (Phase 1.5)
  auth_config: Record<string, unknown> | null;
  error_message: string | null;
  // Detection mode
  lab_mode: boolean;
  logs?: ScanLog[];
}

export interface ScanListResponse {
  total: number;
  items: Scan[];
}

export interface AuthCredentials {
  username?: string;
  password?: string;
  token?: string;
  cookie?: string;
  login_url?: string;
  header_name?: string;
  header_prefix?: string;
}

export interface CreateScanPayload {
  target: string;
  credentials?: AuthCredentials;
  lab_mode?: boolean;
}

export interface User {
  id: string;
  email: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

// ---------------------------------------------------------------------------
// Token storage — source of truth for both tokens
// ---------------------------------------------------------------------------

const ACCESS_KEY = "auditscan_token";
const REFRESH_KEY = "auditscan_refresh_token";
const REMEMBER_KEY = "auditscan_remember";

const _store = (): Storage | null => {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REMEMBER_KEY) === "true" ? localStorage : sessionStorage;
};

export const tokenStore = {
  getAccess: (): string | null => _store()?.getItem(ACCESS_KEY) ?? null,
  getRefresh: (): string | null => _store()?.getItem(REFRESH_KEY) ?? null,

  setRemember: (v: boolean): void => {
    if (typeof window === "undefined") return;
    if (v) localStorage.setItem(REMEMBER_KEY, "true");
    else localStorage.removeItem(REMEMBER_KEY);
  },

  set: (access: string, refresh: string): void => {
    _store()?.setItem(ACCESS_KEY, access);
    _store()?.setItem(REFRESH_KEY, refresh);
  },

  // Wipe from both storages to cover any edge case
  clear: (): void => {
    if (typeof window === "undefined") return;
    [localStorage, sessionStorage].forEach((s) => {
      s.removeItem(ACCESS_KEY);
      s.removeItem(REFRESH_KEY);
    });
    localStorage.removeItem(REMEMBER_KEY);
  },
};

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------

export const apiClient: AxiosInstance = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
  timeout: 120_000,  // 2 min — scans take time, DB pool can be under pressure
});

// Lightweight client for polling endpoints (scan status, logs)
// Shorter timeout — if it fails, React Query retries automatically
export const pollClient: AxiosInstance = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
  timeout: 15_000,
});

// ---- Request interceptor: inject access token (both clients) ----
const _authInterceptor = (config: InternalAxiosRequestConfig) => {
  const token = tokenStore.getAccess();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
};
apiClient.interceptors.request.use(_authInterceptor);
pollClient.interceptors.request.use(_authInterceptor);

// ---- Response interceptor: 401 → silent refresh → retry ----

let _isRefreshing = false;
let _refreshQueue: Array<(token: string) => void> = [];

const _drainQueue = (token: string) => {
  _refreshQueue.forEach((cb) => cb(token));
  _refreshQueue = [];
};

const _forceLogout = () => {
  tokenStore.clear();
  if (typeof window !== "undefined") window.location.href = "/login";
};

apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    if (error.response?.status === 401 && !originalRequest._retry) {
      // Never retry the refresh call itself — that would loop forever
      if (originalRequest.url?.includes("/auth/refresh")) {
        _isRefreshing = false;
        _forceLogout();
        return Promise.reject(new Error("Session expired. Please sign in again."));
      }

      originalRequest._retry = true;

      if (_isRefreshing) {
        // Another refresh is already in flight — queue this request
        return new Promise<AxiosResponse>((resolve) => {
          _refreshQueue.push((newToken: string) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(apiClient(originalRequest));
          });
        });
      }

      const refreshToken = tokenStore.getRefresh();
      if (!refreshToken) {
        _forceLogout();
        return Promise.reject(new Error("Session expired. Please sign in again."));
      }

      _isRefreshing = true;
      try {
        const { data } = await apiClient.post<TokenResponse>("/auth/refresh", {
          refresh_token: refreshToken,
        });
        tokenStore.set(data.access_token, data.refresh_token);
        _isRefreshing = false;
        _drainQueue(data.access_token);
        originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
        return apiClient(originalRequest);
      } catch {
        _isRefreshing = false;
        _refreshQueue = [];
        _forceLogout();
        return Promise.reject(new Error("Session expired. Please sign in again."));
      }
    }

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

  logout: async (accessToken: string, refreshToken?: string | null): Promise<void> => {
    await apiClient.post(
      "/auth/logout",
      refreshToken ? { refresh_token: refreshToken } : null,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
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
    // Use pollClient (15s timeout) — called every 3s during active scans
    const response = await pollClient.get<Scan>(`/scans/${id}`);
    return response.data;
  },

  getLogs: async (id: string): Promise<ScanLog[]> => {
    const response = await pollClient.get<ScanLog[]>(`/scans/${id}/logs`);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/scans/${id}`);
  },

  retry: async (id: string): Promise<Scan> => {
    const response = await apiClient.post<Scan>(`/scans/${id}/retry`);
    return response.data;
  },

  stop: async (id: string): Promise<Scan> => {
    const response = await apiClient.post<Scan>(`/scans/${id}/stop`);
    return response.data;
  },
};
