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
  shodan_data: Record<string, unknown> | null;
  virustotal_data: Record<string, unknown> | null;
  abuseipdb_data: Record<string, unknown> | null;
  nmap_data: Record<string, unknown> | null;
  nuclei_data: Record<string, unknown> | null;
  zap_data: Record<string, unknown> | null;
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
  timeout: 30_000,
});

// ---- Request interceptor: inject access token ----
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = tokenStore.getAccess();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

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
