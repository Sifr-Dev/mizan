import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios';
import type {
  APIResponse,
  AuthResponse,
  User,
  Task,
  CreateTaskRequest,
  UpdateTaskRequest,
} from '../types';

export const api = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

// Authentication requests use a separate client so a failed login or
// registration can never trigger an access-token refresh. Refresh tokens are
// HttpOnly cookies and are sent only with credentialed requests.
export const authClient = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

type RetriableRequest = InternalAxiosRequestConfig & {
  _retried?: boolean;
  _refreshTransientFailure?: boolean;
};

let refreshPromise: Promise<string> | null = null;

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError<APIResponse<unknown>>) => {
    const original = error.config as RetriableRequest | undefined;
    if (error.response?.status === 401 && original && !original._retried) {
      original._retried = true;
      let token: string;
      try {
        token = await refreshAccessToken();
      } catch (refreshError) {
        if (isAuthenticationFailure(refreshError)) {
          clearAccessSession();
        } else {
          // A network error or 5xx from the refresh endpoint is transient.
          // Keep the existing access token and let the caller retry later.
          original._refreshTransientFailure = true;
        }
        return Promise.reject(error);
      }
      original.headers.Authorization = `Bearer ${token}`;
      return api(original);
    }

    if (error.response?.status === 401 && isAuthenticationFailure(error)) {
      clearAccessSession();
    }
    return Promise.reject(error);
  },
);

function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = authClient
      .post<APIResponse<AuthResponse>>('/auth/refresh', {})
      .then(extractData)
      .then((response) => {
        localStorage.setItem('access_token', response.access_token);
        return response.access_token;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

export function isAuthenticationFailure(error: unknown): boolean {
  if (!axios.isAxiosError(error)) {
    return false;
  }
  const request = error.config as RetriableRequest | undefined;
  return error.response?.status === 401 && !request?._refreshTransientFailure;
}

function clearAccessSession(): void {
  localStorage.removeItem('access_token');
  if (window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
}

export function extractData<T>(response: { data: APIResponse<T> }): T {
  if (!response.data.success) {
    throw new Error(response.data.error || 'An error occurred');
  }
  return response.data.data as T;
}

export const authAPI = {
  register: (name: string, email: string, password: string) =>
    authClient.post<APIResponse<AuthResponse>>('/auth/register', { name, email, password })
      .then(extractData),

  login: (email: string, password: string) =>
    authClient.post<APIResponse<AuthResponse>>('/auth/login', { email, password })
      .then(extractData),

  logout: () => authClient.post('/auth/logout'),

  getProfile: () =>
    api.get<APIResponse<User>>('/users/me').then(extractData),
};

export const tasksAPI = {
  list: () =>
    api.get<APIResponse<Task[]>>('/tasks').then(extractData),

  get: (id: string) =>
    api.get<APIResponse<Task>>(`/tasks/${id}`).then(extractData),

  create: (data: CreateTaskRequest) =>
    api.post<APIResponse<Task>>('/tasks', data).then(extractData),

  update: (id: string, data: UpdateTaskRequest) =>
    api.put<APIResponse<Task>>(`/tasks/${id}`, data).then(extractData),

  delete: (id: string) =>
    api.delete(`/tasks/${id}`),
};
