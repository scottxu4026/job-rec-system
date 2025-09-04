import axios from 'axios';
import type { AxiosError, AxiosInstance } from 'axios';

const baseURL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:8080';

const api: AxiosInstance = axios.create({ baseURL, withCredentials: false });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err: AxiosError) => {
    const status = err.response?.status;
    const reqUrl = (err.config?.url || '').toString();
    // Do not redirect for login endpoint; let page show precise error
    if (reqUrl.includes('/auth/login')) {
      return Promise.reject(err);
    }
    if (status === 401 || status === 403) {
      // Clear token and redirect to login
      localStorage.removeItem('auth_token');
      // Optional: show a user-friendly message
      if (status === 401) alert('Please login to continue.');
      if (status === 403) alert('You do not have permission to perform this action.');
      if (typeof window !== 'undefined') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

export const get = <T = any>(url: string, config?: any) => api.get<T>(url, config);
export const post = <T = any>(url: string, data?: any, config?: any) => api.post<T>(url, data, config);
export const put = <T = any>(url: string, data?: any, config?: any) => api.put<T>(url, data, config);
export const del = <T = any>(url: string, config?: any) => api.delete<T>(url, config);

export default api;


