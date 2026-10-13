/**
 * BrandShield AI - Unified REST API Client
 * Compatible with local dev proxy, Vercel single-origin rewrites, and direct Render backend.
 */

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const token = localStorage.getItem('brandshield_token');

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? {
      'Authorization': `Bearer ${token}`,
      'X-Analyst-Email': token,
    } : {}),
    ...options.headers,
  };

  const config = {
    ...options,
    headers,
    credentials: 'include', // Sends HTTP-only session cookies
  };

  try {
    const response = await fetch(url, config);

    // Handle CSV or file downloads
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('text/csv') || contentType.includes('application/octet-stream')) {
      const blob = await response.blob();
      return { ok: response.ok, data: blob };
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMsg = data.error || data.message || `Request failed with status ${response.status}`;
      return { ok: false, status: response.status, error: errorMsg, data };
    }

    return { ok: true, status: response.status, data };
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err);
    return { ok: false, error: err.message || 'Network connection failed' };
  }
}

export const api = {
  // Base URL helper
  getBaseUrl: () => API_BASE,

  // Health
  checkHealth: () => request('/health'),
  getStatus: () => request('/api/status'),

  // Auth
  auth: {
    login: async (username, password, remember = true) => {
      const res = await request('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password, remember }),
      });
      if (res.ok && res.data?.token) {
        localStorage.setItem('brandshield_token', res.data.token);
        localStorage.setItem('brandshield_user', JSON.stringify(res.data.user));
      }
      return res;
    },
    signup: async (name, email, password, department) => {
      const res = await request('/api/auth/signup', {
        method: 'POST',
        body: JSON.stringify({ name, email, password, department }),
      });
      if (res.ok && res.data?.token) {
        localStorage.setItem('brandshield_token', res.data.token);
        localStorage.setItem('brandshield_user', JSON.stringify(res.data.user));
      }
      return res;
    },
    getMe: async () => {
      const res = await request('/api/auth/me');
      if (res.ok && res.data?.authenticated) {
        localStorage.setItem('brandshield_user', JSON.stringify(res.data.user));
      }
      return res;
    },
    logout: async () => {
      await request('/api/auth/logout', { method: 'POST' });
      localStorage.removeItem('brandshield_token');
      localStorage.removeItem('brandshield_user');
      return { ok: true };
    },
    getStoredUser: () => {
      try {
        const u = localStorage.getItem('brandshield_user');
        return u ? JSON.parse(u) : null;
      } catch {
        return null;
      }
    }
  },

  // Dashboard & Telemetry
  dashboard: {
    getStats: () => request('/api/dashboard-stats'),
    getMlMetrics: () => request('/api/ml-metrics'),
    getSocialMetrics: () => request('/api/social-ml-metrics'),
    getAppMetrics: () => request('/api/app-ml-metrics'),
  },

  // Brand Registry
  brands: {
    getAll: () => request('/api/brands'),
    add: (brandData) => request('/api/brands', {
      method: 'POST',
      body: JSON.stringify(brandData),
    }),
    delete: (brandId) => request(`/api/brands/${brandId}`, {
      method: 'DELETE',
    }),
    reset: () => request('/api/brands/reset', {
      method: 'POST',
    }),
  },

  // Detection Engines
  scanners: {
    scanLink: (url, brandId) => request('/api/scan/link', {
      method: 'POST',
      body: JSON.stringify({ url, brand_id: brandId }),
    }),
    scanSocial: (socialData) => request('/api/scan/social', {
      method: 'POST',
      body: JSON.stringify(socialData),
    }),
    scanApp: (appData) => request('/api/scan/app', {
      method: 'POST',
      body: JSON.stringify(appData),
    }),
  },

  // History & Audit
  history: {
    getAll: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return request(`/api/history${q ? `?${q}` : ''}`);
    },
    getScan: (scanId) => request(`/api/scan/${scanId}`),
    exportCsvUrl: () => `${API_BASE}/history/export/csv`,
    exportJsonUrl: () => `${API_BASE}/history/export/json`,
  }
};

export default api;
