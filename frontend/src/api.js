import axios from 'axios';

export const API = window.SENTINELQ_CONFIG?.apiBaseUrl || (['localhost', '127.0.0.1'].includes(window.location.hostname) ? 'http://127.0.0.1:4000' : window.location.origin);

export function api(path, options = {}) {
  return axios({ url: `${API}${path}`, ...options });
}

export function setToken(token) {
  if (token) axios.defaults.headers.common.Authorization = `Bearer ${token}`;
  else delete axios.defaults.headers.common.Authorization;
}
