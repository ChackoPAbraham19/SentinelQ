import axios from 'axios';

export const API = window.SENTINELQ_CONFIG?.apiBaseUrl || (['localhost', '127.0.0.1'].includes(window.location.hostname) ? 'http://127.0.0.1:4000' : window.location.origin);

const client = axios.create({ timeout: 120000 });
let token = null, generation = 0;
export function setToken(value) { const next = value || null; if (token !== next) generation++; token = next; }
client.interceptors.request.use(config => {
  const url = new URL(config.url, API);
  const base = new URL(API);
  if (url.origin !== base.origin || (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('A secure API connection is required.');
  const authorityRoute = /^\/(?:cases(?:\/|$)|authorities\/|audit$|access-audits\/|viewer-key$|courts$|analytics$|ai\/|auth\/logout$)/.test(url.pathname);
  if (!authorityRoute) config.headers.delete('Authorization');
  else if (token && config.headers.get('Authorization') !== null) config.headers.set('Authorization', `Bearer ${token}`);
  config._authorityRequest = Boolean(authorityRoute && config.headers.get('Authorization'));
  config._generation = generation;
  return config;
});
client.interceptors.response.use(response => {
  if (response.config._authorityRequest && response.config._generation !== generation) throw new axios.CanceledError('Session ended');
  return response;
}, error => {
  if (error.config?._authorityRequest && error.config._generation !== generation) return Promise.reject(new axios.CanceledError('Session ended'));
  if (error.response?.status === 401 && error.config?._authorityRequest && error.response.data?.code === 'SESSION_EXPIRED') window.dispatchEvent(new Event('sentinelq-session-expired'));
  return Promise.reject(error);
});
export function api(path, options = {}) { return client({ url: `${API}${path}`, ...options }); }
export default client;
