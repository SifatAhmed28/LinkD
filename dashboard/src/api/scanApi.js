import axios from 'axios';

const BASE_URL = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:3000/api';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 35000,
  headers: { 'Content-Type': 'application/json' },
});

/**
 * Submits a URL for phishing analysis.
 * @param {string} url
 * @returns {Promise<ScanResult>}
 */
export async function scanUrl(url) {
  const response = await api.post('/scan', { url });
  return response.data;
}

/**
 * Fetches gateway + ML service health status.
 * @returns {Promise<{gateway: string, ml_service: string}>}
 */
export async function getHealth() {
  const response = await api.get('/scan/health');
  return response.data;
}
