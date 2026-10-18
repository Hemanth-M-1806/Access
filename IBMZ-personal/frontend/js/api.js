/**
 * AccessDrift API Client & Network Controller
 */
import { state } from './state.js';

export async function apiRequest(endpoint, options = {}) {
  const headers = options.headers || {};

  if (state.token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(endpoint, {
    ...options,
    headers
  });

  if (!res.ok) {
    let msg = `API Request failed with status ${res.status}`;
    try {
      const err = await res.json();
      msg = err.detail || err.message || msg;
    } catch (e) {}
    throw new Error(msg);
  }

  const contentType = res.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return await res.json();
  }
  return res;
}

export const api = {
  // Authentication
  async login(username, password) {
    return await apiRequest('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
  },

  async getMe() {
    return await apiRequest('/api/v1/auth/me');
  },

  async trialLogin(personaId) {
    return await apiRequest('/api/v1/auth/trial-login', {
      method: 'POST',
      body: JSON.stringify({ persona: personaId })
    });
  },

  // Governance Data
  async getBranches() {
    return await apiRequest('/api/v1/branches');
  },

  async addBranch(branchName) {
    return await apiRequest('/api/v1/branches', {
      method: 'POST',
      body: JSON.stringify({ branch_name: branchName })
    });
  },

  async getUsers(branch = 'all') {
    const q = branch && branch !== 'all' ? `?branch=${encodeURIComponent(branch)}` : '';
    return await apiRequest(`/api/v1/users${q}`);
  },

  async getTopology(branch = 'all') {
    const q = branch && branch !== 'all' ? `?branch=${encodeURIComponent(branch)}` : '';
    return await apiRequest(`/api/v1/topology${q}`);
  },

  // Mutation & Actions
  async remediate(userId, stripDriftOnly = true) {
    return await apiRequest('/api/v1/remediate', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, strip_drift_only: stripDriftOnly })
    });
  },

  async simulateRoleChange(userId, newRole, newDept = null) {
    const body = { user_id: userId, new_role: newRole };
    if (newDept && newDept.trim()) body.new_department = newDept.trim();
    return await apiRequest('/api/v1/simulate/role-change', {
      method: 'POST',
      body: JSON.stringify(body)
    });
  },

  async addEmployee(data) {
    return await apiRequest('/api/v1/roster/add-user', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async deleteEmployee(userId) {
    return await apiRequest(`/api/v1/roster/users/${encodeURIComponent(userId)}`, {
      method: 'DELETE'
    });
  },

  async uploadCsv(formData) {
    return await apiRequest('/api/v1/roster/upload-csv', {
      method: 'POST',
      body: formData
    });
  },

  // Workspace Modes
  async initBlankWorkspace() {
    return await apiRequest('/api/v1/workspace/init-blank', { method: 'POST' });
  },

  async loadDemoWorkspace() {
    return await apiRequest('/api/v1/workspace/load-demo', { method: 'POST' });
  },

  async resetDemo() {
    return await apiRequest('/api/v1/reset', { method: 'POST' });
  },

  // Telemetry & Ledger
  async getHealth() {
    const res = await fetch('/api/v1/system/health');
    return await res.json();
  },

  async getAuditLedger() {
    return await apiRequest('/api/v1/audit-ledger');
  }
};
