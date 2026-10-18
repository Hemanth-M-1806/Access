/**
 * AccessDrift Main Application Coordinator
 */
import { state } from './state.js';
import { api } from './api.js';
import { renderAuthPage, signOut } from './components/auth.js';
import { initGraphCanvas, loadTopologyData, drawFrame } from './components/graph.js';
import { selectUser, executeRemediation, renderPolicyCode } from './components/inspector.js';
import { renderRosterTable } from './components/roster-table.js';
import { updateOnboardingBanner, promptAddBranch } from './components/onboarding.js';
import { initModals, openModal, closeModal, loadLedgerBlocks } from './components/modals.js';
import { showToast, escapeHtml } from './components/toast.js';

// Bootstrap App
async function init() {
  // Check session
  if (!state.token) {
    showAuthView();
  } else {
    try {
      const me = await api.getMe();
      state.currentUser = me;
      state.isAuthenticated = true;
      showDashboardView();
      await loadEnterpriseData();
    } catch (err) {
      console.warn("Stored session invalid, showing login screen:", err);
      showAuthView();
    }
  }

  setupGlobalEventListeners();
  setInterval(pollSystemHealth, 4000);
}

function showAuthView() {
  document.getElementById('dashboard-view-container').style.display = 'none';
  const authContainer = document.getElementById('auth-view-container');
  authContainer.style.display = 'flex';
  renderAuthPage(async (isDemo) => {
    showDashboardView();
    await loadEnterpriseData();
  });
}

function showDashboardView() {
  document.getElementById('auth-view-container').style.display = 'none';
  document.getElementById('dashboard-view-container').style.display = 'flex';
  updateUserUI();

  const canvas = document.getElementById('topology-canvas');
  if (canvas) {
    initGraphCanvas(canvas, (userId) => {
      selectUser(userId, loadEnterpriseData);
    });
  }

  initModals(loadEnterpriseData);
}

function updateUserUI() {
  const u = state.currentUser;
  if (!u) return;

  const greetingEl = document.getElementById('greeting-user-name');
  if (greetingEl) {
    const firstName = u.name ? u.name.split(' ')[0] : 'Victoria';
    greetingEl.textContent = `Hi, ${firstName}`;
  }

  const nameEl = document.getElementById('current-user-name');
  if (nameEl) nameEl.textContent = u.name;
  const roleEl = document.getElementById('current-user-role-badge');
  if (roleEl) roleEl.textContent = u.role;
  const deptEl = document.getElementById('current-user-dept');
  if (deptEl) deptEl.textContent = u.department;

  const initials = u.name ? u.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() : 'VS';
  const avatarEl = document.getElementById('current-user-avatar');
  if (avatarEl) avatarEl.textContent = initials;
}

function updateMetricsRibbon(summary) {
  if (!summary) return;
  const total = document.getElementById('metric-total-users');
  if (total) total.textContent = summary.total_users || 0;
  const outliers = document.getElementById('metric-outliers');
  if (outliers) outliers.textContent = summary.outliers_detected || 0;
  const highRisk = document.getElementById('metric-high-risk');
  if (highRisk) highRisk.textContent = summary.high_risk_users || 0;

  const pct = summary.total_users > 0 
    ? Math.round((summary.clean_users / summary.total_users) * 100) 
    : 100;
  const cleanPct = document.getElementById('metric-clean-pct');
  if (cleanPct) cleanPct.textContent = `${pct}% Zero-Trust Compliant`;

  const branchCount = document.getElementById('metric-branches-count');
  if (branchCount) branchCount.textContent = `Across ${state.branches.length || 5} Global Branches`;
}

export async function loadEnterpriseData() {
  try {
    // 1. Branches
    const branchesData = await api.getBranches();
    state.branches = branchesData.branches || [];

    const branchSelect = document.getElementById('branch-select');
    if (branchSelect) {
      branchSelect.innerHTML = '<option value="all">🌐 Global Enterprise (All Branches)</option>';
      state.branches.forEach(b => {
        const opt = document.createElement('option');
        opt.value = b.branch;
        opt.textContent = `${b.branch} (${b.total_employees} staff, ${b.outliers_detected} outliers)`;
        branchSelect.appendChild(opt);
      });
      branchSelect.value = state.selectedBranch;
    }

    // Populate modal branch selectors
    ['csv-branch-select', 'new-emp-branch'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.innerHTML = '';
        state.branches.forEach(b => {
          const opt = document.createElement('option');
          opt.value = b.branch;
          opt.textContent = b.branch;
          el.appendChild(opt);
        });
      }
    });

    // 2. Users
    const usersData = await api.getUsers(state.selectedBranch);
    state.users = usersData.users || [];
    state.summary = usersData.summary || {};
    state.availableRoles = usersData.available_roles || [];
    state.availableBranches = usersData.available_branches || [];

    updateMetricsRibbon(usersData.summary);
    updateOnboardingBanner(loadEnterpriseData);
    renderRosterTable((userId) => selectUser(userId, loadEnterpriseData));
    populateRoleDropdowns();

    // 3. Topology
    const topoData = await api.getTopology(state.selectedBranch);
    loadTopologyData(topoData.nodes || [], topoData.links || []);

    const scopeBadge = document.getElementById('graph-scope-badge');
    if (scopeBadge) {
      scopeBadge.textContent = state.selectedBranch === 'all'
        ? 'Global Enterprise'
        : state.selectedBranch;
    }
    const nodesCount = document.getElementById('graph-nodes-count');
    if (nodesCount) {
      nodesCount.textContent = `${(topoData.nodes || []).length} Nodes`;
    }

    // 4. Default user selection (e.g. Bob Vance in demo or first user)
    if (state.users.length > 0) {
      if (!state.selectedUserId || !state.users.some(u => u.id === state.selectedUserId)) {
        const bob = state.users.find(u => u.name && u.name.includes("Bob Vance"));
        selectUser(bob ? bob.id : state.users[0].id, loadEnterpriseData);
      } else {
        selectUser(state.selectedUserId, loadEnterpriseData);
      }
    } else {
      selectUser(null);
    }

    await pollSystemHealth();
  } catch (err) {
    console.error("Failed to load enterprise data:", err);
  }
}

function populateRoleDropdowns() {
  const roles = state.availableRoles || [];

  // Table filter
  const tableFilter = document.getElementById('table-filter-role');
  if (tableFilter && tableFilter.options.length <= 1) {
    roles.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r;
      opt.textContent = r;
      tableFilter.appendChild(opt);
    });
  }

  // Modals
  const simRole = document.getElementById('sim-modal-role-select');
  const simUser = document.getElementById('sim-modal-user-select');
  const newRole = document.getElementById('new-emp-role');

  if (simRole) {
    simRole.innerHTML = '';
    roles.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r;
      opt.textContent = r;
      simRole.appendChild(opt);
    });
  }

  if (simUser) {
    simUser.innerHTML = '';
    state.users.forEach(u => {
      const opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = `${u.name} (${u.role})`;
      simUser.appendChild(opt);
    });
  }

  if (newRole) {
    newRole.innerHTML = '';
    roles.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r;
      opt.textContent = r;
      newRole.appendChild(opt);
    });
  }

  // Permissions checkbox grid
  const permGrid = document.getElementById('new-emp-perms-grid');
  if (permGrid && permGrid.children.length === 0) {
    state.standardPermissions.forEach(p => {
      const label = document.createElement('label');
      label.className = `perm-cb-label ${p.critical ? 'critical' : ''}`;
      label.innerHTML = `
        <input type="checkbox" name="emp-permission" value="${p.id}" />
        <span>${p.name} ${p.critical ? '⚠️' : ''}</span>
      `;
      permGrid.appendChild(label);
    });
  }
}

async function pollSystemHealth() {
  try {
    const health = await api.getHealth();
    const ramEl = document.getElementById('ram-usage-text');
    if (ramEl) ramEl.textContent = `${health.memory_rss_mb} MB`;
    const cryptoEl = document.getElementById('crypto-mode-text');
    if (cryptoEl) cryptoEl.textContent = health.crypto_mode;
  } catch (e) {}
}

function setupGlobalEventListeners() {
  // Sign Out
  const handleSignOut = () => {
    signOut(async (isDemo) => {
      showDashboardView();
      await loadEnterpriseData();
    });
  };
  document.getElementById('btn-header-signout')?.addEventListener('click', handleSignOut);
  document.getElementById('btn-rail-signout')?.addEventListener('click', handleSignOut);

  // Branch selector menu
  document.getElementById('branch-select')?.addEventListener('change', (e) => {
    state.selectedBranch = e.target.value;
    loadEnterpriseData();
    showToast(`Switched view to branch: ${e.target.value}`, 'info');
  });

  // Switch to demo dataset button
  document.getElementById('btn-switch-demo')?.addEventListener('click', async () => {
    try {
      await api.loadDemoWorkspace();
      state.isDemoWorkspace = true;
      showToast("Enterprise demo dataset loaded!", "success");
      await loadEnterpriseData();
    } catch (err) {
      showToast(`Error: ${err.message}`, "error");
    }
  });

  // Ingest Modal & Staff buttons
  document.getElementById('btn-open-ingest-modal')?.addEventListener('click', () => {
    openModal('ingest-modal');
    document.getElementById('modal-tab-csv')?.click();
  });
  document.getElementById('btn-quick-add-staff')?.addEventListener('click', () => {
    openModal('ingest-modal');
    document.getElementById('modal-tab-manual')?.click();
  });

  // Top Pastel Card actions
  document.getElementById('btn-card-inspect')?.addEventListener('click', () => {
    const outlier = state.users.find(u => u.is_outlier || u.risk_score >= 70);
    if (outlier) {
      selectUser(outlier.id, loadEnterpriseData);
      showToast(`Inspecting critical drift for ${outlier.name}`, 'info');
    }
  });

  document.getElementById('btn-card-roster')?.addEventListener('click', () => {
    document.getElementById('table-card-section')?.scrollIntoView({ behavior: 'smooth' });
  });

  document.getElementById('btn-card-remediate')?.addEventListener('click', () => {
    executeRemediation(loadEnterpriseData);
  });

  // Right Inspector Profile buttons
  document.getElementById('btn-profile-remediate')?.addEventListener('click', () => {
    executeRemediation(loadEnterpriseData);
  });
  document.getElementById('btn-remediate-now')?.addEventListener('click', () => {
    executeRemediation(loadEnterpriseData);
  });
  // Player Waveform Buttons
  document.getElementById('btn-player-play')?.addEventListener('click', () => {
    executeRemediation(loadEnterpriseData);
  });
  document.getElementById('btn-player-forward')?.addEventListener('click', () => {
    openModal('simulator-modal');
    const simUserSelect = document.getElementById('sim-modal-user-select');
    if (simUserSelect && state.selectedUserId) simUserSelect.value = state.selectedUserId;
    showToast('Select promotion target for employee', 'info');
  });
  document.getElementById('btn-player-rewind')?.addEventListener('click', () => {
    if (state.selectedUserId) {
      selectUser(state.selectedUserId, loadEnterpriseData);
      showToast('Reset view for selected employee', 'info');
    }
  });

  // Table Select All Checkbox
  document.getElementById('select-all-checkbox')?.addEventListener('change', (e) => {
    const isChecked = e.target.checked;
    document.querySelectorAll('.table-checkbox').forEach(cb => cb.checked = isChecked);
  });

  document.getElementById('btn-profile-star')?.addEventListener('click', () => {
    showToast('Employee bookmarked for periodic governance review', 'success');
  });
  document.getElementById('btn-profile-explain')?.addEventListener('click', () => {
    showToast('Explainable AI: Isolation Forest τ = 0.055, 12 IAM features analyzed', 'info');
  });

  // Notifications Pill
  document.getElementById('btn-notifications-pill')?.addEventListener('click', () => {
    showToast(`System active: ${state.summary.outliers_detected || 0} drift alerts detected across ${state.branches.length} branches.`, 'info');
  });

  // Dual Policy tabs
  document.getElementById('tab-btn-aws')?.addEventListener('click', () => {
    state.policyTab = 'aws';
    document.getElementById('tab-btn-aws').classList.add('active');
    document.getElementById('tab-btn-racf').classList.remove('active');
    renderPolicyCode();
  });

  document.getElementById('tab-btn-racf')?.addEventListener('click', () => {
    state.policyTab = 'racf';
    document.getElementById('tab-btn-racf').classList.add('active');
    document.getElementById('tab-btn-aws').classList.remove('active');
    renderPolicyCode();
  });

  document.getElementById('btn-copy-policy')?.addEventListener('click', () => {
    const code = document.getElementById('policy-code-block').textContent;
    if (code) {
      navigator.clipboard.writeText(code);
      showToast(`${state.policyTab === 'aws' ? 'AWS IAM JSON' : 'IBM RACF Commands'} copied to clipboard!`, 'info');
    }
  });

  // View switch (Graph vs Table)
  document.getElementById('tab-view-graph')?.addEventListener('click', () => {
    state.activeView = 'graph';
    document.getElementById('tab-view-graph').classList.add('active');
    document.getElementById('tab-view-table').classList.remove('active');
    document.getElementById('graph-view-container').style.display = 'block';
    drawFrame();
  });

  document.getElementById('tab-view-table')?.addEventListener('click', () => {
    document.getElementById('table-card-section')?.scrollIntoView({ behavior: 'smooth' });
  });

  // Canvas Viewport Controls
  document.getElementById('btn-reset-zoom')?.addEventListener('click', () => {
    state.scale = 1.0;
    state.panX = 0;
    state.panY = 0;
    drawFrame();
  });

  document.getElementById('btn-toggle-physics')?.addEventListener('click', (e) => {
    state.isPhysicsFrozen = !state.isPhysicsFrozen;
    e.target.textContent = state.isPhysicsFrozen ? '▶ Resume' : '⏸ Pause';
    if (!state.isPhysicsFrozen) drawFrame();
  });

  // Search input
  document.getElementById('node-search-input')?.addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderRosterTable((userId) => selectUser(userId, loadEnterpriseData));
    drawFrame();
  });

  // Table filters
  document.getElementById('table-filter-role')?.addEventListener('change', (e) => {
    state.tableFilterRole = e.target.value;
    renderRosterTable((userId) => selectUser(userId, loadEnterpriseData));
  });

  document.getElementById('table-filter-risk')?.addEventListener('change', (e) => {
    state.tableFilterRisk = e.target.value;
    renderRosterTable((userId) => selectUser(userId, loadEnterpriseData));
  });

  // Left Rail Navigation Buttons
  document.getElementById('rail-btn-overview')?.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
  document.getElementById('rail-btn-graph')?.addEventListener('click', () => {
    document.getElementById('graph-view-container')?.scrollIntoView({ behavior: 'smooth' });
  });
  document.getElementById('rail-btn-roster')?.addEventListener('click', () => {
    document.getElementById('table-card-section')?.scrollIntoView({ behavior: 'smooth' });
  });
  document.getElementById('rail-btn-ledger')?.addEventListener('click', () => {
    openModal('ledger-modal');
    loadLedgerBlocks();
  });
  document.getElementById('rail-btn-telemetry')?.addEventListener('click', async () => {
    try {
      const health = await api.getHealth();
      showToast(`IBM Z Status: ${health.status} &bull; RAM: ${health.memory_rss_mb} MB / 4GB &bull; ${health.crypto_mode}`, 'info');
    } catch (e) {
      showToast('Telemetry probe running...', 'info');
    }
  });

  // Global Drag & Drop CSV onto window
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const isCsv = file.name.toLowerCase().endsWith('.csv') || file.type.includes('csv') || file.type.includes('text');
      if (isCsv) {
        openModal('ingest-modal');
        const fileInput = document.getElementById('csv-file-input');
        if (fileInput) {
          const dt = new DataTransfer();
          dt.items.add(file);
          fileInput.files = dt.files;
          fileInput.dispatchEvent(new Event('change'));
        }
      }
    }
  });
}

document.addEventListener('DOMContentLoaded', init);
