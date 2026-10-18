/**
 * Enterprise Roster Directory Data Table Component
 * Styled to match the clean executive layout from the mockup image
 */
import { state } from '../state.js';
import { escapeHtml } from './toast.js';

export function renderRosterTable(onSelectUser) {
  const tbody = document.getElementById('roster-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  const query = (state.searchQuery || '').toLowerCase().trim();
  const filterRole = state.tableFilterRole || 'all';
  const filterRisk = state.tableFilterRisk || 'all';

  const filtered = state.users.filter(u => {
    const matchSearch = !query || (
      u.name.toLowerCase().includes(query) ||
      u.id.toLowerCase().includes(query) ||
      u.role.toLowerCase().includes(query) ||
      u.department.toLowerCase().includes(query)
    );
    const matchRole = filterRole === 'all' || u.role === filterRole;

    let matchRisk = true;
    if (filterRisk === 'critical') matchRisk = u.risk_score >= 75;
    else if (filterRisk === 'warning') matchRisk = u.risk_score >= 40 && u.risk_score < 75;
    else if (filterRisk === 'compliant') matchRisk = u.risk_score < 40;

    return matchSearch && matchRole && matchRisk;
  });

  const countBadge = document.getElementById('table-count-badge');
  if (countBadge) countBadge.textContent = `${filtered.length} Employees`;

  filtered.forEach(u => {
    const tr = document.createElement('tr');
    tr.dataset.userId = u.id;
    if (u.id === state.selectedUserId) tr.classList.add('active-row');

    // Determine type icon/pill
    let typeClass = 'iam';
    let typeIcon = '🔑';
    let typeLabel = 'IAM';
    const rLower = (u.role || '').toLowerCase();
    const dLower = (u.department || '').toLowerCase();

    if (rLower.includes('devops') || rLower.includes('reliability') || dLower.includes('devops')) {
      typeClass = 'devops';
      typeIcon = '🛡️';
      typeLabel = 'DevOps';
    } else if (rLower.includes('engineer') || dLower.includes('engineering')) {
      typeClass = 'engineering';
      typeIcon = '💻';
      typeLabel = 'Eng';
    } else if (rLower.includes('finance') || dLower.includes('finance') || rLower.includes('payroll')) {
      typeClass = 'finance';
      typeIcon = '💰';
      typeLabel = 'Finance';
    } else if (rLower.includes('hr') || dLower.includes('hr') || rLower.includes('people')) {
      typeClass = 'iam';
      typeIcon = '👥';
      typeLabel = 'HR';
    }

    // Status pill
    let statusDot = 'completed';
    let statusLabel = 'Compliant';
    if (u.risk_score >= 75 || u.is_outlier) {
      statusDot = 'failed';
      statusLabel = 'Critical Drift';
    } else if (u.risk_score >= 40) {
      statusDot = 'pending';
      statusLabel = 'Pending Review';
    }

    // Simulated email / phone
    const handle = u.name.toLowerCase().replace(/[^a-z]/g, '.') + '@enterprise.ibm';

    tr.innerHTML = `
      <td style="width: 36px; text-align: center;">
        <input type="checkbox" class="table-checkbox" ${u.id === state.selectedUserId ? 'checked' : ''} onclick="event.stopPropagation()" />
      </td>
      <td>
        <span class="type-badge-pill ${typeClass}">${typeIcon} ${typeLabel}</span>
      </td>
      <td>
        <strong style="color: var(--text-title);">${escapeHtml(u.name)}</strong>
        <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(handle)}</div>
      </td>
      <td>
        <span style="font-weight: 500;">${escapeHtml(u.role)}</span>
        <div style="font-size: 10.5px; color: var(--text-muted);">${escapeHtml(u.branch || 'Global HQ')}</div>
      </td>
      <td>
        <div class="status-pill-cell">
          <span class="status-dot-circle ${statusDot}"></span>
          <span style="color: ${statusDot === 'failed' ? '#EF4444' : (statusDot === 'pending' ? '#D97706' : '#10B981')};">
            ${statusLabel}
          </span>
        </div>
      </td>
      <td style="font-family: var(--font-mono); font-weight: 600; font-size: 11px;">
        ${u.risk_score} / 100
      </td>
      <td style="text-align: right;">
        <button class="action-dots-btn" title="Inspect ${escapeHtml(u.name)}" onclick="event.stopPropagation()">⋮</button>
      </td>
    `;

    tr.addEventListener('click', () => {
      if (onSelectUser) onSelectUser(u.id);
    });

    tbody.appendChild(tr);
  });
}
