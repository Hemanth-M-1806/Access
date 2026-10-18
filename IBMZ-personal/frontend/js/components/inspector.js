/**
 * Identity Inspector & Explainable AI (XAI) Component
 * Styled to match the right profile and call-recording waveform panel in the mockup
 */
import { state } from '../state.js';
import { api } from '../api.js';
import { showToast, escapeHtml } from './toast.js';
import { drawFrame } from './graph.js';

export function selectUser(userId, onDataRefresh) {
  state.selectedUserId = userId;
  const user = state.users.find(u => u.id === userId);

  const emptyState = document.getElementById('no-user-selected');
  const userContent = document.getElementById('user-selected-content');

  if (!user) {
    if (emptyState) emptyState.style.display = 'flex';
    if (userContent) userContent.style.display = 'none';
    drawFrame();
    return;
  }

  if (emptyState) emptyState.style.display = 'none';
  if (userContent) userContent.style.display = 'flex';

  // 1. Profile Avatar & Name
  const avatarEl = document.getElementById('inspector-avatar-text');
  if (avatarEl) {
    const initials = user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
    avatarEl.textContent = initials;
  }

  document.getElementById('u-name').textContent = user.name;
  const roleEl = document.getElementById('u-role-dept');
  if (roleEl) {
    if (user.is_outlier || user.risk_score >= 70) {
      roleEl.innerHTML = `<span style="color: #EF4444; font-weight: 700;">⚠️ ${escapeHtml(user.role)} &bull; Drift Detected</span>`;
    } else {
      roleEl.innerHTML = `<span style="color: #10B981; font-weight: 600;">✓ ${escapeHtml(user.role)} &bull; Compliant</span>`;
    }
  }

  // 2. Chat / Timeline Drift Summary (Matching Mockup's Summarize section)
  const chatList = document.getElementById('drift-chat-list');
  if (chatList) {
    chatList.innerHTML = '';
    const driftList = user.drift_permissions || [];

    if (driftList.length === 0) {
      chatList.innerHTML = `
        <div class="drift-chat-item">
          <span class="chat-time-stamp">1:00</span>
          <div class="chat-avatar-mini" style="background: #D1FAE5; color: #065F46;">🛡️</div>
          <div class="chat-message-content">
            <span class="chat-author-label">Zero-Trust Evaluator:</span>
            <span class="chat-text-body">All permissions strictly align with the ${escapeHtml(user.role)} normative baseline. No privilege drift detected.</span>
          </div>
        </div>
      `;
    } else {
      // Message 1: Privilege Creep
      const historyStr = user.role_history && user.role_history.length > 1
        ? `Retained legacy privileges from previous role as ${user.role_history[0]}.`
        : 'Accumulated permissions that diverge from normative peer baseline.';

      chatList.innerHTML += `
        <div class="drift-chat-item">
          <span class="chat-time-stamp">1:12</span>
          <div class="chat-avatar-mini" style="background: #FEE2E2; color: #991B1B;">⚠️</div>
          <div class="chat-message-content">
            <span class="chat-author-label">Privilege Creep:</span>
            <span class="chat-text-body">${escapeHtml(historyStr)} (${driftList.length} toxic entitlements).</span>
          </div>
        </div>
      `;

      // Message 2: Critical Admin Entitlements
      const criticalDrift = driftList.filter(p => p.includes('admin') || p.includes('root') || p.includes('deploy'));
      if (criticalDrift.length > 0) {
        chatList.innerHTML += `
          <div class="drift-chat-item">
            <span class="chat-time-stamp">1:31</span>
            <div class="chat-avatar-mini" style="background: #FEF3C7; color: #92400E;">🔑</div>
            <div class="chat-message-content">
              <span class="chat-author-label">High-Risk Admin:</span>
              <span class="chat-text-body">Holds unauthorized superuser access: <code>${escapeHtml(criticalDrift.join(', '))}</code>.</span>
            </div>
          </div>
        `;
      }

      // Message 3: Cross-Department Entitlements
      chatList.innerHTML += `
        <div class="drift-chat-item">
          <span class="chat-time-stamp">2:11</span>
          <div class="chat-avatar-mini" style="background: #E0F2FE; color: #075985;">🏢</div>
          <div class="chat-message-content">
            <span class="chat-author-label">Governance Mandate:</span>
            <span class="chat-text-body">1-Click Dual Remediation recommended to synthesize AWS IAM JSON & IBM Z RACF prunes.</span>
          </div>
        </div>
      `;
    }
  }

  // 3. Waveform Scrubber & Remediation Widget
  const needle = document.getElementById('waveform-needle');
  const scorePercent = Math.min(100, Math.max(5, user.risk_score || 10));
  if (needle) {
    needle.style.left = `${scorePercent}%`;
  }
  const needleTime = document.getElementById('waveform-time-label');
  if (needleTime) {
    needleTime.style.left = `${scorePercent}%`;
    needleTime.textContent = `00:${String(user.risk_score || 0).padStart(2, '0')}`;
  }

  const remediateBtn = document.getElementById('btn-remediate-now');
  if (remediateBtn) {
    if ((user.drift_permissions || []).length === 0) {
      remediateBtn.disabled = true;
      remediateBtn.textContent = '✓ Already Least-Privileged';
      remediateBtn.style.background = '#10B981';
    } else {
      remediateBtn.disabled = false;
      remediateBtn.textContent = `🛡️ 1-Click Remediate (${user.drift_permissions.length} Drift)`;
      remediateBtn.style.background = '#EF4444';
    }
  }

  // Dual Policy Drawer
  const policySection = document.getElementById('policy-output-section');
  if (state.remediationResult && state.remediationResult.user_id === userId) {
    if (policySection) policySection.style.display = 'block';
    renderPolicyCode();
  } else {
    if (policySection) policySection.style.display = 'none';
  }

  drawFrame();
}

export async function executeRemediation(onSuccess) {
  if (!state.selectedUserId) return;
  const targetId = state.selectedUserId;
  const user = state.users.find(u => u.id === targetId);

  const btn = document.getElementById('btn-remediate-now');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Pruning Privileges & Synthesizing...';
  }

  try {
    const result = await api.remediate(targetId, true);
    state.remediationResult = result;

    if (window.confetti) {
      window.confetti({ particleCount: 50, spread: 60, origin: { y: 0.6 } });
    }

    showToast(`Remediated privilege creep for ${user ? user.name : targetId}!`, 'success');

    if (user) {
      user.risk_score = result.new_risk_score;
      user.drift_permissions = [];
      user.is_outlier = false;
      user.permissions = result.retained_permissions;
    }

    const policySection = document.getElementById('policy-output-section');
    if (policySection) policySection.style.display = 'block';
    renderPolicyCode();

    if (onSuccess) onSuccess();
  } catch (err) {
    showToast(`Remediation failed: ${err.message}`, 'error');
  } finally {
    selectUser(targetId);
  }
}

export function renderPolicyCode() {
  if (!state.remediationResult) return;
  const codeBlock = document.getElementById('policy-code-block');
  if (!codeBlock) return;

  if (state.policyTab === 'aws') {
    codeBlock.textContent = JSON.stringify(state.remediationResult.remediated_policy_json, null, 2);
  } else {
    const racf = state.remediationResult.racf_script;
    codeBlock.textContent = Array.isArray(racf) ? racf.join('\n') : String(racf);
  }
}
