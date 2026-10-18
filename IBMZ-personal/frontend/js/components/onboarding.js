/**
 * Blank Workspace Guided Onboarding Component
 * Enables new enterprise users to configure their regional branch and input employees.
 */
import { state } from '../state.js';
import { api } from '../api.js';
import { showToast } from './toast.js';

export function updateOnboardingBanner(onDataChange) {
  const bannerContainer = document.getElementById('blank-workspace-banner');
  if (!bannerContainer) return;

  const isBlank = state.users.length === 0;

  if (isBlank) {
    bannerContainer.style.display = 'flex';
    bannerContainer.innerHTML = `
      <div class="banner-lead">
        <span style="font-size: 16px;">🚀</span>
        <div>
          <strong>Blank Enterprise Workspace Initialized:</strong>
          <span>Please define your enterprise branch and input your first employee profile below.</span>
        </div>
      </div>
      <div class="banner-actions">
        <button class="btn btn-outline btn-xs" id="btn-onboard-add-branch">+ Add Branch</button>
        <button class="btn btn-primary btn-xs" id="btn-onboard-add-emp">+ Add First Employee</button>
        <button class="btn btn-warning btn-xs" id="btn-onboard-load-demo">Switch to Demo Data</button>
      </div>
    `;

    document.getElementById('btn-onboard-add-branch').addEventListener('click', () => {
      promptAddBranch(onDataChange);
    });

    document.getElementById('btn-onboard-add-emp').addEventListener('click', () => {
      const modal = document.getElementById('ingest-modal');
      if (modal) {
        modal.style.display = 'flex';
        // Switch to manual add tab
        document.getElementById('modal-tab-manual').click();
      }
    });

    document.getElementById('btn-onboard-load-demo').addEventListener('click', async () => {
      try {
        await api.loadDemoWorkspace();
        state.isDemoWorkspace = true;
        showToast("Switched to enterprise demo dataset!", "success");
        if (onDataChange) onDataChange();
      } catch (err) {
        showToast(`Failed to load demo: ${err.message}`, "error");
      }
    });
  } else {
    bannerContainer.style.display = 'none';
  }
}

export async function promptAddBranch(onSuccess) {
  const branchName = prompt("Enter Name of New Enterprise Branch Location (e.g. 'Austin Cyber Operations Center'):");
  if (!branchName || !branchName.trim()) return;

  try {
    const res = await api.addBranch(branchName.trim());
    showToast(`Added branch: ${res.branch}`, "success");
    if (onSuccess) onSuccess();
  } catch (err) {
    showToast(`Failed to add branch: ${err.message}`, "error");
  }
}
