/**
 * Modal Dialogs & Ingestion Controller (CSV, Manual Add, Simulator, Audit Ledger)
 */
import { state } from '../state.js';
import { api } from '../api.js';
import { showToast, escapeHtml } from './toast.js';

let onDataChangeCallback = null;

export function initModals(onDataChange) {
  onDataChangeCallback = onDataChange;

  setupCloseButtons();
  setupCsvUpload();
  setupAddEmployeeForm();
  setupSimulatorForm();
  setupLedgerModal();
}

export function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'flex';
}

export function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'none';
}

function setupCloseButtons() {
  document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
  });

  document.querySelectorAll('.modal-overlay').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
    });
  });
}

function setupCsvUpload() {
  const dropZone = document.getElementById('csv-drop-zone');
  const fileInput = document.getElementById('csv-file-input');
  const filenameDisplay = document.getElementById('csv-selected-filename');
  const submitBtn = document.getElementById('btn-submit-csv-upload');
  const btnBrowse = document.getElementById('btn-browse-csv');

  let selectedFile = null;

  btnBrowse?.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropZone?.addEventListener('click', () => fileInput.click());

  dropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

  dropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      handleFile(fileInput.files[0]);
    }
  });

  function handleFile(file) {
    if (!file) return;
    const nameLower = file.name.toLowerCase();
    const isCsv = nameLower.endsWith('.csv') ||
                  file.type.includes('csv') ||
                  file.type.includes('excel') ||
                  file.type.includes('text/plain') ||
                  nameLower.endsWith('.txt');
                  
    if (!isCsv) {
      showToast('Please select a valid CSV file (.csv)', 'error');
      return;
    }
    selectedFile = file;
    
    // Read first few lines to give immediate row count preview
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target.result;
        const validLines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
        const recordEst = Math.max(0, validLines.length - 1);
        filenameDisplay.innerHTML = `<strong>${escapeHtml(file.name)}</strong> <span style="color:#0284C7;">(${(file.size / 1024).toFixed(1)} KB &bull; ~${recordEst} records detected)</span>`;
      } catch (err) {
        filenameDisplay.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      }
      submitBtn.disabled = false;
      showToast(`Ready to ingest: ${file.name}`, 'info');
    };
    reader.readAsText(file.slice(0, 50000)); // preview sample
  }

  submitBtn?.addEventListener('click', async () => {
    if (!selectedFile) return;

    submitBtn.disabled = true;
    submitBtn.textContent = 'Parsing & ML Scoring...';

    const branch = document.getElementById('csv-branch-select') ? document.getElementById('csv-branch-select').value : null;
    const modeEl = document.querySelector('input[name="csv-mode"]:checked');
    const replaceRoster = modeEl ? modeEl.value === 'replace' : false;

    const formData = new FormData();
    formData.append('file', selectedFile);
    if (branch && branch !== 'all') formData.append('branch', branch);
    formData.append('replace_roster', replaceRoster);

    try {
      const result = await api.uploadCsv(formData);
      showToast(`Ingested ${result.records_processed} employee records! Detected ${result.outliers_detected} outliers.`, 'success');
      closeModal('ingest-modal');
      selectedFile = null;
      if (onDataChangeCallback) onDataChangeCallback();
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Upload & Score Roster';
    }
  });

  // Template download
  const dlTemplate = () => { window.location.href = '/api/v1/roster/csv-template'; };
  document.getElementById('btn-download-csv-template')?.addEventListener('click', dlTemplate);
  document.getElementById('btn-modal-dl-template')?.addEventListener('click', dlTemplate);
}

function setupAddEmployeeForm() {
  const form = document.getElementById('add-employee-form');
  const roleSelect = document.getElementById('new-emp-role');
  const deptInput = document.getElementById('new-emp-dept');

  roleSelect?.addEventListener('change', () => {
    const role = roleSelect.value;
    if (role.includes('Engineer')) deptInput.value = 'Engineering';
    else if (role.includes('DevOps') || role.includes('Site Reliability')) deptInput.value = 'DevOps';
    else if (role.includes('Finance') || role.includes('Payroll')) deptInput.value = 'Finance';
    else if (role.includes('HR') || role.includes('People')) deptInput.value = 'HR';
  });

  document.getElementById('btn-set-baseline-perms')?.addEventListener('click', () => {
    const role = roleSelect.value;
    const checkboxes = document.querySelectorAll('input[name="emp-permission"]');
    checkboxes.forEach(cb => cb.checked = false);

    const baselines = {
      "Engineering Manager": ["jira:admin", "github:repo_write", "code:review", "db:read", "s3:read"],
      "Senior Software Engineer": ["github:repo_write", "code:review", "db:read", "s3:read", "k8s:namespace_read"],
      "Frontend Engineer": ["github:repo_write", "code:review", "s3:read"],
      "DevOps Engineer": ["k8s:admin", "prod:deploy", "s3:backup_write", "cloud:iam_admin", "k8s:namespace_read", "github:repo_write"],
      "Financial Analyst": ["finance:reports_read", "finance:gl_write", "s3:read"],
      "HR Generalist": ["hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "s3:read"]
    };

    const target = baselines[role] || ["github:repo_write", "code:review", "s3:read"];
    checkboxes.forEach(cb => { if (target.includes(cb.value)) cb.checked = true; });
  });

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('new-emp-id').value.trim();
    const name = document.getElementById('new-emp-name').value.trim();
    const role = roleSelect.value;
    const dept = deptInput.value.trim();
    const branch = document.getElementById('new-emp-branch').value;
    const checked = Array.from(document.querySelectorAll('input[name="emp-permission"]:checked')).map(cb => cb.value);

    try {
      await api.addEmployee({
        id,
        name,
        role,
        department: dept,
        branch,
        permissions: checked
      });

      closeModal('ingest-modal');
      showToast(`Employee ${name} registered & scored!`, 'success');
      form.reset();
      state.selectedUserId = id;

      if (onDataChangeCallback) onDataChangeCallback();
    } catch (err) {
      showToast(`Add employee failed: ${err.message}`, 'error');
    }
  });
}

function setupSimulatorForm() {
  const form = document.getElementById('sim-modal-form') || document.getElementById('simulator-form');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const userSelect = document.getElementById('sim-modal-user-select');
    const roleSelect = document.getElementById('sim-modal-role-select');
    const deptInput = document.getElementById('sim-modal-dept-input');
    const btn = document.getElementById('btn-modal-run-sim') || form.querySelector('button[type="submit"]');

    if (!userSelect || !roleSelect) return;
    const userId = userSelect.value;
    const newRole = roleSelect.value;
    const newDept = deptInput ? deptInput.value : '';

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Simulating Transition...';
    }

    try {
      const data = await api.simulateRoleChange(userId, newRole, newDept);
      closeModal('simulator-modal');
      showToast(`Simulated promotion: ${data.message}`, 'warning');
      state.selectedUserId = userId;
      if (onDataChangeCallback) onDataChangeCallback();
    } catch (err) {
      showToast(`Simulation failed: ${err.message}`, 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '⚡ Simulate Promotion';
      }
    }
  });
}

function setupLedgerModal() {
  document.getElementById('btn-refresh-ledger')?.addEventListener('click', loadLedgerBlocks);
}

export async function loadLedgerBlocks() {
  try {
    const data = await api.getAuditLedger();
    const countEl = document.getElementById('ledger-total-blocks') || document.getElementById('modal-ledger-total-blocks');
    if (countEl) countEl.textContent = `${data.total_blocks} Verified Blocks`;

    const modeEl = document.getElementById('ledger-crypto-mode') || document.getElementById('modal-ledger-crypto-mode');
    if (modeEl) modeEl.textContent = data.crypto_mode;

    const container = document.getElementById('ledger-blocks-container');
    const tbody = document.getElementById('ledger-table-body');

    if (container) {
      container.innerHTML = '';
      [...data.ledger].reverse().forEach(block => {
        const timeStr = new Date(block.timestamp * 1000).toLocaleTimeString();
        const detailsStr = typeof block.details === 'object' ? JSON.stringify(block.details) : String(block.details);
        const card = document.createElement('div');
        card.style.cssText = 'background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 12px; padding: 12px 14px; font-size: 11.5px; display: flex; flex-direction: column; gap: 4px;';
        card.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; gap: 8px; align-items: center;">
              <span style="font-weight: 800; color: #0284C7; font-family: var(--font-mono);">#${block.index}</span>
              <strong style="color: #1E2024;">${escapeHtml(block.action)}</strong>
              <span style="background: #E2E8F0; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: 600;">${escapeHtml(block.actor)}</span>
            </div>
            <span style="font-size: 10px; color: #64748B;">${timeStr}</span>
          </div>
          <div style="color: #475569; font-size: 11px; font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(detailsStr)}">
            ${escapeHtml(detailsStr)}
          </div>
          <div style="font-size: 9.5px; font-family: var(--font-mono); color: #94A3B8; margin-top: 2px;">
            SHA-256 Hash: <span style="color: #0284C7;">${block.block_hash}</span>
          </div>
        `;
        container.appendChild(card);
      });
    } else if (tbody) {
      tbody.innerHTML = '';
      [...data.ledger].reverse().forEach(block => {
        const tr = document.createElement('tr');
        const timeStr = new Date(block.timestamp * 1000).toLocaleString();
        const detailsStr = typeof block.details === 'object' ? JSON.stringify(block.details) : String(block.details);
        tr.innerHTML = `
          <td style="font-weight: 700; color: #0284C7;">#${block.index}</td>
          <td>${timeStr}</td>
          <td><strong>${escapeHtml(block.action)}</strong></td>
          <td><span>${escapeHtml(block.actor)}</span></td>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(detailsStr)}</td>
          <td><span style="font-family: var(--font-mono); font-size: 10px; color: #0284C7;">${block.block_hash.substring(0, 18)}...</span></td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Ledger load error:", err);
  }
}
