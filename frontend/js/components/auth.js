/**
 * Google-Style Enterprise Sign-In Component
 */
import { state } from '../state.js';
import { api } from '../api.js';
import { showToast, escapeHtml } from './toast.js';

let savedOnAuthSuccess = null;

export function renderAuthPage(onAuthSuccess) {
  if (onAuthSuccess) savedOnAuthSuccess = onAuthSuccess;
  const container = document.getElementById('auth-view-container');
  if (!container) return;

  container.innerHTML = `
    <div class="auth-page-wrapper">
      <div class="google-auth-card">
        <div class="auth-header">
          <div class="auth-logo-badge">AD</div>
          <h2 class="auth-title">Sign in</h2>
          <p class="auth-subtitle">to continue to AccessDrift Zero-Trust IAM</p>
        </div>

        <!-- Quick-Fill Demo Chip -->
        <div class="demo-credentials-banner" id="btn-demo-quickfill" title="Click to prefill Demo CEO account">
          <div class="demo-banner-left">
            <span class="demo-banner-icon">👑</span>
            <div class="demo-banner-text">
              <span class="demo-banner-title">Presentation Demo Account</span>
              <span class="demo-banner-creds">user: trail_demo_ceo &bull; pass: trail_demo</span>
            </div>
          </div>
          <button type="button" class="demo-fill-btn">1-Click Fill</button>
        </div>

        <!-- Form -->
        <form id="google-auth-form" class="auth-form">
          <div class="google-input-group">
            <input type="text" id="auth-username" required placeholder=" " autocomplete="username" />
            <label for="auth-username">Enterprise User ID or Email</label>
          </div>

          <div class="google-input-group">
            <input type="password" id="auth-password" required placeholder=" " autocomplete="current-password" />
            <label for="auth-password">Password</label>
            <button type="button" class="password-toggle-btn" id="btn-toggle-pw" title="Show/hide password">👁️</button>
          </div>

          <p class="auth-note">
            Enter <strong>trail_demo_ceo</strong> to load full demo governance dataset.<br />
            Any other login initializes your <strong>fresh blank enterprise workspace</strong>.
          </p>

          <div class="auth-actions-row">
            <a href="#" class="auth-help-link" id="btn-custom-workspace-hint">How it works</a>
            <button type="submit" class="btn-google-signin" id="btn-auth-submit">
              <span>Sign in</span>
              <span class="arrow">&rarr;</span>
            </button>
          </div>
        </form>
      </div>

      <div class="auth-footer">
        <span>IBM Z Datathon Submission &bull; Zero-Trust CPACF</span>
        <div>
          <a href="#">Help</a>
          <a href="#">Privacy</a>
          <a href="#">Terms</a>
        </div>
      </div>
    </div>
  `;

  const form = document.getElementById('google-auth-form');
  const usernameInput = document.getElementById('auth-username');
  const passwordInput = document.getElementById('auth-password');
  const quickFillBtn = document.getElementById('btn-demo-quickfill');
  const togglePwBtn = document.getElementById('btn-toggle-pw');
  const submitBtn = document.getElementById('btn-auth-submit');

  // Quick fill button
  quickFillBtn.addEventListener('click', () => {
    usernameInput.value = 'trail_demo_ceo';
    passwordInput.value = 'trail_demo';
    usernameInput.focus();
    showToast("Filled demo credentials (trail_demo_ceo)", "info");
  });

  // Password toggle
  togglePwBtn.addEventListener('click', () => {
    const isPw = passwordInput.type === 'password';
    passwordInput.type = isPw ? 'text' : 'password';
    togglePwBtn.textContent = isPw ? '🔒' : '👁️';
  });

  document.getElementById('btn-custom-workspace-hint').addEventListener('click', (e) => {
    e.preventDefault();
    showToast("Input any custom username and password to create a blank workspace where you can input your own branch & employees!", "info", 5000);
  });

  // Submit Handler
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>Signing in...</span>`;

    try {
      const data = await api.login(username, password);
      state.token = data.access_token;
      state.currentUser = data.user;
      state.isAuthenticated = true;
      state.isDemoWorkspace = (username === 'trail_demo_ceo');
      localStorage.setItem('accessdrift_token', data.access_token);

      container.style.display = 'none';
      document.getElementById('dashboard-view-container').style.display = 'flex';

      showToast(`Welcome, ${data.user.name}! ${state.isDemoWorkspace ? 'Loaded Demo Dataset.' : 'Loaded Fresh Blank Workspace.'}`, "success");

      if (onAuthSuccess) onAuthSuccess(state.isDemoWorkspace);
    } catch (err) {
      showToast(`Authentication failed: ${err.message}`, "error");
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>Sign in</span><span class="arrow">&rarr;</span>`;
    }
  });
}

export function signOut(onAuthSuccess) {
  state.token = null;
  state.currentUser = null;
  state.isAuthenticated = false;
  state.selectedUserId = null;
  localStorage.removeItem('accessdrift_token');

  document.getElementById('dashboard-view-container').style.display = 'none';
  const container = document.getElementById('auth-view-container');
  container.style.display = 'flex';
  renderAuthPage(onAuthSuccess || savedOnAuthSuccess);
  showToast("Signed out of AccessDrift", "info");
}
