/**
 * ============================================================================
 * WALKTHROUGH ENGINE
 * Lightweight vanilla JS guided tour for the admin dashboard
 * ============================================================================
 */

class Walkthrough {
  constructor(steps) {
    this.steps = steps;
    this.currentStep = 0;
    this.overlay = null;
    this.tooltip = null;
    this.active = false;
  }

  start() {
    if (this.active) return;
    this.active = true;
    this.currentStep = 0;
    this.createOverlay();
    this.showStep(0);
  }

  createOverlay() {
    // Overlay
    this.overlay = document.createElement('div');
    this.overlay.id = 'wt-overlay';
    Object.assign(this.overlay.style, {
      position: 'fixed', inset: '0', zIndex: '9998',
      background: 'rgba(0,0,0,0.4)', transition: 'opacity 0.2s'
    });
    this.overlay.addEventListener('click', () => this.dismiss());

    // Tooltip container
    this.tooltip = document.createElement('div');
    this.tooltip.id = 'wt-tooltip';
    Object.assign(this.tooltip.style, {
      position: 'fixed', zIndex: '10000', background: 'white',
      borderRadius: '12px', padding: '1.25rem', maxWidth: '360px',
      boxShadow: '0 8px 30px rgba(0,0,0,0.2)', fontSize: '0.9rem',
      lineHeight: '1.5', transition: 'opacity 0.2s, transform 0.2s'
    });

    document.body.appendChild(this.overlay);
    document.body.appendChild(this.tooltip);
  }

  showStep(index) {
    if (index < 0 || index >= this.steps.length) {
      this.dismiss();
      return;
    }

    this.currentStep = index;
    const step = this.steps[index];

    // Find target element
    const target = document.querySelector(step.selector);

    if (target) {
      // Scroll into view
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });

      // Highlight target by raising it above overlay
      target.style.position = target.style.position || 'relative';
      target.style.zIndex = '9999';
      target.style.boxShadow = '0 0 0 4px rgba(30, 82, 136, 0.6)';
      target.style.borderRadius = '8px';
      target.dataset.wtHighlighted = 'true';

      // Position tooltip near target
      requestAnimationFrame(() => {
        const rect = target.getBoundingClientRect();
        const tooltipRect = this.tooltip.getBoundingClientRect();

        let top = rect.bottom + 12;
        let left = rect.left;

        // If tooltip would go off-screen bottom, place above
        if (top + tooltipRect.height > window.innerHeight - 20) {
          top = rect.top - tooltipRect.height - 12;
        }
        // Keep within horizontal bounds
        if (left + 360 > window.innerWidth - 20) {
          left = window.innerWidth - 380;
        }
        if (left < 20) left = 20;

        this.tooltip.style.top = `${Math.max(10, top)}px`;
        this.tooltip.style.left = `${left}px`;
      });
    }

    // Render tooltip content
    const total = this.steps.length;
    this.tooltip.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <strong style="font-size: 0.95rem;">${step.title || `Step ${index + 1}`}</strong>
        <span style="font-size: 0.75rem; color: #718096;">${index + 1} / ${total}</span>
      </div>
      <p style="margin: 0 0 1rem; color: #4a5568;">${step.text}</p>
      <div style="display: flex; gap: 0.5rem; justify-content: space-between;">
        <div>
          ${index > 0 ? `<button id="wt-prev" style="padding: 0.35rem 0.75rem; border-radius: 6px; border: 1px solid #e2e8f0; background: white; cursor: pointer; font-size: 0.8rem;">Back</button>` : ''}
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button id="wt-skip" style="padding: 0.35rem 0.75rem; border-radius: 6px; border: 1px solid #e2e8f0; background: white; cursor: pointer; font-size: 0.8rem; color: #718096;">Skip</button>
          <button id="wt-next" style="padding: 0.35rem 0.75rem; border-radius: 6px; border: none; background: var(--primary, #0c234b); color: white; cursor: pointer; font-size: 0.8rem; font-weight: 500;">${index === total - 1 ? 'Done' : 'Next'}</button>
        </div>
      </div>
    `;

    // Button handlers
    this.tooltip.querySelector('#wt-next')?.addEventListener('click', () => {
      this.clearHighlight();
      if (index === total - 1) {
        this.dismiss();
      } else {
        // If step has a tab to switch to, do it first
        const nextStep = this.steps[index + 1];
        if (nextStep.tab) {
          const tabBtn = document.querySelector(`.tab-btn[onclick*="'${nextStep.tab}'"]`);
          if (tabBtn) tabBtn.click();
          setTimeout(() => this.showStep(index + 1), 300);
        } else {
          this.showStep(index + 1);
        }
      }
    });
    this.tooltip.querySelector('#wt-prev')?.addEventListener('click', () => {
      this.clearHighlight();
      const prevStep = this.steps[index - 1];
      if (prevStep.tab) {
        const tabBtn = document.querySelector(`.tab-btn[onclick*="'${prevStep.tab}'"]`);
        if (tabBtn) tabBtn.click();
        setTimeout(() => this.showStep(index - 1), 300);
      } else {
        this.showStep(index - 1);
      }
    });
    this.tooltip.querySelector('#wt-skip')?.addEventListener('click', () => this.dismiss());
  }

  clearHighlight() {
    document.querySelectorAll('[data-wt-highlighted]').forEach(el => {
      el.style.zIndex = '';
      el.style.boxShadow = '';
      el.style.borderRadius = '';
      delete el.dataset.wtHighlighted;
    });
  }

  dismiss() {
    this.active = false;
    this.clearHighlight();
    if (this.overlay) { this.overlay.remove(); this.overlay = null; }
    if (this.tooltip) { this.tooltip.remove(); this.tooltip = null; }
    localStorage.setItem('admin_walkthrough_seen', 'true');
  }
}

// ============================================================================
// ADMIN DASHBOARD WALKTHROUGH STEPS
// ============================================================================

const adminWalkthroughSteps = [
  {
    selector: '#statsBar',
    title: 'Status Overview',
    text: 'This bar shows the current state of your Guacamole connection, total connections, users, and active sessions at a glance.'
  },
  {
    selector: '#clusterHealthBar',
    title: 'Cluster Resources',
    text: 'Monitor your Proxmox cluster\'s CPU, memory, and storage usage in real-time. Warnings appear when resources are running low. Deployments will be blocked if thresholds are exceeded.'
  },
  {
    selector: '.tab-btn[onclick*="connections"]',
    tab: 'connections',
    title: 'Connections Tab',
    text: 'Manage Guacamole connections (RDP, SSH, VNC) and connection groups. These are the remote desktop links your students use to access VMs.'
  },
  {
    selector: '.tab-btn[onclick*="deploy"]',
    tab: 'deploy',
    title: 'Deploy Lanes',
    text: 'Deploy lanes — a batch of instructor + student accounts with optional VM lanes per student. The system will check cluster resources before allowing deployment.'
  },
  {
    selector: '.tab-btn[onclick*="lanes"]',
    tab: 'lanes',
    title: 'Active Lanes',
    text: 'View all deployed lab environments. Each lane is an isolated network with a challenge VM and gateway. You can toggle internet access and delete lanes from here.'
  },
  {
    selector: '.tab-btn[onclick*="users"]',
    tab: 'users',
    title: 'Users',
    text: 'Manage all user accounts in one place. Group controls let you enable/disable students and set class-hour schedules. The table shows both Clinic and Guacamole account status, with actions for permissions, password resets, and more.'
  },
  {
    selector: '.tab-btn[onclick*="actlog"]',
    tab: 'actlog',
    title: 'Activity Log',
    text: 'Track all user activity: logins, deployments, teardowns, and account changes. Filter by action type, user, or date range. Enable auto-refresh to monitor in real-time.'
  }
];
