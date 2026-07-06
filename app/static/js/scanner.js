/**
 * WeScan — Client-side JavaScript
 * Handles progress polling, UI interactions, and utility functions.
 */

'use strict';

// ── Auto-dismiss flash alerts after 5 seconds ──────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.alert.alert-dismissible').forEach(function (alert) {
    setTimeout(function () {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 6000);
  });
});

// ── Activate Bootstrap tooltips globally ───────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
    new bootstrap.Tooltip(el);
  });
});

// ── Highlight active nav link based on current path ────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(function (link) {
    if (link.getAttribute('href') === path) {
      link.classList.add('active');
    }
  });
});

// ── URL validation helper used on the new scan form ────────────────────────
function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// ── Real-time URL feedback on new_scan form ─────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const urlInput = document.getElementById('target_url');
  if (!urlInput) return;

  urlInput.addEventListener('input', function () {
    const val = this.value.trim();
    if (!val) {
      this.classList.remove('is-valid', 'is-invalid');
    } else if (isValidUrl(val)) {
      this.classList.remove('is-invalid');
      this.classList.add('is-valid');
    } else {
      this.classList.remove('is-valid');
      this.classList.add('is-invalid');
    }
  });
});

// ── Copy payload / evidence to clipboard ───────────────────────────────────
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(function () {
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check"></i> Copied!';
    setTimeout(function () { btn.innerHTML = orig; }, 2000);
  });
}

// ── Confirm delete with a custom message ───────────────────────────────────
function confirmDelete(msg) {
  return confirm(msg || 'Are you sure you want to delete this item?');
}
