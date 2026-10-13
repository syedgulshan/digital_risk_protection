/**
 * BrandShield AI - Frontend JavaScript Engine
 * Handles presets, form interactions, loading states, and live filters.
 */

document.addEventListener('DOMContentLoaded', function () {
  // Mobile sidebar toggle
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebarBackdrop');

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', function () {
      sidebar.classList.toggle('show');
      if (backdrop) backdrop.classList.toggle('show');
    });
  }

  if (backdrop) {
    backdrop.addEventListener('click', function () {
      sidebar.classList.remove('show');
      backdrop.classList.remove('show');
    });
  }

  // Auto-dismiss alerts after 5 seconds
  const autoAlerts = document.querySelectorAll('.alert-dismissible');
  autoAlerts.forEach(function (alert) {
    setTimeout(function () {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 5000);
  });

  // Scanner Form Submit Spinner Handler
  const scanForms = document.querySelectorAll('.scan-form');
  scanForms.forEach(function (form) {
    form.addEventListener('submit', function () {
      const submitBtn = form.querySelector('.btn-scan-submit');
      if (submitBtn) {
        submitBtn.disabled = true;
        const origText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="scan-spinner me-2"></span> Analyzing Heuristics...';
      }
    });
  });

  // =========================================================================
  // SOCIAL CHECKER PRESETS
  // =========================================================================
  const socialPresets = {
    official: {
      brand_name: "CloudShield",
      platform: "Twitter / X",
      profile_name: "CloudShield Official",
      username: "@cloudshield",
      profile_url: "https://x.com/cloudshield",
      description: "Official handle for CloudShield Cyber. Zero trust architecture and cyber defense. Official site: https://cloudshield.io"
    },
    impersonator: {
      brand_name: "ApexBank",
      platform: "Twitter / X",
      profile_name: "ApexBank Priority Help Desk",
      username: "@apexbank_support_help",
      profile_url: "https://x.com/apexbank_support_help",
      description: "ApexBank 24/7 Priority Resolution Desk. Send DM with account number for instant refund / KYC unlock. Official support agent."
    },
    leetspeak: {
      brand_name: "CloudShield",
      platform: "Telegram",
      profile_name: "CloudShield Token Airdrop Bot",
      username: "@cl0udshie1d_giveaways",
      profile_url: "https://t.me/cl0udshie1d_giveaways",
      description: "CloudShield official token airdrop. Connect your wallet to claim 500 CSHIELD rewards. DM us your seed phrase to activate."
    },
    discrepancy: {
      brand_name: "ApexBank",
      platform: "Twitter / X",
      profile_name: "ApexBank Care",
      username: "@apexbank",
      profile_url: "https://x.com/apexbank_fake_desk",
      description: "Claims official @apexbank handle in form, but provides an unofficial rogue profile URL."
    }
  };

  document.querySelectorAll('.btn-social-preset').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const presetKey = this.getAttribute('data-preset');
      const data = socialPresets[presetKey];
      if (!data) return;

      // Select brand in dropdown
      const brandSelect = document.getElementById('brand_id');
      if (brandSelect) {
        for (let i = 0; i < brandSelect.options.length; i++) {
          if (brandSelect.options[i].text.includes(data.brand_name)) {
            brandSelect.selectedIndex = i;
            break;
          }
        }
      }

      setVal('platform', data.platform);
      setVal('profile_name', data.profile_name);
      setVal('username', data.username);
      setVal('profile_url', data.profile_url);
      setVal('description', data.description);

      highlightField('username');
    });
  });

  // =========================================================================
  // LINK CHECKER PRESETS
  // =========================================================================
  const linkPresets = {
    official_portal: {
      brand_name: "VertexHealth",
      url: "https://portal.vertexhealth.org/patient/login"
    },
    genuine_social: {
      brand_name: "ApexBank",
      url: "https://x.com/apexbank"
    },
    fake_social: {
      brand_name: "ApexBank",
      url: "https://x.com/apexbank_scam_support"
    },
    phishing_subdomain: {
      brand_name: "ApexBank",
      url: "http://apexbank-login-secure.xyz/ebanking/verify"
    },
    raw_ip: {
      brand_name: "NexaPay",
      url: "http://192.168.1.105:8080/nexapay/wallet-verify"
    }
  };

  document.querySelectorAll('.btn-link-preset').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const presetKey = this.getAttribute('data-preset');
      const data = linkPresets[presetKey];
      if (!data) return;

      const brandSelect = document.getElementById('brand_id');
      if (brandSelect) {
        for (let i = 0; i < brandSelect.options.length; i++) {
          if (brandSelect.options[i].text.includes(data.brand_name)) {
            brandSelect.selectedIndex = i;
            break;
          }
        }
      }

      setVal('url', data.url);
      highlightField('url');
    });
  });

  // =========================================================================
  // MOBILE APP CHECKER PRESETS
  // =========================================================================
  const appPresets = {
    official: {
      brand_name: "ApexBank",
      app_name: "ApexBank Mobile Banking",
      developer_name: "Apex Financial Technologies LLC",
      store_url: "https://play.google.com/store/apps/details?id=com.apexbank.mobile",
      description: "Official mobile banking application for ApexBank clients. Securely check balances, deposit checks, and wire transfers."
    },
    lookalike: {
      brand_name: "ApexBank",
      app_name: "ApexBank Quick Money & Loan Fast",
      developer_name: "Apex Fast Finance Apps Co.",
      store_url: "https://play.google.com/store/apps/details?id=com.apex.fastloan.instant",
      description: "Get instant personal loans in 5 minutes with ApexBank Quick Money. No credit check or KYC required. Fast approval."
    },
    trojan: {
      brand_name: "NexaPay",
      app_name: "NexaPay Wallet Mod & Free Cash",
      developer_name: "FastCash Mobile Studios",
      store_url: "https://apk-mirrorsite.org/nexapay-mod-free-download",
      description: "Official NexaPay wallet generator with unlimited balance cheat. Requires Root and Accessibility service permissions to hook system payments."
    }
  };

  document.querySelectorAll('.btn-app-preset').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const presetKey = this.getAttribute('data-preset');
      const data = appPresets[presetKey];
      if (!data) return;

      const brandSelect = document.getElementById('brand_id');
      if (brandSelect) {
        for (let i = 0; i < brandSelect.options.length; i++) {
          if (brandSelect.options[i].text.includes(data.brand_name)) {
            brandSelect.selectedIndex = i;
            break;
          }
        }
      }

      setVal('app_name', data.app_name);
      setVal('developer_name', data.developer_name);
      setVal('store_url', data.store_url);
      setVal('description', data.description);

      highlightField('app_name');
    });
  });

  // Helper function to safely set form values
  function setVal(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value;
  }

  // Flash border animation on targeted preset field
  function highlightField(id) {
    const el = document.getElementById(id);
    if (el) {
      el.focus();
      el.style.borderColor = 'var(--bs-cyan)';
      el.style.boxShadow = '0 0 12px var(--bs-cyan-glow)';
      setTimeout(function () {
        el.style.borderColor = '';
        el.style.boxShadow = '';
      }, 1200);
    }
  }

  // Copy to clipboard helper
  window.copyToClipboard = function (text, btnElement) {
    navigator.clipboard.writeText(text).then(function () {
      if (btnElement) {
        const originalText = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="bi bi-check2 text-success"></i> Copied!';
        setTimeout(function () {
          btnElement.innerHTML = originalText;
        }, 2000);
      }
    });
  };
});
