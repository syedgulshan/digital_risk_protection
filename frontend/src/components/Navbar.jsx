import React, { useState } from 'react';

export default function Navbar({
  user,
  onLogout,
  onOpenTour,
  telemetry = {},
  pageTitle = 'Dashboard Overview',
  pageSubtitle = 'Enterprise Digital Footprint Surveillance & Impersonation Defense',
  onToggleSidebar,
  setCurrentView
}) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [actionMenuOpen, setActionMenuOpen] = useState(false);

  return (
    <header className="top-navbar">
      <div className="d-flex align-items-center gap-3">
        <button
          className="btn btn-sm btn-cyber-secondary d-lg-none"
          onClick={onToggleSidebar}
          aria-label="Toggle Navigation"
        >
          <i className="bi bi-list fs-5" />
        </button>
        <div className="page-title">
          <h2>{pageTitle}</h2>
          <p>{pageSubtitle}</p>
        </div>
      </div>

      <div className="d-flex align-items-center gap-2">
        {/* API & Database Status Indicators */}
        <div className="d-none d-xl-flex align-items-center gap-2 me-2">
          {telemetry.supabase_live ? (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-success border border-success-subtle" style={{ background: 'rgba(16, 185, 129, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-database-check" /> Supabase Live
            </span>
          ) : (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-warning border border-warning-subtle" style={{ background: 'rgba(245, 158, 11, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-database-exclamation" /> Supabase Sync Pending
            </span>
          )}

          {telemetry.virustotal_active ? (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-success border border-success-subtle" style={{ background: 'rgba(16, 185, 129, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-shield-check" /> VT v3 Active
            </span>
          ) : (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-secondary border border-secondary" style={{ background: 'rgba(100, 116, 139, 0.1)', fontSize: '0.72rem' }}>
              <i className="bi bi-shield-slash" /> VT Offline
            </span>
          )}

          {telemetry.gemini_active && (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-info border border-info-subtle" style={{ background: 'rgba(56, 189, 248, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-robot" /> Gemini AI
            </span>
          )}

          {telemetry.ml_active && (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-warning border border-warning-subtle" style={{ background: 'rgba(245, 158, 11, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-link-45deg" /> URL ML
            </span>
          )}

          {telemetry.social_ml_active && (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-info border border-info-subtle" style={{ background: 'rgba(6, 182, 212, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-person-bounding-box" /> Profile ML
            </span>
          )}

          {telemetry.app_ml_active && (
            <span className="badge d-flex align-items-center gap-1 py-1 px-2 text-primary border border-primary-subtle" style={{ background: 'rgba(99, 102, 241, 0.12)', fontSize: '0.72rem' }}>
              <i className="bi bi-phone" /> App ML
            </span>
          )}
        </div>

        {/* Product Tour Launcher */}
        <button
          type="button"
          className="btn btn-sm btn-cyber-secondary d-none d-md-inline-flex align-items-center gap-1"
          onClick={onOpenTour}
          title="Explore Onboarding Slider"
        >
          <i className="bi bi-compass" />
          <span>Product Tour</span>
        </button>

        {/* Quick Launch Dropdown */}
        <div className="dropdown position-relative">
          <button
            className="btn btn-sm btn-cyber-primary dropdown-toggle d-flex align-items-center gap-2"
            type="button"
            onClick={() => setActionMenuOpen(!actionMenuOpen)}
          >
            <i className="bi bi-plus-circle" />
            <span>New Analysis</span>
          </button>
          {actionMenuOpen && (
            <ul className="dropdown-menu dropdown-menu-end shadow-lg show" style={{ background: 'var(--bs-bg-card)', borderColor: 'var(--bs-border-highlight)', display: 'block', position: 'absolute', right: 0, top: '100%', zIndex: 1050 }}>
              <li><h6 className="dropdown-header text-secondary" style={{ fontSize: '0.72rem', textTransform: 'uppercase' }}>Select Surface</h6></li>
              <li>
                <button className="dropdown-item text-light py-2" onClick={() => { setCurrentView('social'); setActionMenuOpen(false); }}>
                  <i className="bi bi-person-badge text-info me-2" /> Social Profile Scan
                </button>
              </li>
              <li>
                <button className="dropdown-item text-light py-2" onClick={() => { setCurrentView('link'); setActionMenuOpen(false); }}>
                  <i className="bi bi-link-45deg text-purple me-2" /> Suspicious Link Check
                </button>
              </li>
              <li>
                <button className="dropdown-item text-light py-2" onClick={() => { setCurrentView('app'); setActionMenuOpen(false); }}>
                  <i className="bi bi-phone text-warning me-2" /> Mobile App Inspection
                </button>
              </li>
              <li><hr className="dropdown-divider border-secondary opacity-25" /></li>
              <li>
                <button className="dropdown-item text-light py-2" onClick={() => { setCurrentView('brands'); setActionMenuOpen(false); }}>
                  <i className="bi bi-plus-square text-success me-2" /> Register New Brand
                </button>
              </li>
            </ul>
          )}
        </div>

        {/* Analyst Profile Dropdown */}
        <div className="dropdown ms-1 position-relative">
          <button
            className="btn btn-sm btn-cyber-user dropdown-toggle d-flex align-items-center gap-2"
            type="button"
            onClick={() => setDropdownOpen(!dropdownOpen)}
          >
            <div className="analyst-avatar-badge">
              <i className="bi bi-shield-lock-fill" />
            </div>
            <span className="d-none d-sm-inline fw-semibold" style={{ fontSize: '0.8rem' }}>
              {user?.name || 'Alex Morgan'}
            </span>
          </button>
          {dropdownOpen && (
            <ul className="dropdown-menu dropdown-menu-end shadow-lg show" style={{ background: 'var(--bs-bg-card)', borderColor: 'var(--bs-border-highlight)', minWidth: 230, display: 'block', position: 'absolute', right: 0, top: '100%', zIndex: 1050 }}>
              <li className="px-3 py-2 border-bottom border-secondary border-opacity-25">
                <div className="fw-bold text-light small">{user?.name || 'Threat Analyst'}</div>
                <div className="text-secondary font-monospace" style={{ fontSize: '0.7rem' }}>{user?.email || 'analyst@brandshield.ai'}</div>
                <span className="badge bg-info bg-opacity-10 text-cyan mt-1" style={{ fontSize: '0.65rem' }}>{user?.role || 'Lead Threat Analyst'}</span>
              </li>
              <li>
                <button className="dropdown-item text-light py-2 small" onClick={() => { setCurrentView('dashboard'); setDropdownOpen(false); }}>
                  <i className="bi bi-speedometer2 text-info me-2" /> Threat Command Center
                </button>
              </li>
              <li>
                <button className="dropdown-item text-light py-2 small" onClick={() => { onOpenTour(); setDropdownOpen(false); }}>
                  <i className="bi bi-compass text-warning me-2" /> Replay Onboarding Tour
                </button>
              </li>
              <li><hr className="dropdown-divider border-secondary opacity-25" /></li>
              <li>
                <button className="dropdown-item text-danger py-2 small" onClick={() => { setDropdownOpen(false); onLogout(); }}>
                  <i className="bi bi-box-arrow-right text-danger me-2" /> Terminate Session
                </button>
              </li>
            </ul>
          )}
        </div>
      </div>
    </header>
  );
}
