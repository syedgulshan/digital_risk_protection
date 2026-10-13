import React from 'react';

export default function Sidebar({ currentView, setCurrentView, brandCount = 5, isOpen, onClose }) {
  const navItems = [
    { id: 'dashboard', label: 'Threat Dashboard', icon: 'bi-grid-1x2', section: 'Core Operations' },
    { id: 'brands', label: 'Brand Registry', icon: 'bi-buildings', badge: brandCount, section: null },
    { id: 'social', label: 'Social Profiles', icon: 'bi-person-badge', section: 'Detection Engines' },
    { id: 'link', label: 'Suspicious Links', icon: 'bi-link-45deg', section: null },
    { id: 'app', label: 'Mobile App Listings', icon: 'bi-phone', section: null },
    { id: 'history', label: 'Scan Audit Log', icon: 'bi-clock-history', section: 'Intelligence & Audits' },
  ];

  const handleNavClick = (id) => {
    setCurrentView(id);
    if (window.innerWidth < 992 && onClose) {
      onClose();
    }
  };

  return (
    <>
      {isOpen && (
        <div
          className="sidebar-backdrop d-lg-none"
          onClick={onClose}
          style={{ position: 'fixed', inset: 0, background: 'rgba(3, 7, 18, 0.7)', zIndex: 99 }}
        />
      )}
      <aside className={`sidebar ${isOpen ? 'show' : ''}`} id="sidebar">
        {/* Sidebar Header */}
        <div className="sidebar-header d-flex align-items-center gap-3">
          <div className="brand-hologram-shield">
            <svg viewBox="0 0 40 40" width="34" height="34" className="shield-svg" aria-hidden="true">
              <defs>
                <linearGradient id="sideShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#00f2fe" />
                  <stop offset="50%" stopColor="#38bdf8" />
                  <stop offset="100%" stopColor="#818cf8" />
                </linearGradient>
              </defs>
              <path d="M20 3 L35 9 V19 C35 28 28 35 20 38 C12 35 5 28 5 19 V9 Z" fill="rgba(6, 182, 212, 0.15)" stroke="url(#sideShieldGrad)" strokeWidth="2" />
              <polyline points="15 19 19 23 26 15" fill="none" stroke="#00f2fe" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <div className="brand-text">
            <h1 className="brand-title-neon fs-5 m-0">BrandShield <span className="badge-ai-neon" style={{ fontSize: '0.65rem' }}>AI</span></h1>
            <div className="brand-subtitle font-monospace" style={{ fontSize: '0.68rem', color: '#94a3b8' }}>Guardian Universe</div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="sidebar-nav">
          {navItems.map((item, idx) => (
            <React.Fragment key={item.id}>
              {item.section && <div className={`nav-section-title ${idx > 0 ? 'mt-3' : ''}`}>{item.section}</div>}
              <button
                type="button"
                className={`sidebar-link border-0 text-start w-100 bg-transparent ${currentView === item.id ? 'active' : ''}`}
                onClick={() => handleNavClick(item.id)}
              >
                <i className={`bi ${item.icon}`} />
                <span>{item.label}</span>
                {item.badge !== undefined && (
                  <span className="badge rounded-pill bg-dark border border-secondary text-info ms-auto" style={{ fontSize: '0.68rem' }}>
                    {item.badge}
                  </span>
                )}
              </button>
            </React.Fragment>
          ))}
        </nav>

        {/* Sidebar Footer */}
        <div className="sidebar-footer">
          <div className="sidebar-guardian-status">
            <div className="d-flex align-items-center gap-2 mb-1">
              <span className="pulse-beacon-cyan" />
              <span className="fw-bold text-light" style={{ fontSize: '0.72rem' }}>GUARDIAN AI ACTIVE</span>
            </div>
            <p className="text-secondary mb-0" style={{ fontSize: '0.68rem' }}>
              Autonomous neural heuristics protecting {brandCount} corporate brands.
            </p>
          </div>
        </div>
      </aside>
    </>
  );
}
