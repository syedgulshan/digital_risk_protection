import React, { useState } from 'react';
import GlobeCanvas from '../components/GlobeCanvas';
import GuardianMascot from '../components/GuardianMascot';
import OnboardingModal from '../components/OnboardingModal';
import api from '../api';

export default function LoginView({ onAuthSuccess }) {
  const [mode, setMode] = useState('login'); // 'login' | 'signup' | 'forgot'
  const [username, setUsername] = useState('analyst@brandshield.ai');
  const [password, setPassword] = useState('CyberShield2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [remember, setRemember] = useState(true);

  // Signup fields
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [department, setDepartment] = useState('Digital Brand Surveillance');

  // Loading & Alerts
  const [loading, setLoading] = useState(false);
  const [alert, setAlert] = useState(null); // { type: 'success'|'danger'|'info', message: '' }
  const [tourOpen, setTourOpen] = useState(false);

  const handleQuickFill = () => {
    setUsername('analyst@brandshield.ai');
    setPassword('CyberShield2026!');
    setAlert({
      type: 'info',
      message: 'Demo credentials loaded: analyst@brandshield.ai. Click Authenticate to enter!',
    });
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setAlert(null);

    const res = await api.auth.login(username, password, remember);
    setLoading(false);

    if (res.ok) {
      setAlert({ type: 'success', message: res.data.message || 'Security clearance confirmed!' });
      setTimeout(() => {
        onAuthSuccess(res.data.user);
      }, 400);
    } else {
      setAlert({ type: 'danger', message: res.error || 'Invalid credentials. Access denied.' });
    }
  };

  const handleSignupSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setAlert(null);

    const res = await api.auth.signup(name, email, password, department);
    setLoading(false);

    if (res.ok) {
      setAlert({ type: 'success', message: 'Clearance created successfully in Guardian Directory!' });
      setTimeout(() => {
        onAuthSuccess(res.data.user);
      }, 400);
    } else {
      setAlert({ type: 'danger', message: res.error || 'Registration failed.' });
    }
  };

  const handleForgotSubmit = (e) => {
    e.preventDefault();
    setAlert({
      type: 'info',
      message: `Access recovery token dispatched to '${email || username}'. Follow the secure cryptographic link.`,
    });
    setTimeout(() => setMode('login'), 2500);
  };

  const handleSSO = (provider) => {
    const dummyUser = {
      name: `${provider} Analyst`,
      email: `analyst@${provider.toLowerCase()}-brandshield.com`,
      role: `${provider} Enterprise SSO`
    };
    localStorage.setItem('brandshield_token', dummyUser.email);
    localStorage.setItem('brandshield_user', JSON.stringify(dummyUser));
    setAlert({ type: 'success', message: `Enterprise SSO validated via ${provider}.` });
    setTimeout(() => onAuthSuccess(dummyUser), 400);
  };

  return (
    <div className="guardian-universe-body min-vh-100 d-flex flex-column justify-content-between position-relative overflow-hidden">
      {/* 3D Holographic Threat Globe Canvas */}
      <GlobeCanvas />

      {/* Onboarding Tour Modal */}
      <OnboardingModal isOpen={tourOpen} onClose={() => setTourOpen(false)} />

      {/* Flash Alert Container */}
      {alert && (
        <div className="guardian-flash-container" style={{ position: 'fixed', top: '1.5rem', right: '1.5rem', zIndex: 1050, maxWidth: 450 }}>
          <div className={`alert alert-${alert.type} alert-dismissible fade show border-0 shadow-lg d-flex align-items-center gap-2`} style={{ background: 'rgba(13, 22, 45, 0.95)', borderLeft: '4px solid var(--bs-' + alert.type + ')' }}>
            <i className={`bi ${alert.type === 'success' ? 'bi-shield-check text-success' : alert.type === 'danger' ? 'bi-shield-x text-danger' : 'bi-info-circle text-info'} fs-5`} />
            <div className="text-light flex-grow-1 small">{alert.message}</div>
            <button type="button" className="btn-close btn-close-white" onClick={() => setAlert(null)} />
          </div>
        </div>
      )}

      <div className="container-fluid min-vh-100 d-flex flex-column justify-content-between p-3 p-md-4 position-relative z-1">
        {/* Top Header */}
        <header className="d-flex align-items-center justify-content-between py-2">
          <div className="d-flex align-items-center gap-3">
            <div className="brand-hologram-shield">
              <svg viewBox="0 0 40 40" width="38" height="38" className="shield-svg" aria-hidden="true">
                <defs>
                  <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#00f2fe" />
                    <stop offset="50%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#818cf8" />
                  </linearGradient>
                </defs>
                <path d="M20 3 L35 9 V19 C35 28 28 35 20 38 C12 35 5 28 5 19 V9 Z" fill="rgba(6, 182, 212, 0.15)" stroke="url(#shieldGrad)" strokeWidth="2" />
                <path d="M20 10 L30 14 V19 C30 25 25 30 20 32 C15 30 10 25 10 19 V14 Z" fill="none" stroke="#38bdf8" strokeDasharray="2,2" opacity="0.7" />
                <polyline points="15 19 19 23 26 15" fill="none" stroke="#00f2fe" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
            <div>
              <h1 className="brand-title-neon m-0">BrandShield <span className="badge-ai-neon">AI</span></h1>
              <span className="brand-tagline-neon">Digital Guardian Universe • Cyber Defense</span>
            </div>
          </div>

          <div className="d-flex align-items-center gap-2">
            <button
              type="button"
              className="btn btn-sm btn-cyber-tour"
              onClick={() => setTourOpen(true)}
              title="Explore Onboarding Slider"
            >
              <i className="bi bi-compass me-1" /> Get Started Tour
            </button>
          </div>
        </header>

        {/* Center Stage: Mascot + Glass Card */}
        <main className="row justify-content-center align-items-center my-auto py-4 g-4">
          {/* Mascot Column */}
          <div className="col-lg-5 col-xl-5 text-center text-lg-start d-flex flex-column align-items-center align-items-lg-start">
            <GuardianMascot />
            <div className="mascot-info-badge mt-4">
              <span className="badge badge-cyber-pill">
                <i className="bi bi-shield-lock-fill text-info me-1" /> Continuous Neural Perimeter Shield
              </span>
              <p className="text-secondary small mt-2 mb-0" style={{ maxWidth: 380 }}>
                Deterministic multi-vector defense inspecting impersonation markers, typosquatting domains, and mobile distribution anomalies.
              </p>
            </div>
          </div>

          {/* Form Column */}
          <div className="col-md-9 col-lg-6 col-xl-5">
            <div className="guardian-glass-card">
              {/* Card Header & Tabs */}
              <div className="d-flex align-items-center justify-content-between mb-4 border-bottom border-secondary border-opacity-25 pb-3">
                <div>
                  <h2 className="fs-4 fw-bold text-light m-0">
                    {mode === 'signup' ? 'Create Security Clearance' : mode === 'forgot' ? 'Recover Access Key' : 'Analyst Authentication'}
                  </h2>
                  <span className="text-secondary small">
                    {mode === 'signup' ? 'Enroll new analyst credentials' : mode === 'forgot' ? 'Identity verification token' : 'Zero-trust authenticated perimeter'}
                  </span>
                </div>
                <div className="btn-group btn-group-sm">
                  {mode !== 'login' && (
                    <button type="button" className="btn btn-outline-info" onClick={() => setMode('login')}>
                      Login
                    </button>
                  )}
                  {mode !== 'signup' && (
                    <button type="button" className="btn btn-outline-info" onClick={() => setMode('signup')}>
                      Sign Up
                    </button>
                  )}
                </div>
              </div>

              {/* LOGIN FORM */}
              {mode === 'login' && (
                <form onSubmit={handleLoginSubmit} className="guardian-auth-form">
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Analyst Identifier or Corporate Email</label>
                    <div className="input-cyber-group">
                      <i className="bi bi-person-badge input-cyber-icon" />
                      <input
                        type="text"
                        className="form-control input-cyber"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="analyst@brandshield.ai"
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="mb-3">
                    <div className="d-flex justify-content-between align-items-center mb-1">
                      <label className="form-label text-light small fw-semibold m-0">Security Keyphrase</label>
                      <button
                        type="button"
                        className="btn btn-link text-cyan text-decoration-none small p-0"
                        onClick={() => setMode('forgot')}
                      >
                        Forgot?
                      </button>
                    </div>
                    <div className="input-cyber-group">
                      <i className="bi bi-shield-lock input-cyber-icon" />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        className="form-control input-cyber"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="••••••••••••"
                        required
                      />
                      <button
                        type="button"
                        className="btn-password-toggle"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label="Toggle password visibility"
                      >
                        <i className={`bi ${showPassword ? 'bi-eye-slash text-info' : 'bi-eye'}`} />
                      </button>
                    </div>
                  </div>

                  {/* Remember Me & Demo Quick Fill */}
                  <div className="d-flex justify-content-between align-items-center mb-4">
                    <div className="form-check form-switch m-0">
                      <input
                        className="form-check-input cyber-switch"
                        type="checkbox"
                        role="switch"
                        id="rememberMe"
                        checked={remember}
                        onChange={(e) => setRemember(e.target.checked)}
                      />
                      <label className="form-check-label text-secondary small ms-1" htmlFor="rememberMe">Remember Session</label>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-link text-info p-0 text-decoration-none small"
                      onClick={handleQuickFill}
                    >
                      <i className="bi bi-magic me-1" /> Fill Demo Credentials
                    </button>
                  </div>

                  <button type="submit" className="btn btn-cyber-primary w-100 py-2" disabled={loading}>
                    {loading ? (
                      <span><span className="spinner-border spinner-border-sm me-1" /> Encrypting Session...</span>
                    ) : (
                      <span><i className="bi bi-box-arrow-in-right me-1" /> Authenticate & Enter Universe</span>
                    )}
                  </button>

                  {/* SSO Buttons */}
                  <div className="separator-neon my-4">
                    <span>Or Authenticate via Enterprise Identity</span>
                  </div>

                  <div className="row g-2">
                    <div className="col-6">
                      <button
                        type="button"
                        className="btn btn-cyber-sso w-100 d-flex align-items-center justify-content-center gap-2 py-2"
                        onClick={() => handleSSO('Google')}
                      >
                        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
                          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
                        </svg>
                        <span>Google SSO</span>
                      </button>
                    </div>
                    <div className="col-6">
                      <button
                        type="button"
                        className="btn btn-cyber-sso w-100 d-flex align-items-center justify-content-center gap-2 py-2"
                        onClick={() => handleSSO('Apple')}
                      >
                        <i className="bi bi-apple fs-5" />
                        <span>Apple ID</span>
                      </button>
                    </div>
                  </div>
                </form>
              )}

              {/* SIGNUP FORM */}
              {mode === 'signup' && (
                <form onSubmit={handleSignupSubmit} className="guardian-auth-form">
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Analyst Full Name</label>
                    <div className="input-cyber-group">
                      <i className="bi bi-person input-cyber-icon" />
                      <input
                        type="text"
                        className="form-control input-cyber"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="Alex Morgan"
                        required
                      />
                    </div>
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Corporate Email</label>
                    <div className="input-cyber-group">
                      <i className="bi bi-envelope input-cyber-icon" />
                      <input
                        type="email"
                        className="form-control input-cyber"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="analyst@enterprise.com"
                        required
                      />
                    </div>
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Security Keyphrase (min 6 characters)</label>
                    <div className="input-cyber-group">
                      <i className="bi bi-key input-cyber-icon" />
                      <input
                        type="password"
                        className="form-control input-cyber"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="••••••••••••"
                        required
                      />
                    </div>
                  </div>
                  <div className="mb-4">
                    <label className="form-label text-light small fw-semibold">Department / Clearance</label>
                    <select
                      className="form-select input-cyber"
                      value={department}
                      onChange={(e) => setDepartment(e.target.value)}
                    >
                      <option value="Cyber Defense Operations">Cyber Defense Operations</option>
                      <option value="Digital Brand Surveillance">Digital Brand Surveillance</option>
                      <option value="Threat Intelligence Unit">Threat Intelligence Unit</option>
                      <option value="Executive Protection">Executive Protection</option>
                    </select>
                  </div>
                  <button type="submit" className="btn btn-cyber-primary w-100 py-2" disabled={loading}>
                    <i className="bi bi-person-check me-1" /> Register Clearance & Enter
                  </button>
                </form>
              )}

              {/* FORGOT PASSWORD FORM */}
              {mode === 'forgot' && (
                <form onSubmit={handleForgotSubmit} className="guardian-auth-form">
                  <div className="mb-4">
                    <label className="form-label text-light small fw-semibold">Registered Corporate Email</label>
                    <div className="input-cyber-group">
                      <i className="bi bi-envelope input-cyber-icon" />
                      <input
                        type="email"
                        className="form-control input-cyber"
                        value={email || username}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="analyst@brandshield.ai"
                        required
                      />
                    </div>
                  </div>
                  <button type="submit" className="btn btn-cyber-primary w-100 py-2">
                    <i className="bi bi-send me-1" /> Dispatch Recovery Token
                  </button>
                  <button type="button" className="btn btn-link text-secondary w-100 mt-2 small text-decoration-none" onClick={() => setMode('login')}>
                    Cancel & Return to Login
                  </button>
                </form>
              )}
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer className="d-flex flex-column flex-sm-row align-items-center justify-content-between py-2 text-secondary small border-top border-secondary border-opacity-10 mt-3">
          <div>
            <span className="text-light fw-semibold">BrandShield AI</span> • ByteXL Digital Risk Protection Platform
          </div>
          <div className="d-flex gap-3 mt-2 mt-sm-0">
            <button
              type="button"
              className="btn btn-link text-info p-0 text-decoration-none small hover-cyan"
              onClick={() => setTourOpen(true)}
            >
              <i className="bi bi-compass me-1" /> Take 4-Slide Tour
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
}
