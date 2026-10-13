import React, { useState, useEffect } from 'react';
import api from '../api';

export default function SocialCheckerView() {
  const [brands, setBrands] = useState([]);
  const [platform, setPlatform] = useState('Twitter / X');
  const [username, setUsername] = useState('');
  const [profileName, setProfileName] = useState('');
  const [profileUrl, setProfileUrl] = useState('');
  const [description, setDescription] = useState('');
  const [brandId, setBrandId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [alert, setAlert] = useState(null);

  useEffect(() => {
    async function loadBrands() {
      const res = await api.brands.getAll();
      if (res.ok) {
        setBrands(res.data.brands || []);
        if (res.data.brands?.length > 0) {
          setBrandId(res.data.brands[0].id);
        }
      }
    }
    loadBrands();
  }, []);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!username.trim() && !profileUrl.trim()) {
      setAlert({ type: 'danger', message: 'Account Handle (@username) or Profile URL is required.' });
      return;
    }
    setLoading(true);
    setAlert(null);
    setResult(null);

    const res = await api.scanners.scanSocial({
      platform,
      username,
      profile_name: profileName,
      profile_url: profileUrl,
      description,
      brand_id: brandId ? parseInt(brandId, 10) : undefined,
    });
    setLoading(false);

    if (res.ok) {
      setResult(res.data);
    } else {
      setAlert({ type: 'danger', message: res.error || 'Inspection failed.' });
    }
  };

  const loadDemo = (type) => {
    if (type === 'authentic') {
      setPlatform('Twitter / X');
      setUsername('@apexbank');
      setProfileName('ApexBank Official');
      setProfileUrl('https://x.com/apexbank');
      setDescription('Official account of ApexBank. Member FDIC. 24/7 customer care via verified channels.');
    } else {
      setPlatform('Twitter / X');
      setUsername('@apexbank_support_help');
      setProfileName('Apex Support Assistance');
      setProfileUrl('https://x.com/apexbank_support_help');
      setDescription('Customer support desk. Send your account number and PIN via DM for quick dispute refund.');
    }
  };

  return (
    <div className="container-fluid px-0">
      {alert && (
        <div className={`alert alert-${alert.type} alert-dismissible fade show border-0 shadow-sm mb-4`} style={{ background: 'rgba(13, 22, 45, 0.95)', borderLeft: '4px solid var(--bs-' + alert.type + ')' }}>
          <span className="text-light small">{alert.message}</span>
          <button type="button" className="btn-close btn-close-white" onClick={() => setAlert(null)} />
        </div>
      )}

      {/* Header */}
      <div className="mb-4">
        <h4 className="text-light fw-bold m-0 d-flex align-items-center gap-2">
          <i className="bi bi-person-badge text-info" /> Social Profile Impersonation Shield
        </h4>
        <span className="text-secondary small">
          Detect lookalike handles, unauthorized support lures, digit-padding, and bot heuristics across Twitter/X, Instagram, and Telegram.
        </span>
      </div>

      <div className="row g-4">
        {/* Form Column */}
        <div className="col-lg-5">
          <div className="cyber-panel p-4 h-100">
            <h5 className="text-light fw-bold mb-3 d-flex align-items-center gap-2">
              <i className="bi bi-person-bounding-box text-cyan" /> Profile Target Parameters
            </h5>

            <form onSubmit={handleScan}>
              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Social Network Platform</label>
                <select
                  className="form-select input-cyber"
                  value={platform}
                  onChange={(e) => setPlatform(e.target.value)}
                >
                  <option value="Twitter / X">Twitter / X</option>
                  <option value="Instagram">Instagram</option>
                  <option value="LinkedIn">LinkedIn</option>
                  <option value="Telegram">Telegram</option>
                  <option value="Facebook">Facebook</option>
                  <option value="TikTok">TikTok</option>
                </select>
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Account Handle (@username) *</label>
                <div className="input-cyber-group">
                  <i className="bi bi-at input-cyber-icon" />
                  <input
                    type="text"
                    className="form-control input-cyber"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="@apexbank_support_help"
                    required
                  />
                </div>
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Display Name</label>
                <input
                  type="text"
                  className="form-control input-cyber"
                  value={profileName}
                  onChange={(e) => setProfileName(e.target.value)}
                  placeholder="Apex Support"
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Profile URL (Optional)</label>
                <input
                  type="url"
                  className="form-control input-cyber"
                  value={profileUrl}
                  onChange={(e) => setProfileUrl(e.target.value)}
                  placeholder="https://x.com/apexbank_support_help"
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Bio / Account Description</label>
                <textarea
                  className="form-control input-cyber"
                  rows="2"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Paste profile bio or lure text here"
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Target Brand Baseline</label>
                <select
                  className="form-select input-cyber"
                  value={brandId}
                  onChange={(e) => setBrandId(e.target.value)}
                >
                  {brands.map((b) => (
                    <option key={b.id} value={b.id}>{b.name} ({b.category})</option>
                  ))}
                </select>
              </div>

              {/* Demo Sample Buttons */}
              <div className="mb-4">
                <label className="form-label text-secondary small fw-semibold d-block mb-2">Test Baseline Samples:</label>
                <div className="d-flex gap-2">
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-danger"
                    onClick={() => loadDemo('impersonator')}
                  >
                    Impersonating Fake Handle
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-success"
                    onClick={() => loadDemo('authentic')}
                  >
                    Authentic Verified Handle
                  </button>
                </div>
              </div>

              <button type="submit" className="btn btn-cyber-primary w-100 py-2" disabled={loading}>
                {loading ? (
                  <span><span className="spinner-border spinner-border-sm me-2" /> Inspecting Entropy & Bot Heuristics...</span>
                ) : (
                  <span><i className="bi bi-shield-shaded me-1" /> Run Profile Impersonation Scan</span>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Results Column */}
        <div className="col-lg-7">
          {result ? (
            <div className="cyber-panel p-4 h-100">
              <div className="d-flex align-items-center justify-content-between mb-3 border-bottom border-secondary border-opacity-25 pb-3">
                <div>
                  <h5 className="text-light fw-bold m-0 d-flex align-items-center gap-2">
                    <i className="bi bi-person-check text-cyan" /> Assessment Telemetry
                  </h5>
                  <span className="text-secondary small font-monospace">Target: {result.input_username || result.submitted_username}</span>
                </div>
                <div className="text-end">
                  <span className={`badge fs-6 ${
                    result.risk_category === 'HIGH RISK' ? 'bg-danger' :
                    result.risk_category === 'SUSPICIOUS' ? 'bg-warning text-dark' : 'bg-success'
                  }`}>
                    {result.risk_category}
                  </span>
                  <div className="text-secondary small font-monospace mt-1">Score: {result.risk_score}/100</div>
                </div>
              </div>

              {/* Summary Reason */}
              <div className="alert bg-dark border-secondary border-opacity-50 text-light small mb-3">
                <strong>Analysis Summary:</strong> {result.summary_reason}
              </div>

              {/* Indicators */}
              <div className="mb-3">
                <h6 className="text-cyan small fw-bold mb-2">HEURISTIC INDICATORS & EVIDENCE:</h6>
                <ul className="list-group list-group-flush bg-transparent">
                  {(result.heuristic_findings || []).map((f, i) => (
                    <li key={i} className="list-group-item bg-transparent text-secondary small px-0 py-1 border-secondary border-opacity-10 d-flex align-items-start gap-2">
                      <i className="bi bi-arrow-right-short text-info fs-5 lh-1" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Rule 8 Notice */}
              <div className="alert alert-warning border-0 p-3 mb-3" style={{ background: 'rgba(245, 158, 11, 0.1)', borderLeft: '4px solid #f59e0b !important' }}>
                <div className="d-flex align-items-start gap-2 text-warning small">
                  <i className="bi bi-shield-exclamation fs-5 lh-1" />
                  <div>
                    <strong>Rule 8 Cyber Principle:</strong> Clean domain reputation of major social platforms (x.com, instagram.com) does NOT guarantee profile legitimacy. Authenticity is evaluated strictly on account handle entropy and brand registry authorization.
                  </div>
                </div>
              </div>

              {/* Remediation */}
              <div>
                <h6 className="text-success small fw-bold mb-2">REMEDIATION ACTION PLAN:</h6>
                <ul className="list-group list-group-flush bg-transparent">
                  {(result.recommendations || []).map((r, i) => (
                    <li key={i} className="list-group-item bg-transparent text-light small px-0 py-1 border-secondary border-opacity-10 d-flex align-items-start gap-2">
                      <i className="bi bi-check2-circle text-success fs-6 lh-1" />
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="cyber-panel p-5 h-100 d-flex flex-column align-items-center justify-content-center text-center">
              <i className="bi bi-person-x text-secondary fs-1 mb-3 opacity-50" />
              <h5 className="text-light fw-bold">Awaiting Social Profile Target</h5>
              <p className="text-secondary small" style={{ maxWidth: 360 }}>
                Enter an account handle or profile URL to evaluate token similarity, bot likelihood, digit-padding, and unauthorized support lures.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
