import React, { useState, useEffect } from 'react';
import api from '../api';

export default function LinkCheckerView({ onSelectScan }) {
  const [brands, setBrands] = useState([]);
  const [url, setUrl] = useState('');
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
    if (!url.trim()) {
      setAlert({ type: 'danger', message: 'Target URL is required.' });
      return;
    }
    setLoading(true);
    setAlert(null);
    setResult(null);

    const res = await api.scanners.scanLink(url, brandId ? parseInt(brandId, 10) : undefined);
    setLoading(false);

    if (res.ok) {
      setResult(res.data);
    } else {
      setAlert({ type: 'danger', message: res.error || 'Inspection failed.' });
    }
  };

  const setDemoUrl = (demoLink) => {
    setUrl(demoLink);
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
          <i className="bi bi-link-45deg text-purple" /> Suspicious Link & Phishing Analyzer
        </h4>
        <span className="text-secondary small">
          Deterministic lexical inspection, typosquatting distance verification, and VirusTotal v3 correlation without visiting dangerous URLs.
        </span>
      </div>

      <div className="row g-4">
        {/* Input Form Column */}
        <div className="col-lg-5">
          <div className="cyber-panel p-4 h-100">
            <h5 className="text-light fw-bold mb-3 d-flex align-items-center gap-2">
              <i className="bi bi-search text-cyan" /> Target Inspection Parameters
            </h5>

            <form onSubmit={handleScan}>
              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Target Domain / URL *</label>
                <div className="input-cyber-group">
                  <i className="bi bi-link-45deg input-cyber-icon" />
                  <input
                    type="text"
                    className="form-control input-cyber"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://apexbank-secure-login.xyz"
                    required
                  />
                </div>
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Protecting Brand Baseline</label>
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

              {/* Quick Demo Links */}
              <div className="mb-4">
                <label className="form-label text-secondary small fw-semibold d-block mb-2">Test Baseline Samples:</label>
                <div className="d-flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-danger"
                    onClick={() => setDemoUrl('https://apexbank-secure-login.xyz')}
                  >
                    Phishing Lookalike (.xyz)
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-success"
                    onClick={() => setDemoUrl('https://x.com/apexbank')}
                  >
                    Authentic Social Profile
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-warning"
                    onClick={() => setDemoUrl('https://x.com/apexbank_scam_support')}
                  >
                    Impersonating Social Profile
                  </button>
                </div>
              </div>

              <button type="submit" className="btn btn-cyber-primary w-100 py-2" disabled={loading}>
                {loading ? (
                  <span><span className="spinner-border spinner-border-sm me-2" /> Inspecting Syntactic Vectors...</span>
                ) : (
                  <span><i className="bi bi-shield-shaded me-1" /> Run Multi-Factor Threat Scan</span>
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
                    <i className="bi bi-file-earmark-medical text-cyan" /> Scan Assessment Telemetry
                  </h5>
                  <span className="text-secondary small font-monospace">Target: {result.submitted_url}</span>
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

              {/* Heuristic Findings */}
              <div className="mb-3">
                <h6 className="text-cyan small fw-bold mb-2">HEURISTIC & LEXICAL INDICATORS:</h6>
                <ul className="list-group list-group-flush bg-transparent">
                  {(result.heuristic_findings || []).map((f, i) => (
                    <li key={i} className="list-group-item bg-transparent text-secondary small px-0 py-1 border-secondary border-opacity-10 d-flex align-items-start gap-2">
                      <i className="bi bi-arrow-right-short text-info fs-5 lh-1" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* VirusTotal Findings */}
              {result.api_findings && (
                <div className="p-3 rounded mb-3" style={{ background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                  <div className="fw-semibold text-light small mb-1">
                    <i className="bi bi-shield-check text-info me-1" /> VirusTotal Intelligence Telemetry:
                  </div>
                  <div className="text-secondary small">{result.api_findings.summary || JSON.stringify(result.api_findings)}</div>
                </div>
              )}

              {/* Recommendations */}
              <div>
                <h6 className="text-success small fw-bold mb-2">REMEDIATION & ACTION PLAN:</h6>
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
              <i className="bi bi-radar text-secondary fs-1 mb-3 opacity-50" />
              <h5 className="text-light fw-bold">Awaiting Target URL</h5>
              <p className="text-secondary small" style={{ maxWidth: 360 }}>
                Enter an unverified URL or select a sample baseline to begin lexical inspection, typosquatting checks, and VirusTotal v3 cross-referencing.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
