import React, { useState, useEffect } from 'react';
import api from '../api';

export default function AppCheckerView() {
  const [brands, setBrands] = useState([]);
  const [appName, setAppName] = useState('');
  const [developerName, setDeveloperName] = useState('');
  const [storeUrl, setStoreUrl] = useState('');
  const [description, setDescription] = useState('');
  const [apkHash, setApkHash] = useState('');
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
    if (!appName.trim() || !developerName.trim()) {
      setAlert({ type: 'danger', message: 'Application Name and Developer Name are required.' });
      return;
    }
    setLoading(true);
    setAlert(null);
    setResult(null);

    const res = await api.scanners.scanApp({
      app_name: appName,
      developer_name: developerName,
      store_url: storeUrl,
      description,
      apk_hash: apkHash,
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
      setAppName('ApexBank Mobile Banking');
      setDeveloperName('Apex Financial Technologies LLC');
      setStoreUrl('https://play.google.com/store/apps/details?id=com.apexbank.mobile');
      setDescription('Official mobile banking app for ApexBank customers with biometrics and instant transfers.');
      setApkHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    } else if (type === 'rogue') {
      setAppName('ApexBank Instant Fast Loan & Cash');
      setDeveloperName('Apex Mobile Finance Apps LLC');
      setStoreUrl('https://play.google.com/store/apps/details?id=com.apex.fastloan');
      setDescription('Instant loans in 5 minutes! Requires full access to SMS inbox, contacts, and location.');
      setApkHash('');
    } else {
      setAppName('ApexBank Pro Wallet MOD');
      setDeveloperName('FastCash Studios');
      setStoreUrl('https://apk-mirrorsite.org/apex-mod.apk');
      setDescription('Unlocked features. Demands Root privileges, accessibility services, and device admin permission.');
      setApkHash('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');
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
          <i className="bi bi-phone text-warning" /> Mobile App Listing & Rogue APK Inspector
        </h4>
        <span className="text-secondary small">
          Inspect third-party APK listings, clones, trojanized finance apps, and unauthorized publisher identities using Drebin permission risk profiling.
        </span>
      </div>

      <div className="row g-4">
        {/* Form Column */}
        <div className="col-lg-5">
          <div className="cyber-panel p-4 h-100">
            <h5 className="text-light fw-bold mb-3 d-flex align-items-center gap-2">
              <i className="bi bi-phone-vibrate text-cyan" /> App Package Metadata
            </h5>

            <form onSubmit={handleScan}>
              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Application Name *</label>
                <input
                  type="text"
                  className="form-control input-cyber"
                  value={appName}
                  onChange={(e) => setAppName(e.target.value)}
                  placeholder="ApexBank Mobile Banking"
                  required
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Publisher / Developer Name *</label>
                <input
                  type="text"
                  className="form-control input-cyber"
                  value={developerName}
                  onChange={(e) => setDeveloperName(e.target.value)}
                  placeholder="Apex Financial Technologies LLC"
                  required
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Store / APK Listing URL</label>
                <input
                  type="url"
                  className="form-control input-cyber"
                  value={storeUrl}
                  onChange={(e) => setStoreUrl(e.target.value)}
                  placeholder="https://play.google.com/store/apps/details?id=..."
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">Description / Permission Demands</label>
                <textarea
                  className="form-control input-cyber"
                  rows="2"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Requires SMS access, contacts, accessibility services..."
                />
              </div>

              <div className="mb-3">
                <label className="form-label text-light small fw-semibold">APK SHA-256 Checksum (Optional)</label>
                <input
                  type="text"
                  className="form-control input-cyber font-monospace"
                  style={{ fontSize: '0.75rem' }}
                  value={apkHash}
                  onChange={(e) => setApkHash(e.target.value)}
                  placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae..."
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

              {/* Demo Buttons */}
              <div className="mb-4">
                <label className="form-label text-secondary small fw-semibold d-block mb-2">Test Baseline Samples:</label>
                <div className="d-flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-success"
                    onClick={() => loadDemo('authentic')}
                  >
                    Verified Developer App
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-warning"
                    onClick={() => loadDemo('rogue')}
                  >
                    Lookalike Developer
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-outline-danger"
                    onClick={() => loadDemo('trojan')}
                  >
                    Trojanized APK Mirror
                  </button>
                </div>
              </div>

              <button type="submit" className="btn btn-cyber-primary w-100 py-2" disabled={loading}>
                {loading ? (
                  <span><span className="spinner-border spinner-border-sm me-2" /> Inspecting Android Permission Vectors...</span>
                ) : (
                  <span><i className="bi bi-shield-shaded me-1" /> Run Mobile Threat Scan</span>
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
                    <i className="bi bi-phone-flip text-cyan" /> Assessment Telemetry
                  </h5>
                  <span className="text-secondary small font-monospace">Package: {result.app_name}</span>
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
                <h6 className="text-cyan small fw-bold mb-2">DEVELOPER IDENTITY & PERMISSION INDICATORS:</h6>
                <ul className="list-group list-group-flush bg-transparent">
                  {(result.heuristic_findings || []).map((f, i) => (
                    <li key={i} className="list-group-item bg-transparent text-secondary small px-0 py-1 border-secondary border-opacity-10 d-flex align-items-start gap-2">
                      <i className="bi bi-arrow-right-short text-info fs-5 lh-1" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Drebin ML Findings */}
              {result.app_ml_findings && (
                <div className="p-3 rounded mb-3" style={{ background: 'rgba(245, 158, 11, 0.05)', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
                  <div className="fw-semibold text-light small mb-1">
                    <i className="bi bi-cpu text-warning me-1" /> Drebin Android Malware Classifier:
                  </div>
                  <div className="text-secondary small">
                    Prediction: <strong className="text-light">{result.app_ml_findings.prediction || 'Benign'}</strong> • Probability: {result.app_ml_findings.probability || 'N/A'}
                  </div>
                </div>
              )}

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
              <i className="bi bi-phone text-secondary fs-1 mb-3 opacity-50" />
              <h5 className="text-light fw-bold">Awaiting Mobile Application Listing</h5>
              <p className="text-secondary small" style={{ maxWidth: 360 }}>
                Enter app package metadata or select a baseline sample to verify publisher identity against registered corporate developer credentials.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
