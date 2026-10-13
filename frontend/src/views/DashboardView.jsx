import React, { useState, useEffect } from 'react';
import api from '../api';

export default function DashboardView({ onNavigate, onSelectScan }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    setLoading(true);
    const res = await api.dashboard.getStats();
    if (res.ok) {
      setStats(res.data);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const totalScans = stats?.total_scans ?? 0;
  const highRisk = stats?.high_risk ?? 0;
  const suspicious = stats?.suspicious ?? 0;
  const brandsCount = stats?.brands_count ?? 5;
  const recentScans = stats?.recent_scans ?? [];

  return (
    <div className="container-fluid px-0">
      {/* KPI Cards Row */}
      <div className="row g-3 mb-4">
        {/* Total Scans */}
        <div className="col-12 col-sm-6 col-xl-3">
          <div className="kpi-card">
            <div className="kpi-icon-box bg-info bg-opacity-10 text-cyan border border-info border-opacity-25">
              <i className="bi bi-shield-check fs-4" />
            </div>
            <div className="kpi-content">
              <div className="kpi-label">TOTAL SCANS EXECUTED</div>
              <div className="kpi-value text-light">{loading ? '...' : totalScans}</div>
              <div className="kpi-trend text-info small">
                <i className="bi bi-activity me-1" /> Continuous Multi-Vector
              </div>
            </div>
          </div>
        </div>

        {/* High Risk Flags */}
        <div className="col-12 col-sm-6 col-xl-3">
          <div className="kpi-card">
            <div className="kpi-icon-box bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25">
              <i className="bi bi-shield-x fs-4" />
            </div>
            <div className="kpi-content">
              <div className="kpi-label">HIGH RISK ANOMALIES</div>
              <div className="kpi-value text-danger">{loading ? '...' : highRisk}</div>
              <div className="kpi-trend text-danger small">
                <i className="bi bi-exclamation-triangle me-1" /> Remediation Required
              </div>
            </div>
          </div>
        </div>

        {/* Suspicious Alerts */}
        <div className="col-12 col-sm-6 col-xl-3">
          <div className="kpi-card">
            <div className="kpi-icon-box bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25">
              <i className="bi bi-exclamation-octagon fs-4" />
            </div>
            <div className="kpi-content">
              <div className="kpi-label">SUSPICIOUS SIGNALS</div>
              <div className="kpi-value text-warning">{loading ? '...' : suspicious}</div>
              <div className="kpi-trend text-warning small">
                <i className="bi bi-eye me-1" /> Heuristic Flags
              </div>
            </div>
          </div>
        </div>

        {/* Protected Brands */}
        <div className="col-12 col-sm-6 col-xl-3">
          <div className="kpi-card">
            <div className="kpi-icon-box bg-primary bg-opacity-10 text-purple border border-primary border-opacity-25">
              <i className="bi bi-buildings fs-4" />
            </div>
            <div className="kpi-content">
              <div className="kpi-label">PROTECTED ASSETS</div>
              <div className="kpi-value text-purple">{loading ? '...' : brandsCount}</div>
              <div className="kpi-trend text-cyan small">
                <i className="bi bi-patch-check me-1" /> Official Brand Registry
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Surface Quick Checkers & Neural Telemetry */}
      <div className="row g-4 mb-4">
        {/* Quick Launch Cards */}
        <div className="col-lg-7">
          <div className="cyber-panel p-4 h-100">
            <div className="d-flex align-items-center justify-content-between mb-3">
              <h5 className="text-light fw-bold m-0 d-flex align-items-center gap-2">
                <i className="bi bi-radar text-info" /> Surface Surveillance Engines
              </h5>
              <button className="btn btn-sm btn-cyber-secondary" onClick={fetchStats} title="Refresh stats">
                <i className="bi bi-arrow-clockwise me-1" /> Refresh
              </button>
            </div>
            <p className="text-secondary small mb-4">
              Inspect suspicious assets across social platforms, web domains, and third-party app stores using multi-model ML classifiers and static heuristics.
            </p>

            <div className="row g-3">
              <div className="col-md-4">
                <div
                  className="card bg-dark bg-opacity-50 border border-secondary border-opacity-25 p-3 h-100 cursor-pointer hover-card"
                  onClick={() => onNavigate('social')}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="d-flex align-items-center gap-2 text-info mb-2">
                    <i className="bi bi-person-badge fs-4" />
                    <span className="fw-semibold small">Social Shield</span>
                  </div>
                  <p className="text-secondary small mb-3">
                    Analyze lookalike handles, bio lures, and bot signals.
                  </p>
                  <span className="text-cyan small fw-semibold mt-auto d-inline-flex align-items-center gap-1">
                    Scan Profile <i className="bi bi-arrow-right" />
                  </span>
                </div>
              </div>

              <div className="col-md-4">
                <div
                  className="card bg-dark bg-opacity-50 border border-secondary border-opacity-25 p-3 h-100 cursor-pointer hover-card"
                  onClick={() => onNavigate('link')}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="d-flex align-items-center gap-2 text-purple mb-2">
                    <i className="bi bi-link-45deg fs-4" />
                    <span className="fw-semibold small">Link Inspector</span>
                  </div>
                  <p className="text-secondary small mb-3">
                    Typosquatting and static lexical phishing analysis.
                  </p>
                  <span className="text-purple small fw-semibold mt-auto d-inline-flex align-items-center gap-1">
                    Inspect Link <i className="bi bi-arrow-right" />
                  </span>
                </div>
              </div>

              <div className="col-md-4">
                <div
                  className="card bg-dark bg-opacity-50 border border-secondary border-opacity-25 p-3 h-100 cursor-pointer hover-card"
                  onClick={() => onNavigate('app')}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="d-flex align-items-center gap-2 text-warning mb-2">
                    <i className="bi bi-phone fs-4" />
                    <span className="fw-semibold small">App Store Risk</span>
                  </div>
                  <p className="text-secondary small mb-3">
                    Rogue APK packages & Android permission inspection.
                  </p>
                  <span className="text-warning small fw-semibold mt-auto d-inline-flex align-items-center gap-1">
                    Verify APK <i className="bi bi-arrow-right" />
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Machine Learning Telemetry */}
        <div className="col-lg-5">
          <div className="cyber-panel p-4 h-100">
            <h5 className="text-light fw-bold mb-3 d-flex align-items-center gap-2">
              <i className="bi bi-cpu text-info" /> Machine Learning Classifiers
            </h5>
            <div className="space-y-3">
              <div className="p-3 rounded mb-3" style={{ background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="fw-semibold text-light small"><i className="bi bi-link-45deg text-info me-1" /> Phishing URL RandomForest</span>
                  <span className="badge bg-info text-dark font-monospace">97.8% ACC</span>
                </div>
                <small className="text-secondary d-block">Trained on 18,000+ verified phishing vs benign links.</small>
              </div>

              <div className="p-3 rounded mb-3" style={{ background: 'rgba(129, 140, 248, 0.05)', border: '1px solid rgba(129, 140, 248, 0.2)' }}>
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="fw-semibold text-light small"><i className="bi bi-person-bounding-box text-purple me-1" /> Social Profile Bot Classifier</span>
                  <span className="badge bg-purple text-dark font-monospace">98.3% ACC</span>
                </div>
                <small className="text-secondary d-block">Cresci et al. (2017) academic dataset benchmark.</small>
              </div>

              <div className="p-3 rounded" style={{ background: 'rgba(245, 158, 11, 0.05)', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="fw-semibold text-light small"><i className="bi bi-phone text-warning me-1" /> Mobile Malware Drebin Model</span>
                  <span className="badge bg-warning text-dark font-monospace">95.7% ACC</span>
                </div>
                <small className="text-secondary d-block">215 permission extraction vectors analyzing APK demands.</small>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Audit Log Table */}
      <div className="cyber-panel p-4">
        <div className="d-flex align-items-center justify-content-between mb-3">
          <div>
            <h5 className="text-light fw-bold m-0 d-flex align-items-center gap-2">
              <i className="bi bi-clock-history text-info" /> Recent Security Assessments
            </h5>
            <small className="text-secondary">Cryptographically logged scan audit telemetry</small>
          </div>
          <button className="btn btn-sm btn-cyber-secondary" onClick={() => onNavigate('history')}>
            View Full Log ({totalScans}) <i className="bi bi-arrow-right ms-1" />
          </button>
        </div>

        <div className="table-responsive">
          <table className="table table-dark table-hover align-middle mb-0" style={{ background: 'transparent' }}>
            <thead>
              <tr className="text-secondary small border-secondary border-opacity-25">
                <th>VECTOR</th>
                <th>TARGET</th>
                <th>BRAND TARGET</th>
                <th>RISK LEVEL</th>
                <th>REASON</th>
                <th>TIMESTAMP</th>
                <th className="text-end">ACTION</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center py-4 text-secondary">
                    No scans logged yet. Launch an analysis above to populate audit records.
                  </td>
                </tr>
              ) : (
                recentScans.slice(0, 8).map((s) => (
                  <tr key={s.id} className="border-secondary border-opacity-10">
                    <td>
                      <span className="badge bg-dark border border-secondary text-info text-uppercase font-monospace" style={{ fontSize: '0.7rem' }}>
                        {s.scan_type}
                      </span>
                    </td>
                    <td className="text-light fw-semibold small text-truncate" style={{ maxWidth: 220 }}>
                      {s.input_title}
                    </td>
                    <td className="small text-secondary">{s.target_brand_name || 'General'}</td>
                    <td>
                      <span className={`badge ${
                        s.risk_category === 'HIGH RISK' ? 'bg-danger' :
                        s.risk_category === 'SUSPICIOUS' ? 'bg-warning text-dark' : 'bg-success'
                      }`} style={{ fontSize: '0.72rem' }}>
                        {s.risk_category} ({s.risk_score})
                      </span>
                    </td>
                    <td className="small text-secondary text-truncate" style={{ maxWidth: 240 }}>
                      {s.summary_reason || 'N/A'}
                    </td>
                    <td className="small text-secondary font-monospace" style={{ fontSize: '0.7rem' }}>
                      {s.created_at ? new Date(s.created_at).toLocaleString() : 'Just now'}
                    </td>
                    <td className="text-end">
                      <button
                        className="btn btn-xs btn-outline-info py-0 px-2 small"
                        style={{ fontSize: '0.72rem' }}
                        onClick={() => onSelectScan(s.id)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
