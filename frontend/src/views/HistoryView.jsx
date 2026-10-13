import React, { useState, useEffect } from 'react';
import api from '../api';

export default function HistoryView({ onSelectScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanType, setScanType] = useState('all');
  const [riskCategory, setRiskCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchHistory = async () => {
    setLoading(true);
    const params = {};
    if (scanType !== 'all') params.type = scanType;
    if (riskCategory !== 'all') params.risk = riskCategory;
    if (searchQuery.trim()) params.q = searchQuery.trim();

    const res = await api.history.getAll(params);
    if (res.ok) {
      setScans(res.data.scans || []);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchHistory();
  }, [scanType, riskCategory]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchHistory();
  };

  return (
    <div className="container-fluid px-0">
      {/* Header Bar */}
      <div className="d-flex flex-column flex-sm-row align-items-sm-center justify-content-between gap-3 mb-4">
        <div>
          <h4 className="text-light fw-bold m-0 d-flex align-items-center gap-2">
            <i className="bi bi-clock-history text-info" /> Security Scan Intelligence Log
          </h4>
          <span className="text-secondary small">
            Cryptographically stamped assessment records ready for enterprise compliance and threat audit exports.
          </span>
        </div>
        <div className="d-flex align-items-center gap-2">
          <a
            href={api.history.exportCsvUrl()}
            target="_blank"
            rel="noreferrer"
            className="btn btn-sm btn-cyber-secondary"
          >
            <i className="bi bi-file-earmark-spreadsheet me-1" /> Export CSV
          </a>
          <a
            href={api.history.exportJsonUrl()}
            target="_blank"
            rel="noreferrer"
            className="btn btn-sm btn-cyber-secondary"
          >
            <i className="bi bi-file-earmark-code me-1" /> Export JSON
          </a>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="cyber-panel p-3 mb-4">
        <form onSubmit={handleSearchSubmit} className="row g-2 align-items-center">
          <div className="col-12 col-md-4">
            <div className="input-cyber-group">
              <i className="bi bi-search input-cyber-icon" />
              <input
                type="text"
                className="form-control input-cyber"
                style={{ paddingLeft: '2.4rem' }}
                placeholder="Search targets or brand names..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>
          <div className="col-6 col-md-3">
            <select
              className="form-select input-cyber"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="all">All Surface Vectors</option>
              <option value="link">URL & Phishing Links</option>
              <option value="social">Social Media Profiles</option>
              <option value="app">Mobile App Listings</option>
            </select>
          </div>
          <div className="col-6 col-md-3">
            <select
              className="form-select input-cyber"
              value={riskCategory}
              onChange={(e) => setRiskCategory(e.target.value)}
            >
              <option value="all">All Risk Levels</option>
              <option value="HIGH RISK">HIGH RISK Only</option>
              <option value="SUSPICIOUS">SUSPICIOUS Only</option>
              <option value="LOW RISK">LOW RISK Only</option>
            </select>
          </div>
          <div className="col-12 col-md-2 d-flex gap-2">
            <button type="submit" className="btn btn-cyber-primary w-100">
              Filter
            </button>
            <button
              type="button"
              className="btn btn-cyber-secondary"
              onClick={() => { setSearchQuery(''); setScanType('all'); setRiskCategory('all'); }}
              title="Reset Filters"
            >
              <i className="bi bi-x-circle" />
            </button>
          </div>
        </form>
      </div>

      {/* Audit Log Table */}
      <div className="cyber-panel p-4">
        <div className="d-flex align-items-center justify-content-between mb-3">
          <span className="text-secondary small font-monospace">
            MATCHING AUDIT RECORDS: <strong className="text-light">{scans.length}</strong>
          </span>
          <button className="btn btn-xs btn-outline-info" onClick={fetchHistory}>
            <i className="bi bi-arrow-clockwise me-1" /> Refresh Records
          </button>
        </div>

        <div className="table-responsive">
          <table className="table table-dark table-hover align-middle mb-0" style={{ background: 'transparent' }}>
            <thead>
              <tr className="text-secondary small border-secondary border-opacity-25">
                <th>ID</th>
                <th>VECTOR</th>
                <th>INPUT TARGET</th>
                <th>PROTECTED BRAND</th>
                <th>RISK STATUS</th>
                <th>ASSESSMENT REASON</th>
                <th>TIMESTAMP</th>
                <th className="text-end">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="8" className="text-center py-5 text-secondary">
                    <span className="spinner-border spinner-border-sm me-2" /> Loading Audit Log...
                  </td>
                </tr>
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan="8" className="text-center py-5 text-secondary">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="border-secondary border-opacity-10">
                    <td className="font-monospace text-secondary small">#{s.id}</td>
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
                        {s.risk_category} ({s.risk_score}/100)
                      </span>
                    </td>
                    <td className="small text-secondary text-truncate" style={{ maxWidth: 260 }}>
                      {s.summary_reason || 'N/A'}
                    </td>
                    <td className="small text-secondary font-monospace" style={{ fontSize: '0.7rem' }}>
                      {s.created_at ? new Date(s.created_at).toLocaleString() : 'N/A'}
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
