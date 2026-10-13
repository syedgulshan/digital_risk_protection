import React, { useState, useEffect } from 'react';
import api from '../api';

export default function ScanDetailModal({ scanId, onClose }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    async function load() {
      setLoading(true);
      const res = await api.history.getScan(scanId);
      if (res.ok) {
        setScan(res.data.scan);
      }
      setLoading(false);
    }
    load();
  }, [scanId]);

  if (!scanId) return null;

  return (
    <div className="modal fade show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(3, 7, 18, 0.85)', backdropFilter: 'blur(8px)', zIndex: 1070 }}>
      <div className="modal-dialog modal-dialog-centered modal-lg">
        <div className="modal-content guardian-slider-modal">
          <div className="modal-header border-0 pb-0 d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center gap-2">
              <span className="badge badge-ai-neon">AUDIT RECORD #{scanId}</span>
              {scan && (
                <span className={`badge ${
                  scan.risk_category === 'HIGH RISK' ? 'bg-danger' :
                  scan.risk_category === 'SUSPICIOUS' ? 'bg-warning text-dark' : 'bg-success'
                }`}>
                  {scan.risk_category} ({scan.risk_score}/100)
                </span>
              )}
            </div>
            <button type="button" className="btn btn-sm btn-link text-secondary" onClick={onClose}>
              <i className="bi bi-x-lg" />
            </button>
          </div>

          <div className="modal-body py-4">
            {loading ? (
              <div className="text-center py-5 text-secondary">
                <span className="spinner-border spinner-border-sm me-2" /> Loading Audit Evidence...
              </div>
            ) : !scan ? (
              <div className="text-center py-5 text-danger">Audit record not found.</div>
            ) : (
              <div>
                <h4 className="text-light fw-bold mb-1">{scan.input_title}</h4>
                <div className="text-secondary small font-monospace mb-4">
                  Vector: <span className="text-info">{scan.scan_type.toUpperCase()}</span> • Protected Brand: <span className="text-cyan">{scan.target_brand_name || 'General'}</span> • Timestamp: {new Date(scan.created_at).toLocaleString()}
                </div>

                <div className="alert bg-dark border-secondary border-opacity-50 text-light small mb-4">
                  <strong>Summary Reason:</strong> {scan.summary_reason}
                </div>

                {/* Indicators */}
                <div className="mb-4">
                  <h6 className="text-cyan small fw-bold mb-2">HEURISTIC INDICATORS ({Array.isArray(scan.indicators) ? scan.indicators.length : 0}):</h6>
                  <div className="p-3 rounded bg-dark bg-opacity-50 border border-secondary border-opacity-25">
                    {Array.isArray(scan.indicators) && scan.indicators.length > 0 ? (
                      <ul className="list-group list-group-flush bg-transparent mb-0">
                        {scan.indicators.map((ind, i) => (
                          <li key={i} className="list-group-item bg-transparent text-secondary small px-0 py-1 border-secondary border-opacity-10 d-flex align-items-start gap-2">
                            <i className="bi bi-arrow-right-short text-info fs-5 lh-1" />
                            <span>{ind}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span className="text-secondary small">No adverse heuristic flags recorded.</span>
                    )}
                  </div>
                </div>

                {/* Recommendations */}
                {Array.isArray(scan.recommendations) && scan.recommendations.length > 0 && (
                  <div className="mb-4">
                    <h6 className="text-success small fw-bold mb-2">SECURITY RECOMMENDATIONS:</h6>
                    <div className="p-3 rounded bg-dark bg-opacity-50 border border-secondary border-opacity-25">
                      <ul className="list-group list-group-flush bg-transparent mb-0">
                        {scan.recommendations.map((rec, i) => (
                          <li key={i} className="list-group-item bg-transparent text-light small px-0 py-1 border-secondary border-opacity-10 d-flex align-items-start gap-2">
                            <i className="bi bi-check2-circle text-success fs-6 lh-1" />
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}

                {/* Raw Evidence Payload */}
                <div>
                  <h6 className="text-secondary small fw-bold mb-2">TELEMETRY PAYLOAD:</h6>
                  <pre className="p-3 rounded bg-dark border border-secondary border-opacity-25 text-info small mb-0 font-monospace overflow-auto" style={{ maxHeight: 180, fontSize: '0.72rem' }}>
                    {JSON.stringify(scan.input_details || {}, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>

          <div className="modal-footer border-0 pt-0">
            <button type="button" className="btn btn-sm btn-cyber-secondary" onClick={onClose}>
              Close Inspector
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
