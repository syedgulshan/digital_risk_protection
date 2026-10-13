import React, { useState, useEffect } from 'react';

export default function OnboardingModal({ isOpen, onClose }) {
  const [currentSlide, setCurrentSlide] = useState(1);
  const totalSlides = 4;

  useEffect(() => {
    function handleKeyDown(e) {
      if (!isOpen) return;
      if (e.key === 'ArrowRight') {
        setCurrentSlide((s) => Math.min(totalSlides, s + 1));
      } else if (e.key === 'ArrowLeft') {
        setCurrentSlide((s) => Math.max(1, s - 1));
      } else if (e.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="modal fade show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(3, 7, 18, 0.85)', backdropFilter: 'blur(8px)', zIndex: 1060 }}>
      <div className="modal-dialog modal-dialog-centered modal-lg">
        <div className="modal-content guardian-slider-modal">
          {/* Modal Header */}
          <div className="modal-header border-0 pb-0 d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center gap-2">
              <span className="badge badge-ai-neon">ONBOARDING TOUR</span>
              <span className="text-secondary small font-monospace">SLIDE {currentSlide} / {totalSlides}</span>
            </div>
            <button type="button" className="btn btn-sm btn-link text-secondary text-decoration-none" onClick={onClose}>
              Skip Tour <i className="bi bi-x-lg ms-1" />
            </button>
          </div>

          {/* Modal Body with 4 Slides */}
          <div className="modal-body py-4">
            <div className="guardian-slides-wrapper">
              {/* SLIDE 1: URL Threat Detection */}
              {currentSlide === 1 && (
                <div className="guardian-slide active">
                  <div className="row align-items-center g-4">
                    <div className="col-md-6 text-center">
                      <div className="slide-visual-box visual-url-scan">
                        <div className="url-hologram-grid" />
                        <div className="url-scan-beam" />
                        <div className="url-input-chip">
                          <i className="bi bi-link-45deg text-info" />
                          <span>apexbank-login-secure.xyz</span>
                        </div>
                        <div className="threat-telemetry-badge">
                          <span className="badge bg-danger"><i className="bi bi-shield-x me-1" /> HIGH RISK PHISH</span>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center gap-2 mb-2">
                        <span className="slide-number-badge">01</span>
                        <span className="badge bg-info bg-opacity-10 text-info font-monospace">SURFACE DEFENSE</span>
                      </div>
                      <h3 className="fs-4 fw-bold text-light mb-3">URL Threat & Typosquat Detection</h3>
                      <p className="text-secondary small mb-3">
                        BrandShield AI performs static lexical feature extraction, subdomain depth analysis, and typosquatting distance verification against authorized domains.
                      </p>
                      <ul className="slide-feature-list small text-secondary">
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Syntactic URL inspection without visiting dangerous destinations.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Integrated with VirusTotal v3 API for threat intelligence correlation.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />RandomForest ML model trained on benchmark links (97.8% Accuracy).</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* SLIDE 2: Social Profile Protection */}
              {currentSlide === 2 && (
                <div className="guardian-slide active">
                  <div className="row align-items-center g-4">
                    <div className="col-md-6 text-center">
                      <div className="slide-visual-box visual-social-scan">
                        <div className="social-node official">
                          <i className="bi bi-patch-check-fill text-info" />
                          <span>@apexbank</span>
                        </div>
                        <div className="social-connector" />
                        <div className="social-node rogue">
                          <i className="bi bi-person-x-fill text-danger" />
                          <span>@apexbank_support_help</span>
                          <small className="badge bg-danger ms-1">Impersonator</small>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center gap-2 mb-2">
                        <span className="slide-number-badge">02</span>
                        <span className="badge bg-purple bg-opacity-10 text-purple font-monospace">IDENTITY DEFENSE</span>
                      </div>
                      <h3 className="fs-4 fw-bold text-light mb-3">Social Profile Impersonation Shield</h3>
                      <p className="text-secondary small mb-3">
                        Detects look-alike handles, unauthorized support lures, digit-padding, and deceptive bios across Twitter/X, Instagram, Telegram, and LinkedIn.
                      </p>
                      <ul className="slide-feature-list small text-secondary">
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Fuzzy token similarity analysis against registered brand handles.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />RandomForest bot detector trained on Cresci et al. academic benchmark.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Rule 8 Notice: Platform domain reputation does not equate to account authenticity.</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* SLIDE 3: Mobile App Risk Analysis */}
              {currentSlide === 3 && (
                <div className="guardian-slide active">
                  <div className="row align-items-center g-4">
                    <div className="col-md-6 text-center">
                      <div className="slide-visual-box visual-app-scan">
                        <div className="phone-frame">
                          <div className="phone-screen">
                            <i className="bi bi-phone text-warning fs-3 mb-1" />
                            <div className="small fw-bold text-light">ApexBank APK</div>
                            <div className="badge bg-warning text-dark font-monospace" style={{ fontSize: '0.65rem' }}>SUSPICIOUS PERMS</div>
                          </div>
                        </div>
                        <div className="shield-scan-ring" />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center gap-2 mb-2">
                        <span className="slide-number-badge">03</span>
                        <span className="badge bg-warning bg-opacity-10 text-warning font-monospace">APPLICATION DEFENSE</span>
                      </div>
                      <h3 className="fs-4 fw-bold text-light mb-3">Mobile App Risk & APK Analysis</h3>
                      <p className="text-secondary small mb-3">
                        Inspects third-party APK listings, clones, trojanized finance apps, and unauthorized publisher identities using permission risk profiling.
                      </p>
                      <ul className="slide-feature-list small text-secondary">
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Verification against authoritative brand developer registries.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Drebin benchmark ML classifier evaluating 215 Android permission features.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Correlates SHA-256 APK signatures with threat intelligence databases.</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* SLIDE 4: Security Intelligence Dashboard */}
              {currentSlide === 4 && (
                <div className="guardian-slide active">
                  <div className="row align-items-center g-4">
                    <div className="col-md-6 text-center">
                      <div className="slide-visual-box visual-dash-preview">
                        <div className="radar-circle-outer" />
                        <div className="radar-sweep-beam" />
                        <div className="center-brand-core">
                          <i className="bi bi-shield-check text-info fs-3" />
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center gap-2 mb-2">
                        <span className="slide-number-badge">04</span>
                        <span className="badge bg-success bg-opacity-10 text-success font-monospace">AUDIT & COMPLIANCE</span>
                      </div>
                      <h3 className="fs-4 fw-bold text-light mb-3">Enterprise Command & Audit Trail</h3>
                      <p className="text-secondary small mb-3">
                        Every assessment is cryptographically logged with risk scores, indicators, timestamps, and actionable remediation guidelines.
                      </p>
                      <ul className="slide-feature-list small text-secondary">
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Unified KPI metrics: Total Scans, High-Risk Flags, and Surface Exposure.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Export audits as CSV or JSON for compliance and incident response.</li>
                        <li><i className="bi bi-check2-circle text-cyan me-2" />Interactive Guardian AI companion assisting analysts across workflows.</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Modal Footer Controls */}
          <div className="modal-footer border-0 pt-0 d-flex justify-content-between align-items-center">
            {/* Progress Dots */}
            <div className="slider-progress-dots">
              {[1, 2, 3, 4].map((num) => (
                <button
                  key={num}
                  type="button"
                  className={`dot ${currentSlide === num ? 'active' : ''}`}
                  onClick={() => setCurrentSlide(num)}
                  aria-label={`Slide ${num}`}
                />
              ))}
            </div>

            {/* Navigation Buttons */}
            <div className="d-flex align-items-center gap-2">
              <button
                type="button"
                className="btn btn-sm btn-cyber-secondary"
                disabled={currentSlide === 1}
                onClick={() => setCurrentSlide((s) => s - 1)}
              >
                <i className="bi bi-arrow-left me-1" /> Prev
              </button>
              {currentSlide < totalSlides ? (
                <button
                  type="button"
                  className="btn btn-sm btn-cyber-primary"
                  onClick={() => setCurrentSlide((s) => s + 1)}
                >
                  Next <i className="bi bi-arrow-right ms-1" />
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-sm btn-cyber-success"
                  onClick={onClose}
                >
                  Get Started <i className="bi bi-rocket-takeoff ms-1" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
