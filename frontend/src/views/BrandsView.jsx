import React, { useState, useEffect } from 'react';
import api from '../api';

export default function BrandsView() {
  const [brands, setBrands] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [alert, setAlert] = useState(null);

  // Form fields
  const [name, setName] = useState('');
  const [category, setCategory] = useState('Banking & Finance');
  const [description, setDescription] = useState('');
  const [handles, setHandles] = useState('');
  const [domains, setDomains] = useState('');
  const [developers, setDevelopers] = useState('');

  const fetchBrands = async () => {
    setLoading(true);
    const res = await api.brands.getAll();
    if (res.ok) {
      setBrands(res.data.brands || []);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchBrands();
  }, []);

  const handleAddBrand = async (e) => {
    e.preventDefault();
    const res = await api.brands.add({
      name,
      category,
      description,
      handles,
      domains,
      developers,
    });
    if (res.ok) {
      setAlert({ type: 'success', message: res.data.message || `Brand '${name}' added successfully.` });
      setShowAddModal(false);
      setName('');
      setDescription('');
      setHandles('');
      setDomains('');
      setDevelopers('');
      fetchBrands();
    } else {
      setAlert({ type: 'danger', message: res.error || 'Failed to add brand.' });
    }
  };

  const handleDelete = async (id, brandName) => {
    if (!window.confirm(`Are you sure you want to remove '${brandName}' from the registry?`)) return;
    const res = await api.brands.delete(id);
    if (res.ok) {
      setAlert({ type: 'info', message: `Brand '${brandName}' removed from registry.` });
      fetchBrands();
    }
  };

  const handleReset = async () => {
    if (!window.confirm("Reset registry with default demo brands and baseline scan data?")) return;
    const res = await api.brands.reset();
    if (res.ok) {
      setAlert({ type: 'success', message: "Database reset with default 5 demo brands." });
      fetchBrands();
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

      {/* Header Bar */}
      <div className="d-flex flex-column flex-sm-row align-items-sm-center justify-content-between gap-3 mb-4">
        <div>
          <h4 className="text-light fw-bold m-0 d-flex align-items-center gap-2">
            <i className="bi bi-buildings text-info" /> Authorized Brand Registry
          </h4>
          <span className="text-secondary small">
            Authoritative corporate assets used as truth baselines for typosquatting and impersonation heuristics.
          </span>
        </div>
        <div className="d-flex align-items-center gap-2">
          <button className="btn btn-sm btn-cyber-secondary" onClick={handleReset}>
            <i className="bi bi-arrow-counterclockwise me-1" /> Reset Baseline
          </button>
          <button className="btn btn-sm btn-cyber-primary" onClick={() => setShowAddModal(true)}>
            <i className="bi bi-plus-lg me-1" /> Add Brand
          </button>
        </div>
      </div>

      {/* Brands Grid */}
      <div className="row g-3">
        {loading ? (
          <div className="col-12 text-center py-5 text-secondary">
            <span className="spinner-border spinner-border-sm me-2" /> Loading Brand Registry...
          </div>
        ) : brands.length === 0 ? (
          <div className="col-12 text-center py-5 text-secondary">
            No brands registered. Click "Add Brand" above to register one.
          </div>
        ) : (
          brands.map((b) => (
            <div key={b.id} className="col-md-6 col-xl-4">
              <div className="cyber-panel p-4 h-100 d-flex flex-column position-relative">
                <div className="d-flex align-items-center justify-content-between mb-2">
                  <div className="d-flex align-items-center gap-2">
                    <div className="brand-hologram-shield" style={{ width: 32, height: 32 }}>
                      <i className="bi bi-shield-fill-check text-cyan fs-5" />
                    </div>
                    <h5 className="text-light fw-bold m-0">{b.name}</h5>
                  </div>
                  <button
                    className="btn btn-sm btn-link text-danger p-0 opacity-75 hover-opacity-100"
                    title="Delete Brand"
                    onClick={() => handleDelete(b.id, b.name)}
                  >
                    <i className="bi bi-trash" />
                  </button>
                </div>

                <span className="badge bg-dark border border-secondary text-info small mb-3 align-self-start font-monospace" style={{ fontSize: '0.68rem' }}>
                  {b.category || 'Enterprise Asset'}
                </span>

                <p className="text-secondary small mb-3 flex-grow-1">
                  {b.description || 'Corporate entity registered under continuous surveillance.'}
                </p>

                {/* Authoritative Assets */}
                <div className="border-top border-secondary border-opacity-25 pt-3 space-y-2">
                  <div className="small mb-1">
                    <span className="text-secondary me-2"><i className="bi bi-at text-info" /> Handles:</span>
                    <span className="text-light font-monospace">
                      {Array.isArray(b.official_handles) ? b.official_handles.join(', ') : b.official_handles || 'None'}
                    </span>
                  </div>
                  <div className="small mb-1">
                    <span className="text-secondary me-2"><i className="bi bi-globe text-cyan" /> Domains:</span>
                    <span className="text-light font-monospace">
                      {Array.isArray(b.official_domains) ? b.official_domains.join(', ') : b.official_domains || 'None'}
                    </span>
                  </div>
                  <div className="small">
                    <span className="text-secondary me-2"><i className="bi bi-person-gear text-warning" /> Developers:</span>
                    <span className="text-light font-monospace">
                      {Array.isArray(b.verified_developers) ? b.verified_developers.join(', ') : b.verified_developers || 'None'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Add Brand Modal */}
      {showAddModal && (
        <div className="modal fade show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(3, 7, 18, 0.85)', backdropFilter: 'blur(8px)', zIndex: 1060 }}>
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content guardian-slider-modal">
              <div className="modal-header border-0 pb-0 d-flex justify-content-between align-items-center">
                <h5 className="text-light fw-bold m-0"><i className="bi bi-shield-plus text-info me-2" /> Register New Brand</h5>
                <button type="button" className="btn btn-sm btn-link text-secondary" onClick={() => setShowAddModal(false)}>
                  <i className="bi bi-x-lg" />
                </button>
              </div>
              <form onSubmit={handleAddBrand}>
                <div className="modal-body py-4">
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Brand / Corporate Name *</label>
                    <input
                      type="text"
                      className="form-control input-cyber"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. ApexBank"
                      required
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Industry Category</label>
                    <select
                      className="form-select input-cyber"
                      value={category}
                      onChange={(e) => setCategory(e.target.value)}
                    >
                      <option value="Banking & Finance">Banking & Finance</option>
                      <option value="Cloud & Cyber Defense">Cloud & Cyber Defense</option>
                      <option value="Healthcare & BioTech">Healthcare & BioTech</option>
                      <option value="Media & Streaming">Media & Streaming</option>
                      <option value="Retail & E-Commerce">Retail & E-Commerce</option>
                    </select>
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Description</label>
                    <textarea
                      className="form-control input-cyber"
                      rows="2"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Brief description of the corporate entity."
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Official Social Handles (comma or newline separated)</label>
                    <input
                      type="text"
                      className="form-control input-cyber"
                      value={handles}
                      onChange={(e) => setHandles(e.target.value)}
                      placeholder="@apexbank, @apex_official"
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Official Domains (comma separated)</label>
                    <input
                      type="text"
                      className="form-control input-cyber"
                      value={domains}
                      onChange={(e) => setDomains(e.target.value)}
                      placeholder="apexbank.com, apex.io"
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label text-light small fw-semibold">Verified Mobile Developer Names</label>
                    <input
                      type="text"
                      className="form-control input-cyber"
                      value={developers}
                      onChange={(e) => setDevelopers(e.target.value)}
                      placeholder="Apex Financial Technologies LLC"
                    />
                  </div>
                </div>
                <div className="modal-footer border-0 pt-0">
                  <button type="button" className="btn btn-sm btn-cyber-secondary" onClick={() => setShowAddModal(false)}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-sm btn-cyber-primary">
                    <i className="bi bi-check2-circle me-1" /> Save Brand Registry
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
