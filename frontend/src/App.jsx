import React, { useState, useEffect } from 'react';
import api from './api';

// Components
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import OnboardingModal from './components/OnboardingModal';
import ScanDetailModal from './components/ScanDetailModal';

// Views
import LoginView from './views/LoginView';
import DashboardView from './views/DashboardView';
import BrandsView from './views/BrandsView';
import LinkCheckerView from './views/LinkCheckerView';
import SocialCheckerView from './views/SocialCheckerView';
import AppCheckerView from './views/AppCheckerView';
import HistoryView from './views/HistoryView';

export default function App() {
  const [user, setUser] = useState(() => api.auth.getStoredUser());
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [currentView, setCurrentView] = useState('dashboard'); // 'dashboard' | 'brands' | 'social' | 'link' | 'app' | 'history'
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [tourOpen, setTourOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [brandCount, setBrandCount] = useState(5);
  const [telemetry, setTelemetry] = useState({});

  // Verify active server session on mount
  useEffect(() => {
    async function initSession() {
      try {
        const [meRes, statusRes, brandsRes] = await Promise.all([
          api.auth.getMe(),
          api.getStatus(),
          api.brands.getAll()
        ]);

        if (meRes.ok && meRes.data?.authenticated) {
          setUser(meRes.data.user);
        } else if (!api.auth.getStoredUser()) {
          setUser(null);
        }

        if (statusRes.ok) {
          setTelemetry(statusRes.data || {});
        }

        if (brandsRes.ok && brandsRes.data?.brands) {
          setBrandCount(brandsRes.data.brands.length);
        }
      } catch (err) {
        console.warn('Initial session check failed:', err);
      } finally {
        setCheckingAuth(false);
      }
    }

    initSession();
  }, []);

  const handleAuthSuccess = (authenticatedUser) => {
    setUser(authenticatedUser);
    setCurrentView('dashboard');
  };

  const handleLogout = async () => {
    await api.auth.logout();
    setUser(null);
  };

  // View titles
  const viewMeta = {
    dashboard: {
      title: 'Threat Command Center',
      subtitle: 'Enterprise Digital Footprint Surveillance & Impersonation Defense',
    },
    brands: {
      title: 'Authorized Brand Registry',
      subtitle: 'Authoritative Digital Assets & Verified Identities',
    },
    social: {
      title: 'Social Profile Impersonation Shield',
      subtitle: 'Lookalike Handle Entropy, Cresci Bot Heuristics & Platform Reputation Checks',
    },
    link: {
      title: 'Suspicious Link & Phishing Analyzer',
      subtitle: 'Syntactic Lexical Feature Extraction & VirusTotal v3 Intelligence',
    },
    app: {
      title: 'Mobile App Store Listing Inspector',
      subtitle: 'Publisher Identity Verification & Drebin Permission Profiling',
    },
    history: {
      title: 'Security Scan Intelligence Log',
      subtitle: 'Cryptographically Stamped Assessment Telemetry & Incident Audit Trails',
    },
  };

  // Show loading spinner during initial clearance check
  if (checkingAuth) {
    return (
      <div className="guardian-universe-body min-vh-100 d-flex flex-column align-items-center justify-content-center text-center">
        <div className="brand-hologram-shield mb-3" style={{ width: 48, height: 48 }}>
          <i className="bi bi-shield-check text-cyan fs-2" />
        </div>
        <div className="spinner-border text-info mb-2" role="status" />
        <span className="text-secondary small font-monospace">VERIFYING DIGITAL GUARDIAN CLEARANCE...</span>
      </div>
    );
  }

  // If not authenticated, render Login & Onboarding view
  if (!user) {
    return <LoginView onAuthSuccess={handleAuthSuccess} />;
  }

  const currentMeta = viewMeta[currentView] || viewMeta.dashboard;

  return (
    <div className="guardian-universe-body">
      {/* Background Ambience */}
      <div className="cyber-bg-overlay" />
      <div className="guardian-cosmos-ambient" />

      {/* 4-Slide Onboarding Tour Modal */}
      <OnboardingModal isOpen={tourOpen} onClose={() => setTourOpen(false)} />

      {/* Scan Detail Inspector Modal */}
      {selectedScanId && (
        <ScanDetailModal scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
      )}

      <div className="app-wrapper">
        {/* Sidebar */}
        <Sidebar
          currentView={currentView}
          setCurrentView={setCurrentView}
          brandCount={brandCount}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />

        {/* Main Content Area */}
        <div className="main-content">
          <Navbar
            user={user}
            onLogout={handleLogout}
            onOpenTour={() => setTourOpen(true)}
            telemetry={telemetry}
            pageTitle={currentMeta.title}
            pageSubtitle={currentMeta.subtitle}
            onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
            setCurrentView={setCurrentView}
          />

          <main className="content-container p-3 p-md-4">
            {currentView === 'dashboard' && (
              <DashboardView
                onNavigate={setCurrentView}
                onSelectScan={setSelectedScanId}
              />
            )}
            {currentView === 'brands' && <BrandsView />}
            {currentView === 'social' && <SocialCheckerView />}
            {currentView === 'link' && <LinkCheckerView onSelectScan={setSelectedScanId} />}
            {currentView === 'app' && <AppCheckerView />}
            {currentView === 'history' && <HistoryView onSelectScan={setSelectedScanId} />}
          </main>
        </div>
      </div>
    </div>
  );
}
