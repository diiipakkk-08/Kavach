import React, { useState, useEffect } from 'react';
import { SiteData, SecurityScanResult } from '../utils/types';
import TrustScore from '../components/TrustScore';
import TrackerList from '../components/TrackerList';
import PrivacyAnalysis from '../components/PrivacyAnalysis';
import DataFlowVisualization from '../components/DataFlowVisualization';
import ActionButtons from '../components/ActionButtons';
import FingerprintInfo from '../components/FingerprintInfo';
import SecurityScanner from '../components/SecurityScanner';
import BugReportIcon from '@mui/icons-material/BugReport';
import ClearAllIcon from '@mui/icons-material/ClearAll';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

// ─── Tab types ───────────────────────────────────────────────────────────────
type Tab = 'privacy' | 'security' | 'upload';

// ─── Tab Bar ─────────────────────────────────────────────────────────────────
const TabBar: React.FC<{ active: Tab; onChange: (t: Tab) => void }> = ({ active, onChange }) => {
  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: 'privacy',  label: 'Privacy',  icon: '🔍' },
    { id: 'security', label: 'Security', icon: '🔐' },
    { id: 'upload',   label: 'Upload Guard', icon: '📤' },
  ];
  return (
    <div style={{
      display: 'flex',
      gap: '4px',
      padding: '8px 12px 0',
      background: 'transparent',
      flexShrink: 0,
    }}>
      {tabs.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          style={{
            flex: 1,
            padding: '8px 4px',
            border: 'none',
            borderRadius: '8px 8px 0 0',
            fontSize: '11px',
            fontWeight: '700',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            background: active === t.id
              ? 'linear-gradient(135deg, #ffffff, #f8fafc)'
              : 'rgba(255,255,255,0.4)',
            color: active === t.id ? '#007E36' : '#64748b',
            borderBottom: active === t.id ? '2px solid #007E36' : '2px solid transparent',
            boxShadow: active === t.id ? '0 -2px 8px rgba(0,0,0,0.06)' : 'none',
            fontFamily: "'Titillium Web', sans-serif",
          }}
        >
          {t.icon} {t.label}
        </button>
      ))}
    </div>
  );
};

// ─── Upload Guard Info Panel ─────────────────────────────────────────────────
const UploadGuardPanel: React.FC<{ currentUrl: string }> = ({ currentUrl }) => {
  const [isTrusted, setIsTrusted] = useState(false);
  const domain = (() => {
    try { return new URL(currentUrl).hostname; } catch { return ''; }
  })();

  useEffect(() => {
    if (!domain) return;
    chrome.storage.local.get(['trustedUploadDomains'], (res) => {
      const list: string[] = res.trustedUploadDomains || [];
      setIsTrusted(list.includes(domain));
    });
  }, [domain]);

  const toggleTrust = async () => {
    if (!domain) return;
    chrome.storage.local.get(['trustedUploadDomains'], async (res) => {
      let list: string[] = res.trustedUploadDomains || [];
      if (isTrusted) {
        list = list.filter(d => d !== domain);
        setIsTrusted(false);
      } else {
        if (!list.includes(domain)) list.push(domain);
        setIsTrusted(true);
      }
      await chrome.storage.local.set({ trustedUploadDomains: list });
    });
  };

  return (
    <div style={{ padding: '8px 0' }}>
      {/* Trust this Website Card */}
      {domain && (
        <div style={{
          background: isTrusted ? '#f0fdf4' : '#ffffff',
          border: `1.5px solid ${isTrusted ? '#86efac' : '#cbd5e1'}`,
          borderRadius: '10px',
          padding: '12px 14px',
          marginBottom: '12px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <div style={{ fontWeight: '700', fontSize: '12px', color: isTrusted ? '#166534' : '#1e293b', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span>{isTrusted ? '✅' : '🛡️'}</span>
              <span>{domain}</span>
            </div>
            <span style={{
              fontSize: '10px',
              fontWeight: '700',
              padding: '2px 8px',
              borderRadius: '4px',
              background: isTrusted ? '#dcfce7' : '#f1f5f9',
              color: isTrusted ? '#166534' : '#475569',
              border: `1px solid ${isTrusted ? '#bbf7d0' : '#e2e8f0'}`,
            }}>
              {isTrusted ? 'TRUSTED (BYPASSED)' : 'GUARD ACTIVE'}
            </span>
          </div>
          <p style={{ fontSize: '11px', color: '#64748b', margin: '0 0 10px 0', lineHeight: '1.4' }}>
            {isTrusted
              ? 'Upload Guard is bypassed for this site. Files upload immediately without privacy popups.'
              : 'Kavach scans files selected on this site for GPS coordinates, faces, passwords, and sensitive metadata.'}
          </p>
          <button
            onClick={toggleTrust}
            style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: '700',
              cursor: 'pointer',
              border: isTrusted ? '1px solid #bbf7d0' : 'none',
              background: isTrusted ? '#ffffff' : 'linear-gradient(135deg, #007E36, #005a26)',
              color: isTrusted ? '#166534' : '#ffffff',
              transition: 'all 0.15s ease',
            }}
          >
            {isTrusted ? '🔒 Revoke Trust (Re-enable Kavach)' : '🛡️ Trust this Website (Disable Upload Popups)'}
          </button>
        </div>
      )}

      <div style={{
        background: 'linear-gradient(135deg, #007E36 0%, #005a26 100%)',
        borderRadius: '10px',
        padding: '14px 16px',
        color: 'white',
        marginBottom: '12px',
      }}>
        <div style={{ fontSize: '20px', marginBottom: '6px' }}>📤</div>
        <div style={{ fontSize: '13px', fontWeight: '700', marginBottom: '2px' }}>Upload Guard Engine</div>
        <div style={{ fontSize: '11px', opacity: 0.9, lineHeight: '1.4' }}>
          Intercepts file choices before upload to inspect metadata, faces, and secrets locally on your device.
        </div>
      </div>

      <div style={{ fontSize: '11px', fontWeight: '700', color: '#64748b', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
        Active Security Checks
      </div>

      {[
        { icon: '📍', title: 'GPS Location', desc: 'Embedded latitude/longitude in photos' },
        { icon: '👤', title: 'Face & Biometrics', desc: 'Identifiable human portraits & selfies' },
        { icon: '🔑', title: 'Passwords & Keys', desc: 'Plaintext credentials, Wi-Fi keys & emails' },
        { icon: '📁', title: 'Filename Leaks', desc: 'Sanitizes timestamps & camera device models' },
      ].map(item => (
        <div key={item.title} style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          padding: '8px 10px',
          background: 'linear-gradient(135deg, #ffffff, #f8fafc)',
          borderRadius: '8px',
          border: '1px solid #e2e8f0',
          marginBottom: '5px',
        }}>
          <span style={{ fontSize: '16px', flexShrink: 0 }}>{item.icon}</span>
          <div>
            <div style={{ fontSize: '11px', fontWeight: '700', color: '#1e293b', marginBottom: '1px' }}>{item.title}</div>
            <div style={{ fontSize: '10px', color: '#64748b', lineHeight: '1.3' }}>{item.desc}</div>
          </div>
          <span style={{ marginLeft: 'auto', fontSize: '10px', color: '#16a34a', fontWeight: '700', background: '#f0fdf4', padding: '2px 5px', borderRadius: '4px', border: '1px solid #bbf7d0', flexShrink: 0 }}>ON</span>
        </div>
      ))}
    </div>
  );
};

// ─── Opt-out cleanup (runs in page context) ──────────────────────────────────
function comprehensiveOptOutCleanup(domain: string) {
  try {
    localStorage.clear();
    sessionStorage.clear();
    const universalOptOutCookies = ['gdpr_consent=false','ccpa_optout=true','cookie_consent=rejected','tracking_consent=false','analytics_consent=false','marketing_consent=false','opt_out=true'];
    const domainVariants = [domain, `.${domain}`, `www.${domain}`];
    domainVariants.forEach(dv => {
      universalOptOutCookies.forEach(c => { document.cookie = `${c}; path=/; max-age=31536000; SameSite=Strict; domain=${dv}`; });
    });
    const optOutSelectors = ['button[data-testid*="reject"]','button[data-testid*="decline"]','#onetrust-reject-all-handler','#CybotCookiebotDialogBodyButtonDecline','.sp_choice_type_REJECT_ALL'];
    optOutSelectors.forEach(sel => {
      document.querySelectorAll(sel).forEach(el => { try { (el as HTMLElement).click(); } catch {} });
    });
    const notification = document.createElement('div');
    notification.innerHTML = `<div style="position:fixed;top:20px;left:20px;z-index:999999;background:linear-gradient(135deg,#007E36,#005a26);color:white;padding:16px 20px;border-radius:12px;font-family:system-ui,sans-serif;font-size:14px;font-weight:600;box-shadow:0 20px 40px rgba(0,126,54,0.4);min-width:280px;">🛡️ Kavach Privacy Reset<br><span style="font-size:12px;opacity:0.9">✓ Cookies cleared · ✓ Storage wiped · ✓ Tracking disabled</span></div>`;
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 6000);
    setTimeout(() => window.location.reload(), 3000);
  } catch {}
}

// ─── Main App ────────────────────────────────────────────────────────────────
const App: React.FC = () => {
  const [siteData, setSiteData] = useState<SiteData | null>(null);
  const [loading, setLoading] = useState(true);
  const [currentUrl, setCurrentUrl] = useState('');
  const [analyzingPolicy, setAnalyzingPolicy] = useState(false);
  const [debugInfo, setDebugInfo] = useState<any>(null);
  const [clearCacheMessage, setClearCacheMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('privacy');
  const [securityResult, setSecurityResult] = useState<SecurityScanResult | null>(null);
  const [securityLoading, setSecurityLoading] = useState(false);
  const [showAiSettings, setShowAiSettings] = useState(false);
  const [geminiKeyInput, setGeminiKeyInput] = useState('');
  const [geminiKeyStatus, setGeminiKeyStatus] = useState<string | null>(null);
  const [testingKey, setTestingKey] = useState(false);

  useEffect(() => {
    loadCurrentSiteData();
    chrome.storage.local.get(['geminiApiKey'], (res) => {
      if (res.geminiApiKey) {
        setGeminiKeyInput(res.geminiApiKey);
        setGeminiKeyStatus('🟢 Gemini Flash Active');
      }
    });
  }, []);

  const handleSaveAndTestKey = async () => {
    if (!geminiKeyInput.trim()) {
      await chrome.storage.local.remove(['geminiApiKey']);
      setGeminiKeyStatus('🔵 Using Built-in Offline Engine');
      return;
    }
    setTestingKey(true);
    setGeminiKeyStatus('⏳ Verifying Gemini API Key...');
    try {
      const res = await chrome.runtime.sendMessage({ action: 'testGeminiApiKey', apiKey: geminiKeyInput.trim() });
      if (res?.valid) {
        await chrome.storage.local.set({ geminiApiKey: geminiKeyInput.trim() });
        setGeminiKeyStatus('🟢 Verified & Saved! Gemini 1.5 Flash Connected.');
      } else {
        setGeminiKeyStatus(`🔴 ${res?.message || 'Key invalid'}`);
      }
    } catch {
      setGeminiKeyStatus('⚠️ Failed to connect to verification service.');
    } finally {
      setTestingKey(false);
    }
  };

  const loadCurrentSiteData = async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab.url) return;
      setCurrentUrl(tab.url);
      const response = await chrome.runtime.sendMessage({ action: 'getSiteData', url: tab.url });
      setSiteData(response);
      chrome.runtime.sendMessage({ action: 'clearThreatBadge' }).catch(() => {});
    } catch (err) {
      console.error('Failed to load site data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleOptOut = async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab.url || !tab.id) return;
      const url = new URL(tab.url);
      const domain = url.hostname;
      await chrome.runtime.sendMessage({ action: 'performOptOut', url: tab.url, tabId: tab.id });
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: comprehensiveOptOutCleanup, args: [domain] });
      try {
        await chrome.browsingData.remove({ origins: [url.origin] }, { localStorage: true, indexedDB: true, cacheStorage: true, formData: true });
      } catch {}
    } catch (err) {
      console.error('Opt-out failed:', err);
    }
  };

  const handleAnalyzePolicy = async () => {
    if (!siteData || analyzingPolicy) return;
    setAnalyzingPolicy(true);
    try {
      const response = await chrome.runtime.sendMessage({ action: 'analyzePrivacyPolicy', url: currentUrl });
      if (response && !response.error) {
        setSiteData({ ...siteData, privacyAnalysis: response });
      } else {
        setSiteData({ ...siteData, privacyAnalysis: response || { error: 'Analysis failed', summary: 'Unable to analyze', safety: 'RISKY', score: 30 } });
      }
    } catch {
      setSiteData({ ...siteData, privacyAnalysis: { score: 0, risks: ['Analysis failed'], summary: 'Unable to analyze privacy policy.', dataSharing: [] } });
    } finally {
      setAnalyzingPolicy(false);
    }
  };

  const handleSecurityScan = async (result: SecurityScanResult) => {
    setSecurityResult(result);
  };

  const handleTabChange = (tab: Tab) => {
    setActiveTab(tab);
  };

  const handleDebugInfo = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'debugInfo' });
      setDebugInfo(response);
    } catch {}
  };

  const handleClearCache = async () => {
    try {
      await chrome.runtime.sendMessage({ action: 'clearKavachCache' });
      setClearCacheMessage('Cache cleared!');
      setTimeout(() => setClearCacheMessage(null), 3000);
    } catch {
      setClearCacheMessage('Failed to clear cache.');
      setTimeout(() => setClearCacheMessage(null), 3000);
    }
  };

  if (loading) {
    return (
      <div className="app">
        <div className="loading">
          <div className="loading-logo">
            <img src="logo.png" alt="Kavach Logo" className="logo-image" />
          </div>
          <div className="spinner"></div>
          Loading site data...
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <img src="logo.png" alt="Kavach Logo" className="logo-image" />
        </div>
        <div className="header-text">
          <h1>Kavach</h1>
          <p>Privacy &amp; Security Guardian</p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <button
            onClick={() => setShowAiSettings(!showAiSettings)}
            title="Configure AI Engine (Google Gemini Flash & Local Models)"
            style={{
              background: showAiSettings ? '#ffffff' : 'rgba(255,255,255,0.2)',
              color: showAiSettings ? '#007E36' : 'white',
              border: 'none',
              borderRadius: '8px',
              padding: '6px 8px',
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: '700',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.15s ease',
            }}
          >
            <span>🤖</span> <span style={{ fontSize: '10px' }}>AI</span>
          </button>
          {siteData && (
            <div style={{
              textAlign: 'center',
              background: 'rgba(255,255,255,0.15)',
              borderRadius: '8px',
              padding: '4px 8px',
              zIndex: 1,
            }}>
              <div style={{ fontSize: '16px', fontWeight: '900', color: siteData.trustScore >= 80 ? '#86efac' : siteData.trustScore >= 50 ? '#fde68a' : '#fca5a5' }}>
                {siteData.trustScore}
              </div>
              <div style={{ fontSize: '8px', opacity: 0.8, fontWeight: '700', letterSpacing: '0.5px' }}>SCORE</div>
            </div>
          )}
        </div>
      </header>

      {/* ─── AI Engine Settings Drawer ─── */}
      {showAiSettings && (
        <div style={{
          background: '#ffffff',
          borderBottom: '2px solid #007E36',
          padding: '12px 14px',
          fontSize: '11px',
          boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
          zIndex: 10,
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <div style={{ fontWeight: '800', color: '#0f172a', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span>🤖</span> Google Gemini AI Integration
            </div>
            <button
              onClick={() => setShowAiSettings(false)}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontSize: '13px', color: '#64748b' }}
            >
              ✕
            </button>
          </div>
          <div style={{ color: '#475569', fontSize: '10.5px', marginBottom: '8px', lineHeight: '1.4' }}>
            Enables deep screenshot vision OCR (extracts passwords/emails) and live tracker classification.
          </div>
          <div style={{ display: 'flex', gap: '6px', marginBottom: '6px' }}>
            <input
              type="password"
              placeholder="Paste Gemini API Key (AIzaSy...)"
              value={geminiKeyInput}
              onChange={(e) => setGeminiKeyInput(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #cbd5e1', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' }}
            />
            <button
              onClick={handleSaveAndTestKey}
              disabled={testingKey}
              style={{
                background: '#007E36',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                padding: '6px 10px',
                fontSize: '11px',
                fontWeight: '700',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              {testingKey ? 'Testing...' : 'Save & Test'}
            </button>
          </div>
          {geminiKeyStatus && (
            <div style={{ fontSize: '10px', fontWeight: '700', marginBottom: '6px', color: geminiKeyStatus.startsWith('🟢') ? '#166534' : geminiKeyStatus.startsWith('🔴') ? '#dc2626' : '#0369a1' }}>
              {geminiKeyStatus}
            </div>
          )}
          <div style={{ fontSize: '10px', color: '#94a3b8' }}>
            Get a 100% free API key from{' '}
            <a
              href="https://aistudio.google.com/app/apikey"
              target="_blank"
              rel="noreferrer"
              style={{ color: '#0284c7', textDecoration: 'underline', fontWeight: '700' }}
            >
              Google AI Studio ↗
            </a>
          </div>
        </div>
      )}

      <TabBar active={activeTab} onChange={handleTabChange} />

      <div className="content">
        {siteData ? (
          <>
            {/* ─── PRIVACY TAB ─── */}
            {activeTab === 'privacy' && (
              <>
                <TrustScore score={siteData.trustScore} url={currentUrl} />

                <div className="section">
                  <div className="section-header">
                    <div className="section-title">Tracker Blocking</div>
                  </div>
                  <TrackerList trackers={siteData.trackers} onBlock={loadCurrentSiteData} />
                </div>

                {siteData.privacyAnalysis && (
                  <PrivacyAnalysis analysis={siteData.privacyAnalysis} />
                )}

                <div className="section">
                  <div className="section-title" style={{ marginBottom: '14px' }}>Data Flow &amp; Surveillance</div>
                  <DataFlowVisualization dataFlow={siteData.dataFlow} />
                </div>

                <FingerprintInfo />

                <ActionButtons
                  onOptOut={handleOptOut}
                  onAnalyzePolicy={handleAnalyzePolicy}
                  hasPrivacyAnalysis={!!siteData.privacyAnalysis}
                  analyzingPolicy={analyzingPolicy}
                />

                <div className="debug-section">
                  <div className="debug-buttons">
                    <button onClick={handleDebugInfo} className="debug-button">
                      <BugReportIcon className="debug-icon" />
                      <span>Debug Info</span>
                    </button>
                    <button onClick={handleClearCache} className="debug-button">
                      <ClearAllIcon className="debug-icon" />
                      <span>Clear Cache</span>
                    </button>
                  </div>
                  {debugInfo && (
                    <div className="debug-info">
                      <p><strong>Tracked Domains:</strong> {debugInfo.totalSites}</p>
                      <p><strong>Current Domain:</strong> {(() => { try { return new URL(currentUrl).hostname; } catch { return currentUrl; } })()}</p>
                    </div>
                  )}
                  {clearCacheMessage && (
                    <div className="debug-info success-message">
                      <CheckCircleIcon className="success-icon" />
                      {clearCacheMessage}
                    </div>
                  )}
                </div>
              </>
            )}

            {/* ─── SECURITY TAB ─── */}
            {activeTab === 'security' && (
              <>
                {siteData.lastPasswordDestination && (
                  <div className="section" style={{ borderLeft: '4px solid #007E36', marginBottom: '8px' }}>
                    <div className="section-header" style={{ marginBottom: '8px' }}>
                      <div className="section-title" style={{ fontSize: '13px' }}>🔑 Password Destination Audit</div>
                    </div>
                    <div style={{
                      background: siteData.lastPasswordDestination.severity === 'SAFE' ? '#f0fdf4' : siteData.lastPasswordDestination.severity === 'CRITICAL' ? '#fef2f2' : '#fffbeb',
                      border: `1px solid ${siteData.lastPasswordDestination.severity === 'SAFE' ? '#bbf7d0' : siteData.lastPasswordDestination.severity === 'CRITICAL' ? '#fecaca' : '#fde68a'}`,
                      borderRadius: '8px',
                      padding: '10px 12px',
                      fontSize: '11px',
                      lineHeight: '1.4'
                    }}>
                      <div style={{ fontWeight: '700', marginBottom: '4px', color: siteData.lastPasswordDestination.severity === 'SAFE' ? '#166534' : siteData.lastPasswordDestination.severity === 'CRITICAL' ? '#991b1b' : '#92400e' }}>
                        {siteData.lastPasswordDestination.providerName || (siteData.lastPasswordDestination.destinationType === 'SAME_ORIGIN' ? 'Direct Site Database Custody' : 'Unknown Destination')}
                      </div>
                      <div style={{ color: '#475569', marginBottom: '4px' }}>
                        {siteData.lastPasswordDestination.description}
                      </div>
                      <div style={{ fontSize: '10px', color: '#94a3b8', wordBreak: 'break-all' }}>
                        Endpoint: {siteData.lastPasswordDestination.destinationUrl.substring(0, 60)}…
                      </div>
                    </div>
                  </div>
                )}

                <div className="section">
                  <div className="section-header">
                    <div className="section-title">🔐 Client Security Audit</div>
                  </div>
                  <SecurityScanner
                    onScanComplete={handleSecurityScan}
                    result={securityResult || (siteData?.securityScan as any) || null}
                    loading={securityLoading}
                  />
                </div>
              </>
            )}

            {/* ─── UPLOAD GUARD TAB ─── */}
            {activeTab === 'upload' && (
              <div className="section">
                <div className="section-header">
                  <div className="section-title">📤 Upload Guard</div>
                </div>
                <UploadGuardPanel currentUrl={currentUrl} />
              </div>
            )}
          </>
        ) : (
          <div className="empty-state">
            <div className="empty-state-logo">
              <img src="logo.png" alt="Kavach Logo" className="logo-image" />
            </div>
            <p>No tracking data available for this site yet.</p>
            <p>Navigate to a website to see privacy insights.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
