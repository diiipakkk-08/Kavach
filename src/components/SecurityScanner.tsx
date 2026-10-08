import React, { useState } from 'react';
import { SecurityScanResult, SecurityFinding } from '../utils/types';

interface SecurityScannerProps {
  onScanComplete: (result: SecurityScanResult) => void;
  result: SecurityScanResult | null;
  loading: boolean;
}

const severityColors: Record<string, { bg: string; text: string; border: string; icon: string }> = {
  HIGH:   { bg: '#fef2f2', text: '#dc2626', border: '#fecaca', icon: '🔴' },
  MEDIUM: { bg: '#fffbeb', text: '#d97706', border: '#fde68a', icon: '🟠' },
  LOW:    { bg: '#f0fdf4', text: '#16a34a', border: '#bbf7d0', icon: '🟡' },
  INFO:   { bg: '#f0f9ff', text: '#0369a1', border: '#bae6fd', icon: 'ℹ️' },
};

const categoryIcons: Record<string, string> = {
  headers: '🔒',
  storage: '💾',
  scripts: '📜',
  exposure: '🔓',
  mixed_content: '⚠️',
  forms: '📝',
};

const FindingCard: React.FC<{ finding: SecurityFinding }> = ({ finding }) => {
  const [expanded, setExpanded] = useState(false);
  const [highlighting, setHighlighting] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const sev = severityColors[finding.severity] || severityColors.INFO;

  const handleHighlight = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setHighlighting(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, {
          action: 'highlightSecurityFinding',
          findingId: finding.id,
        });
      }
    } catch {}
    setTimeout(() => setHighlighting(false), 1200);
  };

  const handleCopy = (e: React.MouseEvent, text: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        background: sev.bg,
        border: `1px solid ${sev.border}`,
        borderRadius: '8px',
        padding: '10px 12px',
        marginBottom: '8px',
        cursor: 'pointer',
        transition: 'all 0.15s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '13px', flexShrink: 0 }}>{sev.icon}</span>
        <span style={{ fontSize: '12px', fontWeight: '700', color: sev.text, flex: 1 }}>
          {finding.title}
        </span>
        <span style={{ fontSize: '10px', color: '#94a3b8' }}>
          {categoryIcons[finding.category] || '🔍'} {expanded ? '▲' : '▼'}
        </span>
      </div>

      {/* Concrete evidence / forwarding links */}
      {(finding.evidenceUrl || finding.destinationUrl) && (
        <div style={{
          marginTop: '6px',
          background: 'rgba(0,0,0,0.04)',
          borderRadius: '6px',
          padding: '6px 8px',
          fontSize: '10px',
          fontFamily: 'monospace',
          color: '#334155',
          wordBreak: 'break-all',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}>
          <span style={{ flex: 1 }}>
            {finding.destinationUrl ? `🔗 Destination: ${finding.destinationUrl}` : `📜 Source: ${finding.evidenceUrl}`}
          </span>
          <button
            onClick={(e) => handleCopy(e, finding.destinationUrl || finding.evidenceUrl || '')}
            title="Copy URL"
            style={{
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: '4px',
              padding: '2px 6px',
              fontSize: '10px',
              cursor: 'pointer',
              color: '#475569',
              flexShrink: 0,
            }}
          >
            {copySuccess ? '✓ Copied' : '📋 Copy'}
          </button>
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: '6px', marginTop: '6px', alignItems: 'center' }}>
        {finding.canHighlight !== false && (
          <button
            onClick={handleHighlight}
            style={{
              background: '#ffffff',
              border: `1px solid ${sev.border}`,
              borderRadius: '6px',
              padding: '4px 10px',
              fontSize: '10px',
              fontWeight: '700',
              cursor: 'pointer',
              color: sev.text,
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.15s ease',
            }}
          >
            <span>👁️</span> {highlighting ? 'Highlighting on Page...' : 'Highlight on Page'}
          </button>
        )}
      </div>

      {expanded && (
        <div style={{
          marginTop: '8px',
          fontSize: '11px',
          color: '#475569',
          lineHeight: '1.5',
          paddingTop: '6px',
          borderTop: `1px solid ${sev.border}`,
        }}>
          {finding.description}
        </div>
      )}
    </div>
  );
};

const SecurityScanner: React.FC<SecurityScannerProps> = ({ onScanComplete, result, loading: externalLoading }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loading = externalLoading || isScanning;

  const handleScan = async () => {
    setIsScanning(true);
    setErrorMessage(null);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        setErrorMessage('No active tab found.');
        return;
      }

      const url = tab.url || '';
      if (
        url.startsWith('chrome://') ||
        url.startsWith('edge://') ||
        url.startsWith('about:') ||
        url.startsWith('chrome-extension://') ||
        url.startsWith('devtools://') ||
        url.includes('chrome.google.com/webstore') ||
        url.includes('chromewebstore.google.com')
      ) {
        setErrorMessage('Security scanner cannot run on internal browser/extension pages. Please open an external website (e.g., https://youtube.com or https://httpbin.org).');
        return;
      }

      if (url.startsWith('file://')) {
        // Local files require "Allow access to file URLs" in chrome://extensions
        // Check if we can inject or message
      }

      let scanResult = null;
      try {
        scanResult = await chrome.tabs.sendMessage(tab.id, { action: 'getSecurityScan' });
      } catch (_firstErr) {
        // Content script might not be injected yet (e.g. tab opened before extension loaded/updated).
        // Attempt programmatic injection using chrome.scripting:
        try {
          if (chrome.scripting && chrome.scripting.executeScript) {
            await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              files: ['content.js']
            });
            // Small pause for content script initialization
            await new Promise((resolve) => setTimeout(resolve, 200));
            scanResult = await chrome.tabs.sendMessage(tab.id, { action: 'getSecurityScan' });
          }
        } catch (_injectErr) {
          if (url.startsWith('file://')) {
            setErrorMessage('For local HTML files, please enable "Allow access to file URLs" in chrome://extensions > Kavach Details, then refresh the page.');
          } else {
            setErrorMessage('Could not connect to this page. Please refresh the page (press F5 or ⟳) and try scanning again.');
          }
          return;
        }
      }

      if (scanResult) {
        onScanComplete(scanResult);
      } else {
        setErrorMessage('Could not retrieve scan results from this page. Please refresh the page (F5) and try again.');
      }
    } catch (_err) {
      setErrorMessage('Could not communicate with page. Please refresh the page (F5) and try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return '#16a34a';
    if (score >= 50) return '#d97706';
    return '#dc2626';
  };

  const getScoreLabel = (score: number) => {
    if (score >= 80) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
  };

  if (!result && !loading) {
    return (
      <div style={{ textAlign: 'center', padding: '16px 0' }}>
        <div style={{ fontSize: '32px', marginBottom: '8px' }}>🔐</div>
        <div style={{ fontSize: '13px', fontWeight: '700', color: '#1e293b', marginBottom: '4px' }}>
          Client-Side Security Exposure
        </div>
        <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '14px', lineHeight: '1.5' }}>
          Scans the active page for exposed API keys, sensitive tokens in localStorage, insecure password forms, and mixed content.
        </div>
        <button
          onClick={handleScan}
          style={{
            background: 'linear-gradient(135deg, #007E36, #005a26)',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            padding: '10px 20px',
            fontSize: '13px',
            fontWeight: '700',
            cursor: 'pointer',
            width: '100%',
          }}
        >
          🛡️ Run Security Scan Now
        </button>
        {errorMessage && (
          <div style={{ marginTop: '12px', padding: '8px 12px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '6px', color: '#dc2626', fontSize: '11px', textAlign: 'left' }}>
            ⚠️ {errorMessage}
          </div>
        )}
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '24px 0', color: '#64748b', fontSize: '13px' }}>
        <div className="spinner" style={{ margin: '0 auto 12px' }} />
        Auditing client-side security posture...
      </div>
    );
  }

  if (!result) return null;

  return (
    <div>
      {/* Score row */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        background: '#f8fafc',
        borderRadius: '10px',
        padding: '12px 14px',
        marginBottom: '14px',
        border: '1px solid #e2e8f0',
      }}>
        <div style={{
          width: '52px',
          height: '52px',
          borderRadius: '50%',
          background: getScoreColor(result.score),
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'white',
          fontSize: '18px',
          fontWeight: '900',
          flexShrink: 0,
          boxShadow: `0 4px 12px ${getScoreColor(result.score)}44`,
        }}>
          {result.score}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: '700', fontSize: '13px', color: '#1e293b', marginBottom: '4px' }}>
            Security: {getScoreLabel(result.score)}
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {result.highCount > 0 && (
              <span style={{ fontSize: '10px', background: '#fef2f2', color: '#dc2626', padding: '2px 6px', borderRadius: '4px', fontWeight: '700', border: '1px solid #fecaca' }}>
                🔴 {result.highCount} High
              </span>
            )}
            {result.mediumCount > 0 && (
              <span style={{ fontSize: '10px', background: '#fffbeb', color: '#d97706', padding: '2px 6px', borderRadius: '4px', fontWeight: '700', border: '1px solid #fde68a' }}>
                🟠 {result.mediumCount} Med
              </span>
            )}
            {result.lowCount > 0 && (
              <span style={{ fontSize: '10px', background: '#f0fdf4', color: '#16a34a', padding: '2px 6px', borderRadius: '4px', fontWeight: '700', border: '1px solid #bbf7d0' }}>
                🟡 {result.lowCount} Low
              </span>
            )}
            {result.findings.length === 0 && (
              <span style={{ fontSize: '10px', background: '#f0fdf4', color: '#16a34a', padding: '2px 6px', borderRadius: '4px', fontWeight: '700', border: '1px solid #bbf7d0' }}>
                ✅ Clean
              </span>
            )}
          </div>
        </div>
        <button
          onClick={handleScan}
          title="Re-scan"
          style={{
            background: '#f1f5f9',
            border: '1px solid #e2e8f0',
            borderRadius: '6px',
            padding: '6px 10px',
            fontSize: '11px',
            cursor: 'pointer',
            color: '#475569',
            fontWeight: '600',
          }}
        >
          🔄 Re-scan
        </button>
      </div>

      {errorMessage && (
        <div style={{ marginBottom: '10px', padding: '8px 12px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '6px', color: '#dc2626', fontSize: '11px' }}>
          ⚠️ {errorMessage}
        </div>
      )}

      {/* Findings list */}
      {result.findings.length > 0 ? (
        <div>
          {result.findings.map(finding => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      ) : (
        <div style={{
          textAlign: 'center',
          padding: '16px',
          background: '#f0fdf4',
          borderRadius: '8px',
          border: '1px solid #bbf7d0',
          fontSize: '12px',
          color: '#16a34a',
          fontWeight: '600',
        }}>
          ✅ No security exposure issues detected on this page.
        </div>
      )}

      <div style={{ fontSize: '10px', color: '#94a3b8', textAlign: 'right', marginTop: '6px' }}>
        Scanned at {new Date(result.scannedAt).toLocaleTimeString()}
      </div>
    </div>
  );
};

export default SecurityScanner;
