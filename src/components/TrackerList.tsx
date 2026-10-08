import React from 'react';
import { TrackerData } from '../utils/types';

interface TrackerListProps {
  trackers: TrackerData[];
  onBlock?: () => void;
}

const TrackerList: React.FC<TrackerListProps> = ({ trackers, onBlock }) => {
  if (trackers.length === 0) {
    return (
      <div className="empty-state" style={{ textAlign: 'center', padding: '32px' }}>
        <p style={{ fontSize: '16px', fontWeight: '600', color: '#64748b' }}>No trackers detected</p>
        <p style={{ fontSize: '14px', color: '#94a3b8', marginTop: '8px' }}>This page appears to be clean!</p>
      </div>
    );
  }

  const thirdPartyCount = trackers.filter(t => !t.isFirstParty).length;
  const firstPartyCount = trackers.filter(t => t.isFirstParty).length;
  const blockedCount = trackers.filter(t => t.blocked).length;

  const handleBlockTracker = (domain: string) => {
    chrome.runtime.sendMessage({ action: 'blockTracker', domain }, () => {
      if (onBlock) onBlock();
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) chrome.tabs.reload(tabs[0].id);
      });
    });
  };

  const handleUnblockTracker = (domain: string) => {
    chrome.runtime.sendMessage({ action: 'unblockTracker', domain }, () => {
      if (onBlock) onBlock();
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) chrome.tabs.reload(tabs[0].id);
      });
    });
  };

  return (
    <div>
      {/* Summary Stats */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        marginBottom: '16px',
        padding: '12px 14px',
        background: 'linear-gradient(135deg, #f0fdf4, #e8f5e9)',
        borderRadius: '12px',
        border: '1px solid #c8e6c9'
      }}>
        <div style={{ textAlign: 'center', flex: 1 }}>
          <div style={{ fontSize: '18px', fontWeight: '800', color: thirdPartyCount > 0 ? '#ef4444' : '#10b981' }}>
            {thirdPartyCount}
          </div>
          <div style={{ fontSize: '10px', color: '#166534', fontWeight: '700', textTransform: 'uppercase' }}>
            3rd-Party Trackers
          </div>
        </div>
        <div style={{ textAlign: 'center', flex: 1, borderLeft: '1px solid #c8e6c9', borderRight: '1px solid #c8e6c9' }}>
          <div style={{ fontSize: '18px', fontWeight: '800', color: '#0369a1' }}>
            {firstPartyCount}
          </div>
          <div style={{ fontSize: '10px', color: '#0369a1', fontWeight: '700', textTransform: 'uppercase' }}>
            1st-Party Services
          </div>
        </div>
        <div style={{ textAlign: 'center', flex: 1 }}>
          <div style={{ fontSize: '18px', fontWeight: '800', color: '#10b981' }}>
            {blockedCount}
          </div>
          <div style={{ fontSize: '10px', color: '#166534', fontWeight: '700', textTransform: 'uppercase' }}>
            Blocked
          </div>
        </div>
      </div>

      <div className="tracker-list">
        {trackers.map((tracker, index) => {
          const isFirstParty = !!tracker.isFirstParty;
          return (
            <div
              key={index}
              className="tracker-item"
              style={{
                flexDirection: 'column',
                alignItems: 'stretch',
                padding: '12px 14px',
                borderLeft: isFirstParty ? '4px solid #10b981' : '4px solid #ef4444',
                background: isFirstParty ? 'linear-gradient(135deg, #ffffff, #f0fdf4)' : 'linear-gradient(135deg, #ffffff, #fff5f5)',
                marginBottom: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {isFirstParty ? (
                    <span style={{
                      fontSize: '9px',
                      fontWeight: '800',
                      background: '#dcfce7',
                      color: '#166534',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      border: '1px solid #bbf7d0',
                      letterSpacing: '0.4px',
                    }}>
                      🏢 1ST-PARTY {tracker.parentOrg ? `(${tracker.parentOrg})` : ''}
                    </span>
                  ) : (
                    <span style={{
                      fontSize: '9px',
                      fontWeight: '800',
                      background: '#fee2e2',
                      color: '#991b1b',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      border: '1px solid #fecaca',
                      letterSpacing: '0.4px',
                    }}>
                      ⚠️ 3RD-PARTY TRACKER
                    </span>
                  )}
                  <span style={{
                    fontSize: '9px',
                    color: '#64748b',
                    background: '#f1f5f9',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    textTransform: 'uppercase',
                    fontWeight: '600',
                  }}>
                    {tracker.category}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span className="tracker-count" style={{ fontSize: '10px' }}>
                    {tracker.count} req{tracker.count !== 1 ? 's' : ''}
                  </span>
                  {!tracker.blocked ? (
                    <button
                      style={{
                        padding: '2px 8px',
                        fontSize: '11px',
                        borderRadius: '4px',
                        border: '1px solid #dc2626',
                        background: '#ffffff',
                        color: '#dc2626',
                        cursor: 'pointer',
                        fontWeight: '600',
                      }}
                      onClick={() => handleBlockTracker(tracker.domain)}
                      title="Block this tracker"
                    >
                      Block
                    </button>
                  ) : (
                    <button
                      style={{
                        padding: '2px 8px',
                        fontSize: '11px',
                        borderRadius: '4px',
                        border: '1px solid #007E36',
                        background: '#ffffff',
                        color: '#007E36',
                        cursor: 'pointer',
                        fontWeight: '600',
                      }}
                      onClick={() => handleUnblockTracker(tracker.domain)}
                      title="Unblock this tracker"
                    >
                      Unblock
                    </button>
                  )}
                </div>
              </div>

              <div style={{ fontSize: '13px', fontWeight: '700', color: '#1e293b', marginBottom: '2px', wordBreak: 'break-all' }}>
                {tracker.name || tracker.domain}
              </div>
              {tracker.name && tracker.name !== tracker.domain && (
                <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'monospace', marginBottom: '4px', wordBreak: 'break-all' }}>
                  {tracker.domain}
                </div>
              )}

              {/* Privacy Explanation Context */}
              <div style={{
                fontSize: '11px',
                color: isFirstParty ? '#166534' : '#7f1d1d',
                background: isFirstParty ? 'rgba(240, 253, 244, 0.7)' : 'rgba(254, 242, 242, 0.7)',
                padding: '6px 8px',
                borderRadius: '6px',
                lineHeight: '1.4',
                border: isFirstParty ? '1px solid #dcfce7' : '1px solid #fee2e2',
              }}>
                {tracker.privacyContext || (isFirstParty
                  ? 'First-party infrastructure: Used for content delivery & recommendation algorithms. Data kept in-house.'
                  : 'Third-party tracking: Transmits session telemetry or ad identifiers to an external company.')}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default TrackerList;
