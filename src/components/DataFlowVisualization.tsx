import React, { useState } from 'react';
import { DataFlowNode, DataFlowEdge } from '../utils/types';

interface DataFlowVisualizationProps {
  dataFlow: {
    nodes: DataFlowNode[];
    edges: DataFlowEdge[];
  };
}

const capabilityIcons: Record<string, { icon: string; label: string; color: string }> = {
  SESSION_REPLAY:  { icon: '🖱️', label: 'Mouse & Keystroke Replay', color: '#dc2626' },
  CROSS_SITE_AD:   { icon: '🎯', label: 'Cross-Site Ad Profiling', color: '#ea580c' },
  FINGERPRINTING:  { icon: '🖥️', label: 'Hardware Fingerprinting', color: '#9333ea' },
  FIRST_PARTY_CDN: { icon: '📺', label: '1st-Party Video / Assets', color: '#16a34a' },
  ANALYTICS:       { icon: '📊', label: 'Pageview Telemetry', color: '#0284c7' },
};

const DataFlowVisualization: React.FC<DataFlowVisualizationProps> = ({ dataFlow }) => {
  const [selectedNode, setSelectedNode] = useState<DataFlowNode | null>(null);

  if (dataFlow.nodes.length === 0) {
    return (
      <div className="data-flow">
        <div className="empty-state" style={{ 
          color: '#94a3b8', 
          textAlign: 'center', 
          padding: '32px 20px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center'
        }}>
          <p style={{ fontSize: '15px', fontWeight: '600' }}>No external data flow detected yet.</p>
          <p style={{ fontSize: '12px', marginTop: '6px', opacity: 0.8 }}>Navigate around the site to observe data egress</p>
        </div>
      </div>
    );
  }

  const sourceNode = dataFlow.nodes.find(n => n.type === 'source');
  const trackerNodes = dataFlow.nodes.filter(n => n.type === 'tracker');

  const formatDomain = (domain: string) => {
    return domain.length > 15 ? domain.substring(0, 15) + '…' : domain;
  };

  const displayedTrackers = trackerNodes.slice(0, 4);
  const remainingCount = Math.max(0, trackerNodes.length - 4);

  return (
    <div className="data-flow" style={{ padding: '16px' }}>
      <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px', textAlign: 'center' }}>
        💡 Click on any tracker below to inspect what exact data it harvests
      </div>

      <div className="flow-container">
        {/* Source Node */}
        {sourceNode && (
          <div className="flow-section source-section">
            <div 
              className="flow-node source"
              style={{ cursor: 'pointer' }}
              onClick={() => setSelectedNode(sourceNode)}
            >
              <div className="node-label">SOURCE</div>
              <div className="node-domain">{formatDomain(sourceNode.domain)}</div>
            </div>
          </div>
        )}

        {/* Animated Arrow */}
        {dataFlow.edges.length > 0 && sourceNode && displayedTrackers.length > 0 && (
          <div className="flow-section arrow-section">
            <div className="flow-arrow">
              <div className="arrow-line"></div>
              <div className="arrow-head">&gt;</div>
            </div>
          </div>
        )}

        {/* Tracker Nodes with Real Capabilities */}
        {displayedTrackers.length > 0 && (
          <div className="flow-section trackers-section">
            <div className="tracker-nodes">
              {displayedTrackers.map((node) => {
                const cap = capabilityIcons[node.capability || 'ANALYTICS'] || capabilityIcons.ANALYTICS;
                const isSelected = selectedNode?.id === node.id;
                return (
                  <div
                    key={node.id}
                    className="flow-node tracker"
                    onClick={() => setSelectedNode(node)}
                    style={{
                      cursor: 'pointer',
                      border: isSelected ? '2px solid #DFFF19' : undefined,
                      transform: isSelected ? 'scale(1.04)' : undefined,
                      transition: 'all 0.15s ease',
                      padding: '8px 10px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px', marginBottom: '3px' }}>
                      <span style={{ fontSize: '12px' }}>{cap.icon}</span>
                      <span className="node-label" style={{ fontSize: '9px', padding: '1px 4px' }}>
                        {cap.label.split(' ')[0]}
                      </span>
                    </div>
                    <div className="node-domain" style={{ fontSize: '11px' }}>
                      {formatDomain(node.domain)}
                    </div>
                  </div>
                );
              })}

              {remainingCount > 0 && (
                <div style={{
                  fontSize: '11px',
                  color: 'white',
                  textAlign: 'center',
                  fontStyle: 'italic',
                  padding: '4px 8px',
                  background: 'rgba(255, 255, 255, 0.15)',
                  borderRadius: '6px',
                  fontWeight: '700'
                }}>
                  +{remainingCount} more
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Selected Node Inspector Detail */}
      {selectedNode && (
        <div style={{
          marginTop: '12px',
          background: 'rgba(15, 23, 42, 0.75)',
          border: '1px solid rgba(226, 232, 240, 0.25)',
          borderRadius: '8px',
          padding: '10px 12px',
          fontSize: '11px',
          color: '#e2e8f0',
          lineHeight: '1.4',
          animation: 'kavach-fadein 0.2s ease',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
            <span style={{ fontWeight: '800', color: '#38bdf8' }}>
              🔍 {selectedNode.domain}
            </span>
            <button 
              onClick={() => setSelectedNode(null)}
              style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '12px' }}
            >
              ✕
            </button>
          </div>
          <div>
            <strong>Specific Data Harvested:</strong>{' '}
            <span style={{ color: '#fde047' }}>
              {selectedNode.dataTypeTracked || (selectedNode.type === 'source' ? 'Origin host' : 'User session & click telemetry')}
            </span>
          </div>
          <div style={{ marginTop: '3px', color: '#94a3b8', fontSize: '10px' }}>
            {selectedNode.type === 'source' 
              ? 'This is the active website you are visiting.' 
              : selectedNode.capability === 'FIRST_PARTY_CDN'
              ? 'First-party service: Video chunks & recommendation algorithms kept in-house.'
              : selectedNode.capability === 'SESSION_REPLAY'
              ? 'High Privacy Risk: Tracks mouse movements, rage clicks, and user typing.'
              : 'Third-party connection: Transmits telemetry to external servers.'}
          </div>
        </div>
      )}

      {/* Quick summary alert */}
      {dataFlow.edges.length > 0 && !selectedNode && (
        <div style={{
          marginTop: '12px',
          fontSize: '11px',
          color: '#f8fafc',
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '6px',
          padding: '6px 10px',
          textAlign: 'center',
        }}>
          ⚠️ Active Connections: <strong>{dataFlow.edges.length} data streams</strong> transmitting telemetry.
        </div>
      )}
    </div>
  );
};

export default DataFlowVisualization;
