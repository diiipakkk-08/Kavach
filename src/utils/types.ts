import { GpsCoordinates } from './exif';
import { LocalScanResult } from './local-vision';

export type TrackerCapability = 
  | 'SESSION_REPLAY'       // Mouse movements, keystrokes, screen recordings
  | 'CROSS_SITE_AD'        // Cross-domain purchase & browsing graph
  | 'FINGERPRINTING'       // Canvas, GPU & hardware identity
  | 'FIRST_PARTY_CDN'      // Internal video chunks & recommendation tuning
  | 'ANALYTICS';           // Pageviews & bounce rates

export interface TrackerData {
  domain: string;
  count: number;
  category: string;
  blocked: boolean;
  isFirstParty?: boolean;
  parentOrg?: string;
  privacyContext?: string;
  capability?: TrackerCapability;
  dataTypeTracked?: string;
  name?: string;
}

export interface PasswordDestinationInfo {
  destinationUrl: string;
  destinationType: 'VERIFIED_IAM' | 'SAME_ORIGIN' | 'UNENCRYPTED_HTTP' | 'THIRD_PARTY_SUSPICIOUS';
  providerName?: string;
  severity: 'SAFE' | 'MEDIUM' | 'CRITICAL';
  description: string;
  timestamp: string;
}

export interface PrivacyPolicyAnalysis {
  score: number;
  risks: string[];
  summary: string;
  safety?: 'SAFE' | 'RISKY' | 'UNSAFE';
  dataSharing: string[];
  industryType?: string;
  positiveFeatures?: string[];
  analysisDepth?: string;
  lastAnalyzed?: string;
}

export interface DataFlowNode {
  id: string;
  domain: string;
  type: 'source' | 'tracker' | 'destination';
  position: { x: number; y: number };
  capability?: TrackerCapability;
  dataTypeTracked?: string;
}

export interface DataFlowEdge {
  from: string;
  to: string;
  dataType: string;
}

export interface SecurityFinding {
  id: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  category: 'headers' | 'storage' | 'scripts' | 'exposure' | 'mixed_content' | 'forms' | 'redirects';
  evidenceUrl?: string;
  destinationUrl?: string;
  elementId?: string;
  canHighlight?: boolean;
}

export interface SecurityScanResult {
  score: number;
  findings: SecurityFinding[];
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scannedAt: string;
}

export interface UploadRisk {
  type: 'gps' | 'pii_visual' | 'qr_code' | 'metadata' | 'sensitive_text' | 'credentials';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  exploitScenario?: string;
  exactSnippet?: string;
}

export interface UploadScanResult {
  filename: string;
  mimeType: string;
  hasMetadata: boolean;
  metadataFields: string[];
  gps?: GpsCoordinates;
  risks: UploadRisk[];
  overallRisk: 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  gemmaFindings?: string[];
  localVision?: LocalScanResult;
  cleanedAvailable?: boolean;
}

export interface SiteData {
  url: string;
  trustScore: number;
  trackers: TrackerData[];
  privacyAnalysis?: PrivacyPolicyAnalysis;
  securityScan?: SecurityScanResult;
  lastPasswordDestination?: PasswordDestinationInfo;
  dataFlow: {
    nodes: DataFlowNode[];
    edges: DataFlowEdge[];
  };
}
