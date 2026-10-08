import { SiteData, TrackerData } from './types';
import { KavachAIService } from './ai-service';

export interface OrgInfo {
  orgName: string;
  domains: string[];
  purpose: string;
}

export const KNOWN_ORGANIZATIONS: Record<string, OrgInfo> = {
  google: {
    orgName: 'Google / Alphabet',
    domains: ['google.com', 'youtube.com', 'googlevideo.com', 'ytimg.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'ggpht.com', 'doubleclick.net', 'google-analytics.com', 'googletagmanager.com'],
    purpose: 'Internal video delivery & recommendation algorithms (data retained in-house within Google ecosystem)'
  },
  meta: {
    orgName: 'Meta Platforms',
    domains: ['facebook.com', 'instagram.com', 'fbcdn.net', 'whatsapp.com', 'messenger.com', 'meta.com', 'connect.facebook.net'],
    purpose: 'Media CDN & internal feed personalization algorithms'
  },
  microsoft: {
    orgName: 'Microsoft Corporation',
    domains: ['microsoft.com', 'live.com', 'office.com', 'bing.com', 'azure.com', 'github.com', 'linkedin.com', 'msn.com', 'skype.com', 'windows.net'],
    purpose: 'Cloud infrastructure & telemetry'
  },
  amazon: {
    orgName: 'Amazon',
    domains: ['amazon.com', 'media-amazon.com', 'ssl-images-amazon.com', 'a2z.com', 'aws.amazon.com', 'cloudfront.net', 'amazon-adsystem.com'],
    purpose: 'Product delivery CDN & store telemetry'
  },
  apple: {
    orgName: 'Apple Inc.',
    domains: ['apple.com', 'icloud.com', 'mzstatic.com', 'aaplimg.com'],
    purpose: 'Apple cloud sync & media delivery'
  },
  wikimedia: {
    orgName: 'Wikimedia Foundation',
    domains: ['wikipedia.org', 'wikimedia.org', 'wikidata.org'],
    purpose: 'Non-profit encyclopedia delivery (Zero 3rd-party ad tracking)'
  }
};

/**
 * Checks whether two domains belong to the same parent organization.
 * Uses exact match, known org tables, and KavachAIService semantic token analysis.
 */
export function isSameOrganization(sourceDomain: string, targetDomain: string): { isFirstParty: boolean; orgName?: string; purpose?: string } {
  const cleanSource = sourceDomain.toLowerCase().replace(/^www\./, '');
  const cleanTarget = targetDomain.toLowerCase().replace(/^www\./, '');

  // Exact domain or subdomain match
  if (cleanSource === cleanTarget || cleanTarget.endsWith(`.${cleanSource}`) || cleanSource.endsWith(`.${cleanTarget}`)) {
    return { isFirstParty: true, orgName: 'First Party', purpose: 'Primary domain infrastructure' };
  }

  // Check known parent organizations
  for (const org of Object.values(KNOWN_ORGANIZATIONS)) {
    const sourceInOrg = org.domains.some(d => cleanSource.includes(d));
    const targetInOrg = org.domains.some(d => cleanTarget.includes(d));
    if (sourceInOrg && targetInOrg) {
      return { isFirstParty: true, orgName: org.orgName, purpose: org.purpose };
    }
  }

  // Semantic domain & root brand token decomposition
  const semantic = KavachAIService.semanticDomainAnalysis(cleanTarget, cleanSource);
  if (semantic.isFirstParty) {
    return { isFirstParty: true, orgName: semantic.company, purpose: semantic.purpose };
  }

  return { isFirstParty: false };
}

export class TrustScoreCalculator {
  static calculateScore(trackers: TrackerData[], privacyRisks: string[] = [], domain: string = ''): number {
    const cleanDomain = domain.toLowerCase();
    const isTorrentOrPiracy = /1337x|torrent|pirate|rarbg|yts|fmovies|123movies|stream|download|warez|crack|fitgirl|rutracker/i.test(cleanDomain);
    const isAuthentic = /google|youtube|github|microsoft|apple|wikipedia|netflix|reddit|bbc/i.test(cleanDomain);

    // High-risk piracy / torrent ecosystem: starts heavily penalized due to malvertising rotators & popunder traps
    if (isTorrentOrPiracy) {
      let score = 25;
      score -= trackers.length * 2;
      return Math.max(10, Math.min(35, Math.round(score)));
    }

    // Authentic enterprise platforms: in-house video delivery & CDN (e.g. YouTube googlevideo) should NOT deduct score
    if (isAuthentic) {
      const rogueThirdParty = trackers.filter(t => !t.isFirstParty && !t.domain.includes('google') && !t.domain.includes('youtube'));
      let score = 95 - (rogueThirdParty.length * 5);
      return Math.max(85, Math.min(98, Math.round(score)));
    }

    let score = 90;
    
    // Separate first-party internal infrastructure vs actual 3rd-party cross-site trackers
    const thirdPartyTrackers = trackers.filter(t => !t.isFirstParty);
    
    // High-risk third-party trackers (cross-site ad brokers & tracking pixels)
    const adTrackers = thirdPartyTrackers.filter(t => ['advertising', 'social'].includes(t.category));
    score -= adTrackers.length * 7;
    
    // Third-party analytics (external Google Analytics, Mixpanel, Hotjar)
    const extAnalytics = thirdPartyTrackers.filter(t => t.category === 'analytics');
    score -= extAnalytics.length * 3;
    
    // Other unknown third-party domains
    const otherThirdParty = thirdPartyTrackers.filter(t => !['advertising', 'social', 'analytics'].includes(t.category));
    score -= Math.min(otherThirdParty.length * 2, 10);
    
    // Deduct points for privacy policy legal risks
    score -= Math.min(privacyRisks.length * 5, 20);
    
    return Math.max(15, Math.min(100, Math.round(score)));
  }
}

export class PrivacyPolicyAnalyzer {
  // Try localhost first (dev), fall back to Render (prod)
  private static readonly API_BASE_URL = 'http://localhost:3000/api';
  private static readonly FALLBACK_URL = 'https://kavach-hackolution.onrender.com/api';

  private static async fetchWithFallback(path: string, options: RequestInit): Promise<Response> {
    try {
      const response = await fetch(`${this.API_BASE_URL}${path}`, {
        ...options,
        signal: AbortSignal.timeout(35000),
      });
      return response;
    } catch {
      // Backend not running locally — try Render
      return fetch(`${this.FALLBACK_URL}${path}`, {
        ...options,
        signal: AbortSignal.timeout(35000),
      });
    }
  }

  static async analyzePolicy(url: string): Promise<any> {
    try {
      const response = await this.fetchWithFallback('/privacy-policy/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      if (!result.success) throw new Error(result.error || 'Analysis failed');
      return result.data;

    } catch (error) {
      const fallbackAnalysis = {
        score: 50,
        vectorScores: { dataSale: 50, trackingScope: 50, dataRetention: 50, consentQuality: 50, securityStandards: 50 },
        risks: ['Unable to analyze privacy policy — please review manually'],
        summary: 'Privacy policy analysis failed. This could be due to network issues, missing privacy policy, or service unavailability.',
        safety: 'RISKY' as const,
        dataSharing: [],
        industryType: 'Unknown',
        positiveFeatures: [],
        complianceFlags: [],
        dpdpCompliance: { compliant: false, hasDPO: false, hasGrievanceRedressal: false, hasPurposeSpecification: false, hasConsentWithdrawal: false, hasDataLocalization: false, missingRequirements: [] },
        analysisDepth: 'Failed',
        model: 'N/A',
        lastAnalyzed: new Date().toISOString(),
      };

      if (error instanceof Error) {
        if (error.message.includes('timeout') || error.message.includes('AbortError')) {
          fallbackAnalysis.summary = 'Privacy policy analysis timed out. The website may be slow to respond.';
        } else if (error.message.includes('404') || error.message.includes('not found')) {
          fallbackAnalysis.summary = 'No privacy policy was found on this website.';
          fallbackAnalysis.score = 30;
          fallbackAnalysis.risks = ['No privacy policy found', 'Data practices unclear', 'User rights undefined'];
        } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
          fallbackAnalysis.summary = 'Cannot connect to Kavach backend. Run: cd backend && npm run dev';
        }
      }
      return fallbackAnalysis;
    }
  }

  /** Analyze raw policy text extracted by the content script */
  static async analyzePolicyText(url: string, policyText: string): Promise<any> {
    try {
      const response = await this.fetchWithFallback('/privacy-policy/analyze-text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, policyText }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.success) throw new Error(result.error || 'Analysis failed');
      return result.data;
    } catch {
      return this.analyzePolicy(url);
    }
  }

  /** Strip EXIF metadata from a base64 image via backend */
  static async stripImageMetadata(base64Image: string, mimeType: string, filename?: string): Promise<any> {
    try {
      const response = await this.fetchWithFallback('/metadata/strip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base64Image, mimeType, filename }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      return result.success ? result.data : null;
    } catch (error) {
      console.error('Metadata strip failed:', error);
      return null;
    }
  }

  /** Draft a DPDP Act 2023 / GDPR email to the site's DPO */
  static async draftDPOEmail(params: {
    websiteUrl: string;
    concerns?: string[];
    userName?: string;
    userEmail?: string;
    jurisdiction?: 'INDIA' | 'EU' | 'US' | 'GLOBAL';
  }): Promise<any> {
    try {
      const response = await this.fetchWithFallback('/dpo/draft', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      return result.success ? result.data : null;
    } catch (error) {
      console.error('DPO draft failed:', error);
      return null;
    }
  }

  /** Scan image for visible PII using Gemma 4 vision */
  static async scanImageForPII(base64Image: string, mimeType: string): Promise<any> {
    try {
      const response = await this.fetchWithFallback('/image/scan-pii', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base64Image, mimeType }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      return result.success ? result.data : null;
    } catch (error) {
      console.error('Image PII scan failed:', error);
      return null;
    }
  }

  /** Find privacy policy URL for a website */
  static async findPrivacyPolicyUrl(url: string): Promise<string | null> {
    try {
      const response = await this.fetchWithFallback(`/privacy-policy/find?url=${encodeURIComponent(url)}`, {
        method: 'GET',
      });
      if (!response.ok) return null;
      const result = await response.json();
      return result.success ? result.data.policyUrl : null;
    } catch {
      return null;
    }
  }
}

export const commonTrackers: Record<string, { category: string; name: string; capability?: string; dataType?: string }> = {
  // Session Replay & Keystroke loggers
  'hotjar.com': { category: 'session_replay', name: 'Hotjar Session Replay', capability: 'SESSION_REPLAY', dataType: 'Every mouse movement, rage click, scroll depth & form keystrokes' },
  'clarity.ms': { category: 'session_replay', name: 'Microsoft Clarity', capability: 'SESSION_REPLAY', dataType: 'Full session screen recording, scroll heatmaps & user cursor path' },
  'fullstory.com': { category: 'session_replay', name: 'FullStory Replay', capability: 'SESSION_REPLAY', dataType: 'Live video screen replay & typed form field values' },
  'smartlook.com': { category: 'session_replay', name: 'Smartlook Analytics', capability: 'SESSION_REPLAY', dataType: 'Cursor trajectory & user interaction video' },
  'mouseflow.com': { category: 'session_replay', name: 'Mouseflow', capability: 'SESSION_REPLAY', dataType: 'Keystroke logging, form abandonments & mouse heatmaps' },

  // Cross-Site Ad Profilers
  'doubleclick.net': { category: 'advertising', name: 'Google DoubleClick', capability: 'CROSS_SITE_AD', dataType: 'Cross-site ad profile & search intent mapping' },
  'facebook.com': { category: 'social', name: 'Facebook Pixel', capability: 'CROSS_SITE_AD', dataType: 'Links this page view & shopping cart to your Facebook identity' },
  'connect.facebook.net': { category: 'social', name: 'Facebook Connect', capability: 'CROSS_SITE_AD', dataType: 'Social identity correlation & browsing graph' },
  'criteo.com': { category: 'advertising', name: 'Criteo Retargeting', capability: 'CROSS_SITE_AD', dataType: 'Products viewed & items added to shopping carts across websites' },
  'taboola.com': { category: 'advertising', name: 'Taboola Ad Network', capability: 'CROSS_SITE_AD', dataType: 'Clickstream history & personalized content targeting' },
  'outbrain.com': { category: 'advertising', name: 'Outbrain Telemetry', capability: 'CROSS_SITE_AD', dataType: 'Cross-domain publisher browsing patterns' },
  'tiktok.com': { category: 'social', name: 'TikTok Pixel', capability: 'CROSS_SITE_AD', dataType: 'Cross-web ad tracking linked to TikTok device ID' },
  'amazon-adsystem.com': { category: 'advertising', name: 'Amazon Advertising', capability: 'CROSS_SITE_AD', dataType: 'Purchase interests & product search history' },

  // Hardware & Canvas Fingerprinters
  'fpjs.io': { category: 'fingerprinting', name: 'FingerprintJS', capability: 'FINGERPRINTING', dataType: 'GPU canvas rendering, audio buffer & persistent hardware ID' },
  'fingerprint.com': { category: 'fingerprinting', name: 'Fingerprint Pro', capability: 'FINGERPRINTING', dataType: 'Permanent device identity surviving Incognito & VPNs' },

  // General Analytics
  'google-analytics.com': { category: 'analytics', name: 'Google Analytics', capability: 'ANALYTICS', dataType: 'Page URL, session duration, device viewport & referrer' },
  'googletagmanager.com': { category: 'analytics', name: 'Google Tag Manager', capability: 'ANALYTICS', dataType: 'Script container injecting custom tracking events' },
  'twitter.com': { category: 'social', name: 'Twitter Analytics', capability: 'CROSS_SITE_AD', dataType: 'X / Twitter ad conversion tracking' },
  'linkedin.com': { category: 'social', name: 'LinkedIn Insights', capability: 'CROSS_SITE_AD', dataType: 'Job title, company & professional identity mapping' }
};

export class OptOutManager {
  // Website-specific opt-out mechanisms
  static readonly OPT_OUT_STRATEGIES = {
    'google.com': {
      cookiesToSet: [
        'CONSENT=PENDING+999',
        'NID=; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'ANID=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[data-testid="reject-all"]', '.QS5gu'],
      logoutUrl: 'https://accounts.google.com/logout'
    },
    'facebook.com': {
      cookiesToSet: [
        'dpr=; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'wd=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[data-testid="cookie-policy-manage-dialog-decline-button"]'],
      logoutUrl: 'https://www.facebook.com/logout.php'
    },
    'amazon.com': {
      cookiesToSet: [
        'ad-privacy=0',
        'csm-hit=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[data-cy="sp_choice_type_REJECT_ALL"]'],
      logoutUrl: 'https://www.amazon.com/gp/flex/sign-out.html'
    },
    'twitter.com': {
      cookiesToSet: [
        'personalization_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'guest_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[data-testid="decline"]'],
      logoutUrl: 'https://twitter.com/logout'
    },
    'linkedin.com': {
      cookiesToSet: [
        'UserMatchHistory=; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'AnalyticsSyncHistory=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[data-tracking-control-name="consent-banner_decline-all"]'],
      logoutUrl: 'https://www.linkedin.com/uas/logout'
    },
    'youtube.com': {
      cookiesToSet: [
        'CONSENT=PENDING+999',
        'VISITOR_INFO1_LIVE=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[aria-label="Reject all"]', '[data-testid="reject-all-button"]'],
      logoutUrl: 'https://accounts.google.com/logout'
    },
    'instagram.com': {
      cookiesToSet: [
        'ig_nrcb=; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'csrftoken=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
      ],
      selectors: ['[data-testid="cookie-banner-decline"]'],
      logoutUrl: 'https://www.instagram.com/accounts/logout/'
    }
  };

  static getOptOutStrategy(domain: string) {
    // Find matching strategy for domain or subdomain
    const strategies = Object.keys(this.OPT_OUT_STRATEGIES);
    const matchingStrategy = strategies.find(strategyDomain => 
      domain.includes(strategyDomain) || strategyDomain.includes(domain)
    );
    
    return matchingStrategy ? this.OPT_OUT_STRATEGIES[matchingStrategy as keyof typeof this.OPT_OUT_STRATEGIES] : null;
  }

  static getUniversalOptOutCookies(): string[] {
    return [
      'gdpr_consent=false',
      'ccpa_optout=true',
      'privacy_optout=true',
      'cookie_consent=rejected',
      'tracking_consent=false',
      'analytics_consent=false',
      'marketing_consent=false',
      'personalization_consent=false',
      'advertising_consent=false',
      'functional_consent=false',
      'performance_consent=false',
      'social_media_consent=false',
      'opt_out=true',
      'privacy_settings=all_rejected',
      'consent_mode=opt_out',
      'do_not_track=1',
      'user_consent_status=rejected',
      // OneTrust specific
      'OptanonConsent=',
      'OptanonAlertBoxClosed=',
      // Cookiebot specific
      'CookieConsent=no',
      // TrustArc specific
      'notice_behavior=implied,eu',
      'notice_gdpr_prefs=0,1,2,3:',
      // Quantcast specific
      'euconsent-v2=',
      // Generic IAB consent
      'gdpr=1',
      'gdpr_consent=',
      // Site-specific patterns
      'cookies_accepted=false',
      'accept_cookies=no',
      'cookie_policy_accepted=false',
      'data_processing_consent=false'
    ];
  }

  static getUniversalOptOutSelectors(): string[] {
    return [
      // Generic opt-out buttons
      'button[data-testid*="reject"]',
      'button[data-testid*="decline"]', 
      'button[data-testid*="opt-out"]',
      'button[class*="reject"]',
      'button[class*="decline"]',
      'button[class*="opt-out"]',
      'a[href*="opt-out"]',
      'a[href*="unsubscribe"]',
      'a[href*="privacy-settings"]',
      
      // OneTrust CMP
      '#onetrust-reject-all-handler',
      '#onetrust-pc-btn-handler',
      '.optanon-category-2',
      '.optanon-category-3',
      '.optanon-category-4',
      
      // Cookiebot CMP
      '#CybotCookiebotDialogBodyButtonDecline',
      '#CybotCookiebotDialogBodyLevelButtonLevelOptinDeclineAll',
      
      // TrustArc CMP
      '#truste-consent-required',
      '.truste-button-2',
      
      // Quantcast CMP
      '.qc-cmp2-summary-buttons > button:last-child',
      '.qc-cmp2-toggle-switch',
      
      // Generic consent management
      '[data-cy*="reject"]',
      '[data-cy*="decline"]',
      '[data-cy="manage-consent-reject-all"]',
      '[data-testid="consent-reject-all"]',
      '.sp_choice_type_REJECT_ALL',
      
      // Common cookie banner patterns
      '.cookie-banner button[data-role="reject"]',
      '.gdpr-banner .reject-all',
      '.consent-manager .decline-all',
      '.privacy-banner .opt-out',
      
      // Language-specific patterns
      'button:contains("Reject All")',
      'button:contains("Decline All")', 
      'button:contains("Opt Out")',
      'button:contains("Refuse All")',
      'button:contains("Deny All")',
      'button:contains("No Thanks")',
      'button:contains("Disagree")',
      
      // Logout buttons
      'a[href*="logout"]',
      'a[href*="signout"]',
      'a[href*="sign-out"]',
      'button[data-testid*="logout"]',
      'button[data-testid*="signout"]',
      '.logout', '.signout', '.sign-out'
    ];
  }

  static getTrackingDomainsToBlock(): string[] {
    return [
      // Google tracking
      'google-analytics.com',
      'googletagmanager.com',
      'doubleclick.net',
      'googlesyndication.com',
      'googleadservices.com',
      'gstatic.com',
      
      // Facebook/Meta tracking  
      'facebook.com',
      'facebook.net',
      'connect.facebook.net',
      
      // Amazon tracking
      'amazon-adsystem.com',
      'amazonpay.com',
      
      // Microsoft tracking
      'bing.com',
      'microsoft.com',
      'live.com',
      
      // Social media tracking
      'twitter.com',
      'linkedin.com',
      'pinterest.com',
      'tiktok.com',
      'snapchat.com',
      
      // Analytics platforms
      'mixpanel.com',
      'segment.com',
      'amplitude.com',
      'hotjar.com',
      'fullstory.com',
      'logrocket.com',
      'mouseflow.com',
      'crazyegg.com',
      'optimizely.com',
      
      // Ad networks
      'criteo.com',
      'outbrain.com',
      'taboola.com',
      'pubmatic.com',
      'rubiconproject.com',
      'openx.com',
      'adsystem.com'
    ];
  }
}
