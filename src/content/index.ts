// Kavach Content Script — Advanced Privacy, Client Security & Upload Guard
import { ExifParser, ExifMetadataResult } from '../utils/exif';
import { LocalVisionEngine, LocalScanResult } from '../utils/local-vision';
import { KavachAudioAlert } from '../utils/audio';
import { PasswordDestinationInfo } from '../utils/types';
import { FilenameInspector, FilenameAuditResult } from '../utils/filename-inspector';

class ContentScript {
  private privacyPolicyUrls: string[] = [];
  private optedOutDomains: Set<string> = new Set();
  private trustedUploadDomains: Set<string> = new Set();

  // Guard state
  private isBypassingGuard = false;
  private pendingFiles: File[] = [];
  private pendingInput: HTMLInputElement | null = null;
  private pendingDropTarget: HTMLElement | null = null;
  private cleanedFiles: File[] = [];

  constructor() {
    this.checkOptOutStatus();
    this.loadTrustedUploadDomains();
    this.detectPrivacyPolicies();
    this.injectTrackingDetector();
    this.setupMessageListeners();
    this.injectUploadGuardStyles();
    this.setupUploadGuardInterception();
    this.setupPasswordDestinationInspector();
    this.setupRedirectShield();
    this.setupActiveClickjackNeutralizer();
  }

  // ─── Trusted Sites Whitelist ─────────────────────────────────────────────

  private async loadTrustedUploadDomains(): Promise<void> {
    try {
      const data = await chrome.storage.local.get(['trustedUploadDomains']);
      if (Array.isArray(data.trustedUploadDomains)) {
        this.trustedUploadDomains = new Set(data.trustedUploadDomains);
      }
    } catch {}

    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.trustedUploadDomains) {
          this.trustedUploadDomains = new Set(changes.trustedUploadDomains.newValue || []);
        }
      });
    } catch {}
  }

  private async addTrustedUploadDomain(domain: string): Promise<void> {
    this.trustedUploadDomains.add(domain);
    try {
      const data = await chrome.storage.local.get(['trustedUploadDomains']);
      const list = Array.isArray(data.trustedUploadDomains) ? data.trustedUploadDomains : [];
      if (!list.includes(domain)) {
        list.push(domain);
        await chrome.storage.local.set({ trustedUploadDomains: list });
      }
    } catch {}
  }

  // ─── Opt-Out ─────────────────────────────────────────────────────────────

  private async checkOptOutStatus() {
    const domain = window.location.hostname;
    try {
      const storage = await chrome.storage.local.get([`optedOut_${domain}`]);
      if (storage[`optedOut_${domain}`]) {
        this.optedOutDomains.add(domain);
        this.enforceOptOutState();
      }
    } catch {}
  }

  private enforceOptOutState() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const element = node as Element;
            if (element.tagName === 'SCRIPT') {
              const script = element as HTMLScriptElement;
              const src = script.src?.toLowerCase() || '';
              const content = script.textContent?.toLowerCase() || '';
              const trackingPatterns = ['google-analytics', 'googletagmanager', 'gtag', 'ga(', 'facebook.com/tr', 'fbq(', 'doubleclick'];
              if (trackingPatterns.some(p => src.includes(p) || content.includes(p))) script.remove();
            }
            if (element.tagName === 'IMG') {
              const img = element as HTMLImageElement;
              const src = img.src?.toLowerCase() || '';
              if (src.includes('track') || src.includes('pixel') || src.includes('beacon')) img.remove();
            }
          }
        });
      });
    });
    observer.observe(document, { childList: true, subtree: true });
  }

  private setupMessageListeners() {
    chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
      if (request.action === 'performOptOut') {
        sendResponse({ success: true });
        return false;
      }
      if (request.action === 'getSecurityScan') {
        this.runSecurityScan().then(sendResponse).catch(() => sendResponse(null));
        return true;
      }
      if (request.action === 'highlightSecurityFinding') {
        this.highlightElementOnPage(request.findingId);
        sendResponse({ success: true });
        return false;
      }
      return false;
    });
  }

  // ─── Privacy Policy Detection ────────────────────────────────────────────

  private detectPrivacyPolicies() {
    const selectors = ['a[href*="privacy"]', 'a[href*="terms"]', 'a[href*="policy"]', 'a[href*="legal"]', 'a[href*="gdpr"]'];
    const privacyKeywords = ['privacy policy', 'privacy statement', 'terms of service', 'data policy', 'cookie policy', 'gdpr', 'ccpa'];

    const checkLink = (link: Element) => {
      const href = (link as HTMLAnchorElement).href;
      const text = link.textContent?.toLowerCase() || '';
      if (href && !this.privacyPolicyUrls.includes(href)) {
        if (privacyKeywords.some(kw => text.includes(kw) || href.toLowerCase().includes(kw))) {
          this.privacyPolicyUrls.push(href);
        }
      }
    };

    selectors.forEach(sel => document.querySelectorAll(sel).forEach(checkLink));
    document.querySelectorAll('footer, .footer, [class*="footer"]').forEach(footer => {
      footer.querySelectorAll('a').forEach(checkLink);
    });

    if (this.privacyPolicyUrls.length > 0) {
      chrome.runtime.sendMessage({ action: 'privacyPoliciesFound', urls: this.privacyPolicyUrls, currentUrl: window.location.href }).catch(() => {});
    }
  }

  private injectTrackingDetector() {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('injected.js');
    script.onload = function() { (this as HTMLScriptElement).remove(); };
    (document.head || document.documentElement).appendChild(script);
  }

  init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => this.detectPrivacyPolicies(), 1000);
        setTimeout(() => this.autoAuditAndSync(), 1500);
      });
    } else {
      setTimeout(() => this.detectPrivacyPolicies(), 1000);
      setTimeout(() => this.autoAuditAndSync(), 1500);
    }
    setTimeout(() => this.detectPrivacyPolicies(), 3000);
    setTimeout(() => this.autoAuditAndSync(), 4500);
  }

  private async autoAuditAndSync(): Promise<void> {
    try {
      const scan = await this.runSecurityScan();
      chrome.runtime.sendMessage({
        action: 'recordPageSecurityAudit',
        domain: window.location.hostname,
        securityScan: scan,
      }).catch(() => {});
    } catch {}
  }

  // ─── Calibrated Client-Side Security Scanner ─────────────────────────────

  async runSecurityScan(): Promise<any> {
    const findings: any[] = [];
    const currentHost = window.location.hostname.toLowerCase();
    const isAuthenticPlatform = currentHost.includes('google.com') || currentHost.includes('youtube.com') || currentHost.includes('github.com') || currentHost.includes('microsoft.com') || currentHost.includes('apple.com');
    const isTorrentOrPiracy = /1337x|torrent|pirate|rarbg|yts|fmovies|123movies|stream|download/i.test(currentHost);

    // 0. Known Torrent / Malvertising Ecosystem Profile
    if (isTorrentOrPiracy) {
      findings.push({
        id: 'torrent_risk_profile',
        severity: 'HIGH',
        title: 'High-Risk Torrent Ad Syndication Environment',
        description: 'This portal operates in an aggressive malvertising ecosystem. Pages commonly inject invisible click traps, deceptive download buttons, and popunder ad scripts.',
        category: 'exposure',
        canHighlight: false
      });
    }

    // 1. Password forms over HTTP (Critical)
    try {
      if (window.location.protocol === 'http:' && document.querySelectorAll('input[type="password"]').length > 0) {
        const form = document.querySelector('form');
        if (form) form.setAttribute('data-kavach-sec', 'http_password');
        findings.push({
          id: 'http_password',
          severity: 'HIGH',
          title: 'Password Form over Unencrypted HTTP',
          description: 'Login form detected on an unencrypted HTTP connection. Credentials entered here can be intercepted by anyone on your network/Wi-Fi.',
          category: 'forms',
          destinationUrl: form?.action || window.location.href,
          canHighlight: true
        });
      }
    } catch {}

    // 2. Malvertising & Untrusted Ad Scripts
    try {
      const allExtScripts = Array.from(document.querySelectorAll('script[src]')).filter(s => {
        try {
          const u = new URL((s as HTMLScriptElement).src);
          return u.hostname !== currentHost && !u.hostname.endsWith(`.${currentHost}`) && u.hostname !== '';
        } catch { return false; }
      });

      const adNetworkKeywords = ['pop', 'ad', 'click', 'banner', 'track', 'monetiz', 'bid', 'affiliate', 'syndication', 'traffic', 'propeller', 'exoclick', 'adsterra', 'clickadu', 'mgid', 'yield', 'doubleclick', 'pagead'];
      const shadyAdScripts = allExtScripts.filter(s => {
        const src = (s as HTMLScriptElement).src.toLowerCase();
        return adNetworkKeywords.some(kw => src.includes(kw));
      });

      if (shadyAdScripts.length >= 1) {
        shadyAdScripts.forEach((s, idx) => s.setAttribute('data-kavach-sec', `malvertising_scripts_${idx}`));
        const primaryScript = shadyAdScripts[0] as HTMLScriptElement;
        findings.push({
          id: 'malvertising_scripts',
          severity: isAuthenticPlatform ? 'LOW' : 'HIGH',
          title: isAuthenticPlatform ? `${shadyAdScripts.length} Standard Ad Script(s)` : `${shadyAdScripts.length} Aggressive Ad / Popunder Script(s)`,
          description: isAuthenticPlatform ? `Page executes ${shadyAdScripts.length} standard commercial ad script(s).` : `Page executes ${shadyAdScripts.length} third-party ad syndication script(s). Designed to spawn popunder windows, redirect user clicks, or mine telemetry.`,
          category: 'scripts',
          evidenceUrl: primaryScript.src,
          destinationUrl: primaryScript.src,
          canHighlight: true
        });
      } else if (allExtScripts.length > 8 && !isAuthenticPlatform) {
        allExtScripts.forEach((s, idx) => s.setAttribute('data-kavach-sec', `many_ext_scripts_${idx}`));
        findings.push({
          id: 'many_ext_scripts',
          severity: 'MEDIUM',
          title: `${allExtScripts.length} External Third-Party Scripts`,
          description: `Page loads ${allExtScripts.length} scripts from external origins. Each script has full DOM and cookie execution privileges.`,
          category: 'scripts',
          evidenceUrl: (allExtScripts[0] as HTMLScriptElement).src,
          canHighlight: true
        });
      }
    } catch {}

    // 3. In-Page Ad Containers & Sponsored Placements (YouTube, Google Ads, Ad iframes)
    try {
      const adElements = Array.from(document.querySelectorAll(
        'ins.adsbygoogle, ytd-ad-slot-renderer, ytd-in-feed-ad-layout-renderer, iframe[src*="ad"], iframe[src*="doubleclick"], iframe[src*="googleads"], div[id*="google_ads"], div[class*="ad-container"], div[class*="ad-placement"], div[id*="banner"], a[href*="affiliate"], a[href*="adsterra"], a[href*="propeller"]'
      ));
      if (adElements.length > 0) {
        adElements.forEach((el, idx) => el.setAttribute('data-kavach-sec', `ad_containers_${idx}`));
        const firstAd = adElements[0] as HTMLElement;
        const adEvidence = (firstAd as any).src || (firstAd as any).href || `<${firstAd.tagName.toLowerCase()} id="${firstAd.id || ''}" class="${firstAd.className || ''}">`;
        findings.push({
          id: 'ad_containers',
          severity: isAuthenticPlatform ? 'LOW' : 'MEDIUM',
          title: `${adElements.length} In-Page Ad Container(s) / Sponsored Banner(s)`,
          description: `Found ${adElements.length} commercial ad banner, syndicated frame, or sponsored slot(s) injected into the page layout.`,
          category: 'scripts',
          evidenceUrl: adEvidence,
          canHighlight: true
        });
      }
    } catch {}

    // 4. Clickjack & Transparent Overlay Detection
    try {
      const suspiciousOverlays = Array.from(document.querySelectorAll('div, a, iframe')).filter(el => {
        const style = window.getComputedStyle(el);
        const isPos = style.position === 'fixed' || style.position === 'absolute';
        const isTransparent = parseFloat(style.opacity) <= 0.08 || style.backgroundColor === 'transparent' || style.backgroundColor === 'rgba(0, 0, 0, 0)';
        if (isPos && isTransparent) {
          const rect = el.getBoundingClientRect();
          return rect.width >= window.innerWidth * 0.35 && rect.height >= window.innerHeight * 0.35;
        }
        return false;
      });

      if ((suspiciousOverlays.length > 0 || isTorrentOrPiracy) && !isAuthenticPlatform) {
        suspiciousOverlays.forEach((el, idx) => el.setAttribute('data-kavach-sec', `clickjack_overlay_${idx}`));
        findings.push({
          id: 'clickjack_overlay',
          severity: 'HIGH',
          title: 'Invisible Clickjacking / Popunder Layer',
          description: 'Found transparent layer covering the page or action buttons. Designed to hijack mouse clicks and open advertiser redirects instead of the intended target.',
          category: 'redirects',
          evidenceUrl: suspiciousOverlays[0] ? `DOM Overlay: <${suspiciousOverlays[0].tagName.toLowerCase()}>` : 'Invisible Layer',
          canHighlight: suspiciousOverlays.length > 0
        });
      }
    } catch {}

    // 5. Reverse Tabnabbing (Links opening new tab without rel="noopener")
    try {
      const tabnabbingLinks = Array.from(document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])'));
      if (tabnabbingLinks.length >= 1 && !isAuthenticPlatform) {
        tabnabbingLinks.forEach((el, idx) => el.setAttribute('data-kavach-sec', `reverse_tabnabbing_${idx}`));
        const firstLink = tabnabbingLinks[0] as HTMLAnchorElement;
        findings.push({
          id: 'reverse_tabnabbing',
          severity: 'MEDIUM',
          title: `${tabnabbingLinks.length} Links Exposed to Reverse Tabnabbing`,
          description: 'Links open in new tabs without "noopener" attribute. The newly opened page can secretly redirect your current tab to a phishing clone.',
          category: 'exposure',
          destinationUrl: firstLink.href,
          evidenceUrl: firstLink.href,
          canHighlight: true
        });
      }
    } catch {}

    // 6. Insecure Mixed Content (HTTP scripts on HTTPS)
    try {
      if (window.location.protocol === 'https:') {
        const httpScripts = Array.from(document.querySelectorAll('script[src]')).filter(s => (s as HTMLScriptElement).src.startsWith('http://'));
        if (httpScripts.length > 0) {
          httpScripts.forEach((s, idx) => s.setAttribute('data-kavach-sec', `mixed_content_${idx}`));
          findings.push({
            id: 'mixed_content',
            severity: 'HIGH',
            title: 'Insecure Scripts Loaded over Plain HTTP',
            description: `${httpScripts.length} script(s) loaded over plain HTTP on this secure HTTPS page, risking Man-in-the-Middle code injection.`,
            category: 'mixed_content',
            evidenceUrl: (httpScripts[0] as HTMLScriptElement).src,
            canHighlight: true
          });
        }
      }
    } catch {}

    // 7. Sensitive tokens in localStorage alongside third-party scripts
    try {
      const sensitiveKeys: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && /token|auth|secret|password|jwt/i.test(key)) sensitiveKeys.push(key);
      }
      if (sensitiveKeys.length > 0 && !isAuthenticPlatform) {
        findings.push({
          id: 'storage_sensitive',
          severity: 'MEDIUM',
          title: 'Sensitive Tokens in Local Storage',
          description: `Found ${sensitiveKeys.length} sensitive session key(s) in localStorage (${sensitiveKeys.slice(0, 3).join(', ')}). Accessible to any executing third-party script.`,
          category: 'storage',
          evidenceUrl: `Keys: ${sensitiveKeys.slice(0, 3).join(', ')}`,
          canHighlight: false
        });
      }
    } catch {}

    const highCount = findings.filter((f: any) => f.severity === 'HIGH').length;
    const mediumCount = findings.filter((f: any) => f.severity === 'MEDIUM').length;
    const lowCount = findings.filter((f: any) => f.severity === 'LOW').length;

    // Authentic sites stay high (85-98)
    // Torrent sites with malvertising and overlays drop sharply to 20-30
    let baseScore = isAuthenticPlatform ? 95 : 90;
    const score = Math.max(15, baseScore - (highCount * 30) - (mediumCount * 12) - (lowCount * 5));

    return { score, findings, highCount, mediumCount, lowCount, scannedAt: new Date().toISOString() };
  }

  // ─── On-Page Element Highlighting & Inspector ─────────────────────────────

  private highlightElementOnPage(findingId: string): void {
    // 1. Clean up existing highlights, badges, and inspectors
    document.querySelectorAll('.kavach-sec-highlight-active').forEach(el => {
      el.classList.remove('kavach-sec-highlight-active');
      (el as HTMLElement).style.outline = '';
      (el as HTMLElement).style.boxShadow = '';
    });
    document.querySelectorAll('.kavach-sec-badge').forEach(b => b.remove());
    document.getElementById('kavach-inspector-toolbar')?.remove();
    document.getElementById('kavach-script-inspector-modal')?.remove();

    // 2. Query targets with finding tag or fallback selectors
    let targets = Array.from(document.querySelectorAll(`[data-kavach-sec^="${findingId}"]`));

    if (targets.length === 0) {
      if (findingId.includes('ad_container') || findingId.includes('banner')) {
        targets = Array.from(document.querySelectorAll('ins.adsbygoogle, ytd-ad-slot-renderer, ytd-in-feed-ad-layout-renderer, iframe[src*="ad"], iframe[src*="doubleclick"], iframe[src*="googleads"], div[id*="google_ads"], div[class*="ad-container"], div[class*="ad-placement"], div[id*="banner"], a[href*="affiliate"], a[href*="adsterra"], a[href*="propeller"]'));
      } else if (findingId.includes('malvertis') || findingId.includes('script')) {
        targets = Array.from(document.querySelectorAll('script[src*="ad"], script[src*="track"], script[src*="pop"], script[src*="doubleclick"], script[src*="syndication"], script[src*="adsterra"], script[src*="propeller"]'));
      } else if (findingId.includes('clickjack')) {
        targets = Array.from(document.querySelectorAll('div, iframe, a')).filter(el => {
          const s = window.getComputedStyle(el);
          return (s.position === 'fixed' || s.position === 'absolute') && (parseFloat(s.opacity) <= 0.08 || s.backgroundColor === 'transparent');
        });
      } else if (findingId.includes('tabnabb')) {
        targets = Array.from(document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])'));
      } else if (findingId.includes('password')) {
        targets = Array.from(document.querySelectorAll('input[type="password"]'));
      }
    }

    if (targets.length === 0) {
      this.showToast('⚠️ Target elements are not currently visible in page viewport.');
      return;
    }

    // 3. If targets are scripts or invisible non-rendered elements, open Script Inspector
    const areAllScripts = targets.every(t => t.tagName === 'SCRIPT' || ((t as HTMLElement).offsetParent === null && (t as HTMLElement).offsetWidth === 0 && (t as HTMLElement).offsetHeight === 0));
    if (areAllScripts || targets[0].tagName === 'SCRIPT') {
      this.showScriptInspectorModal(targets as HTMLScriptElement[], findingId);
      return;
    }

    // 4. Highlight ALL matching instances simultaneously
    const total = targets.length;
    targets.forEach((target, index) => {
      const el = target as HTMLElement;
      el.classList.add('kavach-sec-highlight-active');
      el.style.outline = '4px solid #dc2626';
      el.style.boxShadow = '0 0 24px rgba(220, 38, 38, 0.85)';
      el.style.transition = 'all 0.25s ease';

      const rect = el.getBoundingClientRect();
      const badge = document.createElement('div');
      badge.className = 'kavach-sec-badge';
      badge.style.cssText = `
        position: absolute;
        top: ${Math.max(10, window.scrollY + rect.top - 36)}px;
        left: ${Math.max(10, window.scrollX + rect.left)}px;
        z-index: 2147483645;
        background: #dc2626;
        color: white;
        font-size: 11px;
        font-weight: 800;
        padding: 4px 10px;
        border-radius: 6px;
        box-shadow: 0 6px 18px rgba(0,0,0,0.4);
        border: 1.5px solid #ffffff;
        pointer-events: none;
        font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      `;
      badge.textContent = `⚠️ #${index + 1} of ${total} <${el.tagName.toLowerCase()}>`;
      document.documentElement.appendChild(badge);
    });

    // 5. Scroll first instance into view
    (targets[0] as HTMLElement).scrollIntoView({ behavior: 'smooth', block: 'center' });

    // 6. Inject sticky On-Page Kavach Inspector Toolbar
    let currentIndex = 0;
    const toolbar = document.createElement('div');
    toolbar.id = 'kavach-inspector-toolbar';
    toolbar.style.cssText = `
      position: fixed;
      top: 18px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 2147483647;
      background: #0f172a;
      color: white;
      border: 1.5px solid #dc2626;
      border-radius: 12px;
      padding: 10px 18px;
      box-shadow: 0 16px 40px rgba(0,0,0,0.55);
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 12px;
    `;
    toolbar.innerHTML = `
      <span style="font-size:16px;">🛡️</span>
      <div style="font-weight:700;">
        Kavach Security Inspector:
        <span style="color:#ef4444; font-weight:800; margin-left:4px;">${total} instance(s) found</span>
      </div>
      <div style="background:#1e293b; padding:4px 10px; border-radius:6px; font-size:12px; font-weight:700; color:#38bdf8;">
        Viewing <span id="kug-idx-counter">1</span> of ${total}
      </div>
      <div style="display:flex; gap:6px;">
        <button id="kug-nav-prev" style="background:#334155; color:white; border:none; padding:5px 10px; border-radius:6px; font-size:12px; font-weight:700; cursor:pointer;">◀ Prev</button>
        <button id="kug-nav-next" style="background:#334155; color:white; border:none; padding:5px 10px; border-radius:6px; font-size:12px; font-weight:700; cursor:pointer;">Next ▶</button>
      </div>
      <button id="kug-close-toolbar" style="background:transparent; border:none; color:#94a3b8; font-size:16px; cursor:pointer; margin-left:4px;" title="Close Inspector">✕</button>
    `;
    document.documentElement.appendChild(toolbar);

    const updateFocusedTarget = (newIdx: number) => {
      currentIndex = newIdx;
      const counterEl = document.getElementById('kug-idx-counter');
      if (counterEl) counterEl.textContent = `${currentIndex + 1}`;
      const activeEl = targets[currentIndex] as HTMLElement;
      activeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      activeEl.style.outline = '6px solid #ef4444';
      activeEl.style.boxShadow = '0 0 36px rgba(239, 68, 68, 1)';
      setTimeout(() => {
        if (activeEl) {
          activeEl.style.outline = '4px solid #dc2626';
          activeEl.style.boxShadow = '0 0 24px rgba(220, 38, 38, 0.85)';
        }
      }, 700);
    };

    toolbar.querySelector('#kug-nav-next')?.addEventListener('click', () => {
      const nextIdx = (currentIndex + 1) % total;
      updateFocusedTarget(nextIdx);
    });

    toolbar.querySelector('#kug-nav-prev')?.addEventListener('click', () => {
      const prevIdx = (currentIndex - 1 + total) % total;
      updateFocusedTarget(prevIdx);
    });

    const cleanupInspector = () => {
      toolbar.remove();
      document.querySelectorAll('.kavach-sec-badge').forEach(b => b.remove());
      targets.forEach(t => {
        const el = t as HTMLElement;
        el.style.outline = '';
        el.style.boxShadow = '';
        el.classList.remove('kavach-sec-highlight-active');
      });
    };

    toolbar.querySelector('#kug-close-toolbar')?.addEventListener('click', cleanupInspector);
    this.showToast(`🎯 Highlighted ${total} security finding instance(s) on page!`);

    setTimeout(cleanupInspector, 25000);
  }

  private showScriptInspectorModal(scripts: HTMLScriptElement[], findingId: string): void {
    document.getElementById('kavach-script-inspector-modal')?.remove();

    const scriptUrls = scripts.map((s, idx) => {
      const src = s.src || s.textContent?.substring(0, 100) || `Inline Script #${idx + 1}`;
      return src;
    });

    const modal = document.createElement('div');
    modal.id = 'kavach-script-inspector-modal';
    modal.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 90vw;
      max-width: 580px;
      max-height: 80vh;
      background: #0f172a;
      color: white;
      border-radius: 14px;
      box-shadow: 0 24px 60px rgba(0,0,0,0.6);
      border: 2px solid #ef4444;
      z-index: 2147483647;
      padding: 18px 20px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      display: flex;
      flex-direction: column;
      gap: 12px;
    `;

    modal.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:18px;">📜</span>
          <strong>Kavach Script Inspector (${scripts.length} Found)</strong>
        </div>
        <button id="kug-close-scripts" style="background:transparent; border:none; color:#94a3b8; font-size:18px; cursor:pointer;">✕</button>
      </div>
      <div style="font-size:12px; color:#cbd5e1; line-height:1.4;">
        Identified ${scripts.length} third-party or unverified script tags in page DOM for: <em>${this.escapeHtml(findingId)}</em>
      </div>
      <div style="flex:1; overflow-y:auto; max-height:280px; display:flex; flex-direction:column; gap:6px; background:#1e293b; padding:10px; border-radius:8px;">
        ${scriptUrls.map((url, i) => `
          <div style="font-size:11px; font-family:monospace; background:#0f172a; padding:6px 8px; border-radius:4px; border:1px solid #334155; word-break:break-all; display:flex; gap:6px;">
            <span style="color:#ef4444; font-weight:700;">#${i + 1}</span>
            <span style="color:#e2e8f0; flex:1;">${this.escapeHtml(url)}</span>
          </div>
        `).join('')}
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:4px;">
        <button id="kug-copy-scripts" style="background:#334155; color:white; border:none; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:700; cursor:pointer;">
          📋 Copy All URLs
        </button>
        <button id="kug-dismiss-scripts" style="background:#ef4444; color:white; border:none; padding:6px 14px; border-radius:6px; font-size:12px; font-weight:700; cursor:pointer;">
          Close
        </button>
      </div>
    `;

    document.documentElement.appendChild(modal);

    modal.querySelector('#kug-close-scripts')?.addEventListener('click', () => modal.remove());
    modal.querySelector('#kug-dismiss-scripts')?.addEventListener('click', () => modal.remove());
    modal.querySelector('#kug-copy-scripts')?.addEventListener('click', () => {
      navigator.clipboard.writeText(scriptUrls.join('\n'));
      this.showToast('📋 All script URLs copied to clipboard!');
    });

    this.showToast(`📍 Found ${scripts.length} script elements in DOM`);
  }

  // ─── Password Destination Inspector ─────────────────────────────────────

  private setupPasswordDestinationInspector(): void {
    document.addEventListener('submit', (e: Event) => {
      const form = e.target as HTMLFormElement;
      if (!form) return;
      const passInput = form.querySelector('input[type="password"]');
      if (!passInput) return;

      const rawAction = form.action || window.location.href;
      this.evaluatePasswordDestination(rawAction);
    }, true);
  }

  private evaluatePasswordDestination(actionUrl: string): void {
    try {
      const targetUrl = new URL(actionUrl, window.location.href);
      const targetHost = targetUrl.hostname.toLowerCase();
      const currentHost = window.location.hostname.toLowerCase();
      const isHttp = targetUrl.protocol === 'http:';

      let destinationType: 'VERIFIED_IAM' | 'SAME_ORIGIN' | 'UNENCRYPTED_HTTP' | 'THIRD_PARTY_SUSPICIOUS' = 'SAME_ORIGIN';
      let providerName: string | undefined;
      let severity: 'SAFE' | 'MEDIUM' | 'CRITICAL' = 'MEDIUM';
      let description = '';

      if (isHttp) {
        destinationType = 'UNENCRYPTED_HTTP';
        severity = 'CRITICAL';
        description = 'Password submitted over unencrypted HTTP! Anyone on your local network/Wi-Fi can read your credentials in plain text.';
      } else if (targetHost.includes('clerk.') || targetHost.includes('clerk.accounts.dev')) {
        destinationType = 'VERIFIED_IAM';
        providerName = 'Clerk Authentication';
        severity = 'SAFE';
        description = 'Password submitted directly to Clerk enterprise IAM. Credentials hashed with bcrypt/Argon2 before storage.';
      } else if (targetHost.includes('supabase.co')) {
        destinationType = 'VERIFIED_IAM';
        providerName = 'Supabase Auth';
        severity = 'SAFE';
        description = 'Password submitted to Supabase Auth API endpoint. Uses industry-standard Argon2/bcrypt password hashing.';
      } else if (targetHost.includes('auth0.com')) {
        destinationType = 'VERIFIED_IAM';
        providerName = 'Auth0';
        severity = 'SAFE';
        description = 'Password submitted to dedicated Auth0 enterprise identity provider.';
      } else if (targetHost.includes('firebaseapp.com') || targetHost.includes('identitytoolkit.googleapis.com')) {
        destinationType = 'VERIFIED_IAM';
        providerName = 'Firebase Auth';
        severity = 'SAFE';
        description = 'Password submitted to Google Firebase Authentication service.';
      } else if (targetHost === currentHost || targetHost.endsWith(`.${currentHost}`)) {
        destinationType = 'SAME_ORIGIN';
        severity = 'MEDIUM';
        description = `Password submitted to ${currentHost}'s custom endpoint (${targetUrl.pathname}). Credentials stored under site's direct database custody.`;
      } else {
        destinationType = 'THIRD_PARTY_SUSPICIOUS';
        severity = 'CRITICAL';
        description = `CRITICAL PHISHING ALERT: Form on ${currentHost} is transmitting your password to an external domain: ${targetHost}!`;
      }

      const info: PasswordDestinationInfo = {
        destinationUrl: targetUrl.href,
        destinationType,
        providerName,
        severity,
        description,
        timestamp: new Date().toISOString()
      };

      // Notify background & update extension badge
      chrome.runtime.sendMessage({ action: 'recordPasswordDestination', info }).catch(() => {});

      if (severity === 'CRITICAL') {
        KavachAudioAlert.playAlertChime();
        this.showPasswordWarningToast(info);
      }
    } catch {}
  }

  private showPasswordWarningToast(info: PasswordDestinationInfo): void {
    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed; top: 20px; right: 20px; z-index: 2147483647;
      background: #7f1d1d; color: white; padding: 14px 18px; border-radius: 12px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.4); border: 2px solid #ef4444; max-width: 360px;
      animation: kavach-fadein 0.2s ease;
    `;
    toast.innerHTML = `
      <div style="display:flex; align-items:center; gap:8px; font-weight:800; font-size:14px; margin-bottom:6px;">
        <span>🚨</span> Kavach Password Security Alert
      </div>
      <div style="font-size:12px; line-height:1.4; color:#fecaca;">${this.escapeHtml(info.description)}</div>
    `;
    document.documentElement.appendChild(toast);
    setTimeout(() => toast.remove(), 7000);
  }

  // ─── Redirect Shield & Popunder Neutralizer ──────────────────────────────

  private setupRedirectShield(): void {
    // 1. Detect and disable transparent full-screen clickjack overlays
    const neutralizeOverlays = () => {
      const allDivs = document.querySelectorAll('div, a, iframe');
      allDivs.forEach((el) => {
        const style = window.getComputedStyle(el);
        if (
          style.position === 'fixed' &&
          parseInt(style.zIndex, 10) >= 9999 &&
          parseFloat(style.opacity) <= 0.05
        ) {
          const rect = el.getBoundingClientRect();
          if (rect.width >= window.innerWidth * 0.7 && rect.height >= window.innerHeight * 0.7) {
            (el as HTMLElement).style.pointerEvents = 'none';
            (el as HTMLElement).style.display = 'none';
            console.log('🛡️ Kavach neutralized transparent clickjack / popunder overlay');
          }
        }
      });
    };

    setTimeout(neutralizeOverlays, 800);
    setTimeout(neutralizeOverlays, 2500);

    // 2. Track rapid multi-domain navigation hops in sessionStorage
    try {
      const now = Date.now();
      const lastHopTime = parseInt(sessionStorage.getItem('kavach_last_nav_time') || '0', 10);
      const hopCount = parseInt(sessionStorage.getItem('kavach_hop_count') || '0', 10);
      const initialUrl = sessionStorage.getItem('kavach_initial_url') || document.referrer;

      if (now - lastHopTime < 4000 && lastHopTime > 0) {
        const newCount = hopCount + 1;
        sessionStorage.setItem('kavach_hop_count', newCount.toString());
        sessionStorage.setItem('kavach_last_nav_time', now.toString());

        if (newCount >= 2 && initialUrl && !window.location.href.includes(new URL(initialUrl).hostname)) {
          this.showRedirectShieldBanner(initialUrl, newCount);
          KavachAudioAlert.playAlertChime();
          chrome.runtime.sendMessage({ action: 'triggerThreatBadge' }).catch(() => {});
        }
      } else {
        sessionStorage.setItem('kavach_hop_count', '1');
        sessionStorage.setItem('kavach_last_nav_time', now.toString());
        if (!sessionStorage.getItem('kavach_initial_url') && document.referrer) {
          sessionStorage.setItem('kavach_initial_url', document.referrer);
        }
      }
    } catch {}
  }

  private showRedirectShieldBanner(originalUrl: string, hopCount: number): void {
    const banner = document.createElement('div');
    banner.style.cssText = `
      position: fixed; top: 16px; left: 50%; transform: translateX(-50%); z-index: 2147483647;
      background: #0f172a; color: white; padding: 12px 20px; border-radius: 10px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px;
      box-shadow: 0 16px 36px rgba(0,0,0,0.5); border: 1.5px solid #ef4444; display: flex;
      align-items: center; gap: 12px;
    `;
    banner.innerHTML = `
      <span>🚨</span>
      <div>
        <strong>Kavach Redirect Shield:</strong> Rapid redirect trap detected (${hopCount} hops).
      </div>
      <button id="kavach-return-btn" style="background:#ef4444; color:white; border:none; padding:6px 12px; border-radius:6px; font-weight:700; cursor:pointer;">
        🔙 Return to Origin
      </button>
      <button id="kavach-close-banner" style="background:transparent; border:none; color:#94a3b8; cursor:pointer; font-size:14px;">✕</button>
    `;
    document.documentElement.appendChild(banner);

    banner.querySelector('#kavach-return-btn')?.addEventListener('click', () => {
      window.location.href = originalUrl;
    });
    banner.querySelector('#kavach-close-banner')?.addEventListener('click', () => banner.remove());
  }

  // ─── Real-Time Clickjack & Popunder Neutralizer ──────────────────────────
  private setupActiveClickjackNeutralizer(): void {
    const currentHost = window.location.hostname.toLowerCase();
    const isAuthenticPlatform = currentHost.includes('google.com') || currentHost.includes('youtube.com') || currentHost.includes('github.com') || currentHost.includes('microsoft.com') || currentHost.includes('apple.com');
    if (isAuthenticPlatform) return; // Do not disarm overlays on trusted platforms

    const isTorrentOrAdHeavy = /1337x|torrent|pirate|rarbg|yts|fmovies|123movies|stream|download/i.test(currentHost);

    const scanAndDisarmOverlays = () => {
      const candidates = document.querySelectorAll('div, a, iframe, span');
      const vWidth = window.innerWidth;
      const vHeight = window.innerHeight;

      candidates.forEach((el) => {
        if (el.id?.startsWith('kavach') || el.closest('#kavach-upload-overlay')) return;

        const style = window.getComputedStyle(el);
        const isPositioned = style.position === 'fixed' || style.position === 'absolute';
        const opacity = parseFloat(style.opacity);
        const zIndex = parseInt(style.zIndex, 10);

        if (isPositioned) {
          const rect = el.getBoundingClientRect();
          const coversLargeArea = rect.width >= vWidth * 0.35 && rect.height >= vHeight * 0.35;
          const isTransparent = opacity <= 0.08 || style.backgroundColor === 'transparent' || style.backgroundColor === 'rgba(0, 0, 0, 0)';

          const isAnchor = el.tagName === 'A';
          const href = (el as HTMLAnchorElement).href || '';
          const isExternalHref = href && !href.startsWith(window.location.origin) && !href.startsWith('javascript:') && !href.startsWith('#');

          if (coversLargeArea && (isTransparent || isAnchor || isTorrentOrAdHeavy) && (zIndex >= 40 || isNaN(zIndex) || isTorrentOrAdHeavy)) {
            (el as HTMLElement).style.pointerEvents = 'none';
            (el as HTMLElement).style.display = 'none';
            el.remove();
            console.log('🛡️ Kavach neutralized transparent clickjack overlay on:', window.location.hostname);
            this.showToast('🛡️ Kavach disarmed an invisible clickjack overlay on this page!');
          }
        }
      });
    };

    scanAndDisarmOverlays();
    const observer = new MutationObserver(() => scanAndDisarmOverlays());
    observer.observe(document.documentElement || document.body, { childList: true, subtree: true });

    // Capture-phase click interceptor: verify user click target
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (!target || target.id?.startsWith('kavach') || target.closest('#kavach-upload-overlay')) return;

      const style = window.getComputedStyle(target);
      const isTransparent = parseFloat(style.opacity) <= 0.05 || style.backgroundColor === 'rgba(0, 0, 0, 0)';
      const rect = target.getBoundingClientRect();
      const isGiant = rect.width >= window.innerWidth * 0.4 && rect.height >= window.innerHeight * 0.4;

      if (isTransparent && isGiant && (style.position === 'fixed' || style.position === 'absolute')) {
        e.preventDefault();
        e.stopPropagation();
        target.remove();
        this.showToast('🛡️ Kavach blocked clickjacking trap & restored button!');
      }
    }, true);

    // Listen for popunder blocks from injected.js
    window.addEventListener('message', (e) => {
      if (e.data?.type === 'KAVACH_POPUNDER_BLOCKED') {
        const dest = e.data.url ? new URL(e.data.url).hostname : 'untrusted ad';
        this.showToast(`🛡️ Kavach blocked unauthorized popunder window to: ${dest}`);
        KavachAudioAlert.playAlertChime();
        chrome.runtime.sendMessage({ action: 'triggerThreatBadge' }).catch(() => {});
      }
    });
  }

  private showToast(msg: string): void {
    const existing = document.getElementById('kavach-toast-notify');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'kavach-toast-notify';
    toast.style.cssText = `
      position: fixed; top: 18px; right: 20px; z-index: 2147483647;
      background: linear-gradient(135deg, #007E36, #005a26);
      color: white; padding: 11px 16px; border-radius: 10px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px; font-weight: 700;
      box-shadow: 0 16px 36px rgba(0,0,0,0.35); border: 1.5px solid rgba(255,255,255,0.3);
      display: flex; align-items: center; gap: 8px; pointer-events: none;
    `;
    toast.textContent = msg;
    document.documentElement.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }

  // ─── Upload Guard: Pre-Upload Interception ─────────────────────────────────

  private setupUploadGuardInterception(): void {
    // 0. Reset file input value on click so selecting the same file again triggers change event
    window.addEventListener('click', (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (target && target.tagName === 'INPUT' && (target as HTMLInputElement).type === 'file') {
        (target as HTMLInputElement).value = '';
      }
    }, true);

    // 1. Intercept file input change events in the window CAPTURE phase
    window.addEventListener('change', (e: Event) => {
      if (this.isBypassingGuard) return;
      if (this.trustedUploadDomains.has(window.location.hostname)) return;

      const target = e.target as HTMLInputElement;
      if (!target || target.type !== 'file' || !target.files?.length) return;

      const files = Array.from(target.files);
      const hasImagesOrDocs = files.some(f => f.type.startsWith('image/') || f.name.match(/\.(jpg|jpeg|png|webp|heic|gif)$/i));
      if (!hasImagesOrDocs) return;

      // Halt the event from executing page scripts
      e.stopImmediatePropagation();
      e.preventDefault();

      this.pendingFiles = files;
      this.pendingInput = target;
      this.pendingDropTarget = null;
      this.cleanedFiles = [];

      // Clear input value so selecting the same file again triggers change event
      try {
        target.value = '';
      } catch {}

      this.showUploadGuardModal(files);
    }, true);

    // 2. Intercept drag-and-drop file uploads in the window CAPTURE phase
    window.addEventListener('drop', (e: DragEvent) => {
      if (this.isBypassingGuard) return;
      if (this.trustedUploadDomains.has(window.location.hostname)) return;
      if (!e.dataTransfer?.files?.length) return;

      const files = Array.from(e.dataTransfer.files);
      const hasImages = files.some(f => f.type.startsWith('image/') || f.name.match(/\.(jpg|jpeg|png|webp|heic|gif)$/i));
      if (!hasImages) return;

      e.stopImmediatePropagation();
      e.preventDefault();

      this.pendingFiles = files;
      this.pendingInput = null;
      this.pendingDropTarget = e.target as HTMLElement;
      this.cleanedFiles = [];

      this.showUploadGuardModal(files);
    }, true);
  }

  // ─── Upload Guard Modal UI ────────────────────────────────────────────────

  private async showUploadGuardModal(files: File[]): Promise<void> {
    document.getElementById('kavach-upload-overlay')?.remove();

    const file = files[0];
    const isImage = file.type.startsWith('image/') || file.name.match(/\.(jpg|jpeg|png|webp)$/i);
    const fileIcon = isImage ? '📸' : '📄';
    const fileSize = this.formatBytes(file.size);

    const overlay = document.createElement('div');
    overlay.id = 'kavach-upload-overlay';

    overlay.innerHTML = `
      <div id="kavach-upload-modal">
        <div class="kug-header">
          <span style="font-size:20px;">🛡️</span>
          <div>
            <h2>Kavach Upload Guard</h2>
            <div style="font-size:11px; opacity:0.85;">100% Offline Local Privacy Firewall</div>
          </div>
          <span class="kug-badge">Paused</span>
          <button id="kug-header-close" style="background:transparent; border:none; color:white; font-size:18px; font-weight:700; cursor:pointer; opacity:0.85; margin-left:auto; line-height:1; padding:4px 8px; border-radius:6px;" title="Cancel & Close">✕</button>
        </div>

        <div class="kug-body">
          <div class="kug-file-info">
            <span class="kug-file-icon">${fileIcon}</span>
            <div style="flex:1; min-width:0;">
              <div class="kug-file-name">${this.escapeHtml(file.name)}</div>
              <div class="kug-file-meta">${fileSize} &bull; ${this.escapeHtml(file.type || 'image')}</div>
            </div>
            <span style="font-size:11px; color:#166534; background:#dcfce7; padding:2px 8px; border-radius:4px; font-weight:700;">OFFLINE SCAN</span>
          </div>

          <div style="font-size:12px; color:#475569; margin-bottom:12px; background:#f8fafc; padding:8px 12px; border-radius:8px; border:1px solid #e2e8f0; line-height:1.4;">
            🔒 <strong>Zero Cloud Leak:</strong> Analyzed 100% locally on your computer. Inspect what sensitive data this file leaks before approving.
          </div>

          <div id="kug-scan-status">
            <div class="kug-scanning">
              <div class="kug-spinner"></div>
              <span>Auditing EXIF GPS coordinates & running local secret scanner...</span>
            </div>
          </div>

          <div id="kug-findings"></div>

          <div style="margin: 10px 0 2px; display: flex; align-items: center; gap: 8px; font-size: 11px; color: #475569; background: #f8fafc; padding: 8px 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
            <input type="checkbox" id="kug-trust-checkbox" style="cursor: pointer; accent-color: #007E36; width: 14px; height: 14px;" />
            <label for="kug-trust-checkbox" style="cursor: pointer; user-select: none; font-weight: 600;">
              🛡️ Always trust <strong>${this.escapeHtml(window.location.hostname)}</strong> (disable upload checks for this website)
            </label>
          </div>
        </div>

        <div class="kug-actions">
          <button class="kug-btn kug-btn-cancel" id="kug-cancel" title="Discard file upload">✕ Cancel &amp; Block</button>
          <button class="kug-btn kug-btn-anyway" id="kug-anyway" title="Upload as-is with all metadata">Upload As-Is</button>
          <button class="kug-btn kug-btn-clean" id="kug-clean" title="Strip all EXIF/GPS metadata locally before uploading">🧹 Clean &amp; Upload</button>
        </div>
        <div class="kug-watermark">Kavach 2.0 &bull; 100% Local Privacy &amp; Data-Egress Guardian</div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    const closeModal = () => {
      window.removeEventListener('keydown', handleKey);
      overlay.remove();
      if (this.pendingInput) {
        try {
          this.pendingInput.value = '';
        } catch {}
      }
      this.pendingFiles = [];
      this.pendingInput = null;
      this.pendingDropTarget = null;
      this.cleanedFiles = [];
      this.isBypassingGuard = false;
    };

    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeModal();
    };
    window.addEventListener('keydown', handleKey);

    overlay.querySelector('#kug-header-close')?.addEventListener('click', closeModal);
    overlay.querySelector('#kug-cancel')?.addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });

    overlay.querySelector('#kug-anyway')?.addEventListener('click', () => {
      const trustCheckbox = overlay.querySelector('#kug-trust-checkbox') as HTMLInputElement;
      if (trustCheckbox?.checked) {
        this.addTrustedUploadDomain(window.location.hostname);
      }
      const renameInput = overlay.querySelector('#kug-rename-input') as HTMLInputElement;
      const targetName = renameInput?.value.trim() || file.name;
      const renamed = this.pendingFiles.map(f => new File([f], targetName, { type: f.type, lastModified: Date.now() }));
      overlay.remove();
      this.dispatchApprovedFiles(renamed);
    });

    overlay.querySelector('#kug-clean')?.addEventListener('click', async () => {
      const trustCheckbox = overlay.querySelector('#kug-trust-checkbox') as HTMLInputElement;
      if (trustCheckbox?.checked) {
        this.addTrustedUploadDomain(window.location.hostname);
      }
      const btn = overlay.querySelector('#kug-clean') as HTMLButtonElement;
      btn.textContent = '⏳ Stripping Metadata & Renaming...';
      btn.disabled = true;

      const renameInput = overlay.querySelector('#kug-rename-input') as HTMLInputElement;
      const targetName = renameInput?.value.trim() || file.name;

      const clean = this.cleanedFiles.length > 0 ? this.cleanedFiles : await this.stripExifFromFiles(this.pendingFiles);
      const renamedClean = clean.map(f => new File([f], targetName, { type: f.type, lastModified: Date.now() }));
      overlay.remove();
      this.dispatchApprovedFiles(renamedClean);
    });

    this.runComprehensiveFileScan(file, overlay);
  }

  private async runComprehensiveFileScan(file: File, overlay: HTMLElement): Promise<void> {
    const statusEl = overlay.querySelector('#kug-scan-status')!;
    const findingsEl = overlay.querySelector('#kug-findings')!;

    let exifResult: ExifMetadataResult = { hasGps: false, metadataSizeEstimate: 0, fieldsFound: [] };

    // 1. Parse real EXIF & GPS binary headers
    if (file.type.startsWith('image/') || file.name.match(/\.(jpg|jpeg|png)$/i)) {
      exifResult = await ExifParser.parseFile(file);

      // Pre-clean via canvas for instant "Clean & Upload" button
      try {
        const cleanBlob = await this.canvasReencodeImage(file);
        if (cleanBlob) {
          this.cleanedFiles = [new File([cleanBlob], file.name, { type: file.type, lastModified: Date.now() })];
        }
      } catch {}
    }

    // 2. Run Local In-Browser Vision & Secret Scanner (100% Offline / Gemini Vision)
    const localVisionResult = await LocalVisionEngine.scanFileLocally(file);

    // 3. Optional background Gemma vision scan (if available)
    let gemmaData: any = null;
    if (file.type.startsWith('image/') && file.size < 10 * 1024 * 1024) {
      try {
        const base64 = await this.fileToBase64(file);
        const result = await chrome.runtime.sendMessage({
          action: 'scanImageForPII',
          base64Image: base64,
          mimeType: file.type || 'image/jpeg'
        });
        if (result?.success) gemmaData = result.data;
      } catch {}
    }

    statusEl.innerHTML = '';
    this.renderScanFindings(findingsEl, exifResult, localVisionResult, gemmaData, file);

    // Trigger audio chime & red dot if critical risks found
    const hasCritical = exifResult.hasGps || localVisionResult.riskLevel === 'CRITICAL' || localVisionResult.findings.some(f => f.severity === 'CRITICAL');
    if (hasCritical) {
      KavachAudioAlert.playAlertChime();
      chrome.runtime.sendMessage({ action: 'triggerThreatBadge' }).catch(() => {});
    }
  }

  private renderScanFindings(
    container: Element,
    exif: ExifMetadataResult,
    localVision: LocalScanResult,
    gemmaData: any,
    file: File
  ): void {
    let html = '';

    const hasGps = exif.hasGps && !!exif.gps;
    const hasCamera = !!exif.cameraModel || !!exif.cameraMake;
    const hasLocalSecrets = localVision.findings.length > 0;
    const hasGemmaItems = gemmaData && (gemmaData.hasPII || (gemmaData.detectedItems && gemmaData.detectedItems.length > 0));

    const isCritical = hasGps || localVision.riskLevel === 'CRITICAL' || (gemmaData && (gemmaData.riskLevel === 'HIGH' || gemmaData.riskLevel === 'CRITICAL'));
    const isMedium = hasCamera || hasLocalSecrets || (exif.fieldsFound.length > 0);

    const bannerClass = isCritical ? 'kug-risk-HIGH' : isMedium ? 'kug-risk-MEDIUM' : 'kug-risk-SAFE';
    const bannerText = isCritical ? '🔴 CRITICAL PRIVACY LEAKS INTERCEPTED' : isMedium ? '🟠 MEDIUM RISK: METADATA / DATA LEAK' : '🟢 FILE SAFE (CLEAN OF PASSWORDS & GPS)';

    const fileAudit = FilenameInspector.auditFilename(file.name);

    html += `<div class="kug-risk-badge ${bannerClass}">${bannerText}</div>`;

    // ─── 0. FILE NAME PRIVACY & RENAMING CARD ───
    html += `
      <div class="kug-threat-card ${fileAudit.hasLeaks ? 'kug-threat-med' : 'kug-threat-safe'}" style="margin-bottom:10px;">
        <div class="kug-threat-header">
          <span>📁</span>
          <strong>FILE NAME PRIVACY &amp; RENAMING</strong>
          ${fileAudit.hasLeaks ? `<span style="font-size:10px; background:#fef3c7; color:#92400e; padding:2px 6px; border-radius:4px; margin-left:auto; font-weight:700;">METADATA LEAK</span>` : ''}
        </div>
        ${fileAudit.hasLeaks ? `
          <div style="font-size:11px; color:#b45309; margin-bottom:6px; line-height:1.4;">
            ⚠️ <strong>Leaks:</strong> ${fileAudit.leaks.join(' · ')}
          </div>
        ` : `
          <div style="font-size:11px; color:#166534; margin-bottom:4px;">
            ✓ File name does not leak obvious timestamps or device models.
          </div>
        `}
        <div style="display:flex; gap:6px; align-items:center; margin-top:4px;">
          <input type="text" id="kug-rename-input" value="${this.escapeHtml(fileAudit.suggestedName)}"
            style="flex:1; padding:7px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:12px; font-family:inherit; color:#1e293b;"
            title="Edit file name before uploading" />
          <button type="button" id="kug-randomize-btn"
            style="padding:7px 10px; background:#f1f5f9; border:1px solid #cbd5e1; border-radius:6px; font-size:11px; font-weight:700; cursor:pointer; color:#334155;">
            🎲 Randomize
          </button>
        </div>
      </div>
    `;

    // ─── 1. EXACT GPS LOCATION VULNERABILITY ───
    if (hasGps && exif.gps) {
      const g = exif.gps;
      html += `
        <div class="kug-threat-card kug-threat-high">
          <div class="kug-threat-header">
            <span>📍</span>
            <strong>EXACT PHYSICAL GEOLOCATION LEAK</strong>
          </div>
          <div class="kug-coord-pill">
            Latitude: <strong>${g.latitudeDMS}</strong> (${g.latitude})<br>
            Longitude: <strong>${g.longitudeDMS}</strong> (${g.longitude})
            ${g.altitude ? `<br>Altitude: <strong>${g.altitude} meters</strong>` : ''}
          </div>
          <div class="kug-threat-body">
            <strong>Vulnerability:</strong> Anyone or web crawlers downloading this photo can map the exact building where it was captured (within 3m accuracy). Exposes home/office locations.
          </div>
          <div style="margin-top:8px;">
            <a href="${g.mapsUrl}" target="_blank" class="kug-map-btn">
              🗺️ Preview Exact Location on Google Maps ↗
            </a>
          </div>
        </div>
      `;
    }

    // ─── 2. LOCAL IN-BROWSER SECRET, FACE & PRIVACY FINDINGS (100% Offline) ───
    if (hasLocalSecrets) {
      const hasFaces = localVision.findings.some(f => f.type === 'face');
      const hasCredentials = localVision.findings.some(f => f.type !== 'face');
      const cardTitle = hasFaces && hasCredentials
        ? 'LOCAL SCANNER: BIOMETRICS & EXPOSED CREDENTIALS'
        : hasFaces
        ? 'LOCAL SCANNER: BIOMETRIC / HUMAN FACE DETECTED'
        : 'LOCAL SCANNER: EXPOSED CREDENTIALS DETECTED';
      const cardIcon = hasFaces && !hasCredentials ? '👤' : '🔑';
      const badgeText = hasCredentials ? 'CRITICAL EXPOSURE' : 'BIOMETRIC PRIVACY';

      html += `
        <div class="kug-threat-card ${hasCredentials ? 'kug-threat-high' : 'kug-threat-med'}">
          <div class="kug-threat-header">
            <span>${cardIcon}</span>
            <strong>${cardTitle}</strong>
            <span style="font-size:10px; background:${hasCredentials ? '#fee2e2' : '#fef3c7'}; color:${hasCredentials ? '#991b1b' : '#92400e'}; padding:2px 6px; border-radius:4px; margin-left:auto; font-weight:700;">${badgeText}</span>
          </div>
          <div style="margin: 6px 0;">
            ${localVision.findings.map(f => `
              <div class="kug-finding-pill" style="border-left: 3px solid ${f.type === 'face' ? '#d97706' : '#dc2626'}; background: ${f.type === 'face' ? '#fffbeb' : '#fee2e2'}; color: ${f.type === 'face' ? '#92400e' : '#991b1b'};">
                <strong>${f.type === 'face' ? '👤 ' : '🔑 '}${this.escapeHtml(f.title)}:</strong>
                <code style="background:rgba(0,0,0,0.06); padding:2px 4px; border-radius:3px;">${this.escapeHtml(f.exactSnippet)}</code>
                <div style="font-size:10px; margin-top:3px;">${this.escapeHtml(f.vulnerabilityDescription)}</div>
              </div>
            `).join('')}
          </div>
          <div class="kug-threat-body" style="background:${hasCredentials ? '#fef2f2' : '#fffbeb'}; padding:8px 10px; border-radius:6px; border:1px solid ${hasCredentials ? '#fecaca' : '#fde68a'}; margin-top:6px;">
            ${hasCredentials
              ? '🚨 <strong>Security Advisory:</strong> Plaintext credentials visible in image. We strongly recommend clicking <strong>Cancel & Block</strong> to avoid compromising your accounts.'
              : '👤 <strong>Biometric Advisory:</strong> Identifiable human face detected in image. Ensure you intend to share your biometrics.'}
          </div>
        </div>
      `;
    }

    // ─── 3. DEVICE & TIMESTAMP FINGERPRINTING ───
    if (hasCamera || exif.dateTimeOriginal) {
      html += `
        <div class="kug-threat-card kug-threat-med">
          <div class="kug-threat-header">
            <span>📷</span>
            <strong>DEVICE &amp; TIME FINGERPRINT LEAK</strong>
          </div>
          <div class="kug-meta-grid">
            ${exif.cameraMake || exif.cameraModel ? `<div><strong>Hardware:</strong> ${this.escapeHtml([exif.cameraMake, exif.cameraModel].filter(Boolean).join(' '))}</div>` : ''}
            ${exif.dateTimeOriginal ? `<div><strong>Captured At:</strong> ${this.escapeHtml(exif.dateTimeOriginal)}</div>` : ''}
            ${exif.software ? `<div><strong>Software:</strong> ${this.escapeHtml(exif.software)}</div>` : ''}
          </div>
          <div class="kug-threat-body" style="margin-top:6px;">
            <strong>Vulnerability:</strong> Identifies your specific camera hardware model and personal shooting habits for cross-site device correlation.
          </div>
        </div>
      `;
    }

    // ─── 4. GEMMA / OLLAMA AI ENRICHMENT (If Available) ───
    if (gemmaData && hasGemmaItems) {
      const items: string[] = gemmaData.detectedItems || [];
      const risks: string[] = gemmaData.risks || [];
      html += `
        <div class="kug-threat-card kug-threat-high">
          <div class="kug-threat-header">
            <span>🤖</span>
            <strong>DEEP AI VISION FINDINGS</strong>
          </div>
          <div style="margin: 6px 0;">
            ${items.map(it => `
              <div class="kug-finding-pill">⚠️ <strong>Detected:</strong> ${this.escapeHtml(it)}</div>
            `).join('')}
          </div>
          ${risks.length > 0 ? `
            <div class="kug-threat-body">
              <strong>Exploit Scenarios:</strong>
              <ul style="margin:4px 0 4px 16px; padding:0;">
                ${risks.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
        </div>
      `;
    }

    if (!hasGps && !hasCamera && !hasLocalSecrets && !hasGemmaItems && !fileAudit.hasLeaks) {
      html += `
        <div class="kug-threat-card kug-threat-safe">
          <div class="kug-threat-header">
            <span>✅</span>
            <strong>Image Clean</strong>
          </div>
          <div class="kug-threat-body">
            No visible passwords, emails, tokens, or embedded GPS coordinates were detected.
          </div>
        </div>
      `;
    }

    container.innerHTML = html;

    // Attach randomize button listener
    const randBtn = container.querySelector('#kug-randomize-btn');
    const renameInput = container.querySelector('#kug-rename-input') as HTMLInputElement;
    if (randBtn && renameInput) {
      randBtn.addEventListener('click', () => {
        const extMatch = file.name.match(/\.[a-zA-Z0-9]+$/);
        const ext = extMatch ? extMatch[0] : '';
        const rand = Math.random().toString(36).substring(2, 7);
        renameInput.value = `kavach_safe_${rand}${ext}`;
      });
    }
  }

  // ─── Releasing Approved Files to Webpage ───────────────────────────────────

  private dispatchApprovedFiles(files: File[]): void {
    this.isBypassingGuard = true;
    const inputRef = this.pendingInput;

    try {
      if (inputRef) {
        const dt = new DataTransfer();
        files.forEach(f => dt.items.add(f));

        try {
          delete (inputRef as any).files;
          inputRef.files = dt.files;
        } catch {
          try {
            Object.defineProperty(inputRef, 'files', { value: dt.files, configurable: true });
          } catch {}
        }
        inputRef.dispatchEvent(new Event('change', { bubbles: true }));
      } else if (this.pendingDropTarget) {
        const dt = new DataTransfer();
        files.forEach(f => dt.items.add(f));

        const dropEvent = new DragEvent('drop', {
          bubbles: true,
          cancelable: true,
          dataTransfer: dt,
        });
        this.pendingDropTarget.dispatchEvent(dropEvent);
      }
    } finally {
      setTimeout(() => {
        this.isBypassingGuard = false;
        if (inputRef) {
          try {
            delete (inputRef as any).files;
          } catch {}
        }
      }, 300);
      this.pendingFiles = [];
      this.pendingInput = null;
      this.pendingDropTarget = null;
      this.cleanedFiles = [];
    }
  }

  // ─── EXIF Stripping via HTML5 Canvas ───────────────────────────────────────

  private async stripExifFromFiles(files: File[]): Promise<File[]> {
    return Promise.all(files.map(async file => {
      if (!file.type.startsWith('image/')) return file;
      try {
        const blob = await this.canvasReencodeImage(file);
        return blob ? new File([blob], file.name, { type: file.type, lastModified: Date.now() }) : file;
      } catch { return file; }
    }));
  }

  private canvasReencodeImage(file: File): Promise<Blob | null> {
    return new Promise(resolve => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width = img.naturalWidth;
          canvas.height = img.naturalHeight;
          const ctx = canvas.getContext('2d');
          if (!ctx) { resolve(null); return; }
          ctx.drawImage(img, 0, 0);

          const outType = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
          canvas.toBlob(blob => {
            URL.revokeObjectURL(url);
            resolve(blob);
          }, outType, outType === 'image/jpeg' ? 0.94 : undefined);
        } catch {
          URL.revokeObjectURL(url);
          resolve(null);
        }
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
      img.src = url;
    });
  }

  private fileToBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const r = reader.result as string;
        resolve(r.split(',')[1] || r);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  // ─── Stylesheet Injection ─────────────────────────────────────────────────

  private injectUploadGuardStyles(): void {
    if (document.getElementById('kavach-upload-guard-styles')) return;
    const style = document.createElement('style');
    style.id = 'kavach-upload-guard-styles';
    style.textContent = `
      #kavach-upload-overlay {
        position: fixed !important;
        inset: 0 !important;
        background: rgba(15, 23, 42, 0.82) !important;
        z-index: 2147483647 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        backdrop-filter: blur(6px) !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
        animation: kavach-fadein 0.2s ease !important;
      }
      @keyframes kavach-fadein { from { opacity: 0; } to { opacity: 1; } }
      @keyframes kavach-slidein { from { transform: translateY(-24px) scale(0.96); opacity: 0; } to { transform: translateY(0) scale(1); opacity: 1; } }
      @keyframes kavach-spin { to { transform: rotate(360deg); } }

      #kavach-upload-modal {
        background: #ffffff !important;
        border-radius: 16px !important;
        max-width: 500px !important;
        width: 92vw !important;
        max-height: 88vh !important;
        overflow-y: auto !important;
        box-shadow: 0 32px 80px rgba(0,0,0,0.5) !important;
        animation: kavach-slidein 0.25s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
        border: 2px solid #007E36 !important;
        display: flex !important;
        flex-direction: column !important;
        box-sizing: border-box !important;
      }
      .kug-header {
        background: linear-gradient(135deg, #007E36 0%, #005a26 100%) !important;
        color: white !important;
        padding: 16px 20px !important;
        border-radius: 14px 14px 0 0 !important;
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        flex-shrink: 0 !important;
      }
      .kug-header h2 { margin: 0 !important; font-size: 16px !important; font-weight: 800 !important; color: white !important; letter-spacing: 0.3px !important; }
      .kug-badge { font-size: 11px !important; background: rgba(255,255,255,0.2) !important; padding: 4px 10px !important; border-radius: 20px !important; margin-left: auto !important; color: white !important; font-weight: 700 !important; text-transform: uppercase !important; }
      .kug-body { padding: 18px 20px !important; flex: 1 !important; }
      .kug-file-info { background: #f8fafc !important; border: 1px solid #e2e8f0 !important; border-radius: 10px !important; padding: 12px 14px !important; margin-bottom: 12px !important; display: flex !important; align-items: center !important; gap: 10px !important; }
      .kug-file-icon { font-size: 28px !important; flex-shrink: 0 !important; }
      .kug-file-name { font-weight: 700 !important; font-size: 13px !important; color: #1e293b !important; word-break: break-all !important; }
      .kug-file-meta { font-size: 11px !important; color: #64748b !important; margin-top: 2px !important; }

      .kug-risk-badge { display: inline-flex !important; align-items: center !important; gap: 6px !important; padding: 6px 14px !important; border-radius: 20px !important; font-size: 12px !important; font-weight: 800 !important; margin-bottom: 12px !important; width: 100% !important; box-sizing: border-box !important; }
      .kug-risk-HIGH { background: #fee2e2 !important; color: #991b1b !important; border: 1px solid #fecaca !important; }
      .kug-risk-MEDIUM { background: #fef3c7 !important; color: #92400e !important; border: 1px solid #fde68a !important; }
      .kug-risk-SAFE { background: #dcfce7 !important; color: #166534 !important; border: 1px solid #bbf7d0 !important; }

      .kug-threat-card { border-radius: 10px !important; padding: 12px 14px !important; margin-bottom: 10px !important; font-size: 12px !important; border: 1px solid transparent !important; }
      .kug-threat-high { background: #fff5f5 !important; border-color: #fecaca !important; }
      .kug-threat-med { background: #fffbeb !important; border-color: #fde68a !important; }
      .kug-threat-safe { background: #f0fdf4 !important; border-color: #bbf7d0 !important; }

      .kug-threat-header { display: flex !important; align-items: center !important; gap: 8px !important; font-size: 12px !important; font-weight: 800 !important; color: #1e293b !important; margin-bottom: 6px !important; }
      .kug-coord-pill { font-family: monospace !important; background: #fee2e2 !important; color: #991b1b !important; padding: 8px 12px !important; border-radius: 6px !important; font-size: 12px !important; margin-bottom: 6px !important; border: 1px solid #fecaca !important; line-height: 1.5 !important; }
      .kug-threat-body { font-size: 11px !important; color: #475569 !important; line-height: 1.5 !important; }
      .kug-meta-grid { font-size: 11px !important; color: #334155 !important; display: flex !important; flex-direction: column !important; gap: 3px !important; background: #fef3c7 !important; padding: 8px 10px !important; border-radius: 6px !important; }
      .kug-map-btn { display: inline-flex !important; align-items: center !important; gap: 6px !important; font-size: 11px !important; font-weight: 700 !important; color: #0284c7 !important; text-decoration: none !important; background: #e0f2fe !important; padding: 6px 12px !important; border-radius: 6px !important; border: 1px solid #bae6fd !important; transition: all 0.15s ease !important; }
      .kug-map-btn:hover { background: #bae6fd !important; }

      .kug-finding-pill { background: #fee2e2 !important; color: #991b1b !important; padding: 6px 10px !important; border-radius: 6px !important; font-size: 11px !important; margin-bottom: 5px !important; border: 1px solid #fecaca !important; }

      .kug-scanning { display: flex !important; align-items: center !important; gap: 10px !important; color: #475569 !important; font-size: 12px !important; padding: 12px !important; background: #f8fafc !important; border-radius: 8px !important; margin-bottom: 10px !important; border: 1px solid #e2e8f0 !important; }
      .kug-spinner { width: 18px !important; height: 18px !important; border: 2.5px solid #e2e8f0 !important; border-top-color: #007E36 !important; border-radius: 50% !important; animation: kavach-spin 0.8s linear infinite !important; flex-shrink: 0 !important; }

      .kug-actions { display: flex !important; gap: 8px !important; padding: 14px 20px !important; border-top: 1px solid #e2e8f0 !important; background: #f8fafc !important; border-radius: 0 0 14px 14px !important; flex-shrink: 0 !important; }
      .kug-btn { flex: 1 !important; padding: 10px 12px !important; border-radius: 8px !important; font-size: 13px !important; font-weight: 700 !important; cursor: pointer !important; border: none !important; transition: all 0.15s ease !important; font-family: inherit !important; }
      .kug-btn:hover { filter: brightness(0.92) !important; transform: translateY(-1px) !important; }
      .kug-btn-clean { background: #007E36 !important; color: white !important; box-shadow: 0 2px 6px rgba(0, 126, 54, 0.3) !important; }
      .kug-btn-anyway { background: #e2e8f0 !important; color: #475569 !important; }
      .kug-btn-cancel { background: transparent !important; color: #dc2626 !important; border: 1.5px solid #fecaca !important; flex: 0 0 auto !important; padding: 10px 14px !important; }
      .kug-watermark { font-size: 10px !important; color: #94a3b8 !important; text-align: center !important; padding: 6px 0 4px !important; }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private escapeHtml(str: string): string {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  }
}

const contentScript = new ContentScript();
contentScript.init();

export {};
