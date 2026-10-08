/**
 * Kavach AI Engine Service
 * Supports Google Gemini Flash API + Local Ollama (Gemma/Moondream) + Offline Heuristic Fallback
 */

export interface AITrackerAnalysis {
  name: string;
  company: string;
  isFirstParty: boolean;
  category: 'first-party' | 'advertising' | 'analytics' | 'session_replay' | 'fingerprinting' | 'unknown';
  purpose: string;
}

export interface AIImageScanResult {
  hasSensitiveData: boolean;
  findings: Array<{
    type: 'password' | 'email' | 'api_key' | 'gov_id' | 'network_ip' | 'token';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    title: string;
    exactSnippet: string;
    vulnerabilityDescription: string;
  }>;
  recommendation: string;
}

export class KavachAIService {
  private static cachedTrackerAnalyses: Map<string, AITrackerAnalysis> = new Map();

  /**
   * Retrieves user's Gemini API key from chrome.storage.local
   */
  static async getApiKey(): Promise<string | null> {
    try {
      const data = await chrome.storage.local.get(['geminiApiKey']);
      return data.geminiApiKey || null;
    } catch {
      return null;
    }
  }

  /**
   * Saves Gemini API key
   */
  static async saveApiKey(key: string): Promise<boolean> {
    try {
      await chrome.storage.local.set({ geminiApiKey: key.trim() });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Tests a Gemini API key
   */
  static async testApiKey(apiKey: string): Promise<{ valid: boolean; message: string }> {
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey.trim()}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: 'Respond with the word OK if you can read this.' }] }],
          }),
        }
      );

      const data = await response.json();
      if (!response.ok) {
        const errorMsg = data?.error?.message || `HTTP ${response.status}`;
        return { valid: false, message: `Key invalid: ${errorMsg}` };
      }

      return { valid: true, message: 'Gemini 1.5 Flash connected successfully!' };
    } catch (err: any) {
      return { valid: false, message: `Connection error: ${err.message || 'Network failure'}` };
    }
  }

  /**
   * Analyzes a tracker domain using Gemini AI (with fallback to semantic decomposition)
   */
  static async analyzeTracker(trackerDomain: string, sourceDomain: string): Promise<AITrackerAnalysis> {
    const cacheKey = `${sourceDomain}->${trackerDomain}`;
    if (this.cachedTrackerAnalyses.has(cacheKey)) {
      return this.cachedTrackerAnalyses.get(cacheKey)!;
    }

    const apiKey = await this.getApiKey();

    if (apiKey) {
      try {
        const prompt = `You are a web security and privacy analyzer.
Analyze the target domain: "${trackerDomain}" when visited from the website: "${sourceDomain}".
Determine:
1. The company or organization owning "${trackerDomain}".
2. Whether "${trackerDomain}" belongs to the same organization/site as "${sourceDomain}" (1st-party) or is an outside surveillance/ad company (3rd-party).
3. The tracking category: "first-party", "advertising", "analytics", "session_replay", or "fingerprinting".
4. A concise 1-sentence explanation of what data it tracks or delivers.

Respond STRICTLY in valid JSON format:
{
  "name": "Human-friendly name",
  "company": "Owning organization",
  "isFirstParty": boolean,
  "category": "first-party" | "advertising" | "analytics" | "session_replay" | "fingerprinting",
  "purpose": "1-sentence description"
}`;

        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { responseMimeType: 'application/json' },
            }),
          }
        );

        if (response.ok) {
          const json = await response.json();
          const text = json?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            const parsed = JSON.parse(text) as AITrackerAnalysis;
            this.cachedTrackerAnalyses.set(cacheKey, parsed);
            return parsed;
          }
        }
      } catch (e) {
        console.warn('Gemini tracker analysis failed, falling back to semantic matcher:', e);
      }
    }

    // Semantic Fallback (Ultra-accurate domain & token analyzer)
    const fallback = this.semanticDomainAnalysis(trackerDomain, sourceDomain);
    this.cachedTrackerAnalyses.set(cacheKey, fallback);
    return fallback;
  }

  /**
   * Scans an image File/Base64 for visible passwords, emails, and credentials using Gemini Flash Vision
   */
  static async scanImageWithAI(base64Image: string, mimeType: string): Promise<AIImageScanResult | null> {
    const apiKey = await this.getApiKey();
    if (!apiKey) return null;

    try {
      const prompt = `You are an expert security and privacy vision auditor.
Look at this uploaded image / screenshot very carefully.
Check if there are any:
1. Plaintext passwords, Wi-Fi keys (WPA2, PSK), PINs, or secret tokens.
2. Personal email addresses.
3. Secret cloud API keys (OpenAI, AWS, Google Cloud, GitHub tokens, Stripe).
4. Government ID numbers (Aadhaar, PAN, SSN, Passport).
5. Private internal IP addresses or server hostnames.

Respond STRICTLY in valid JSON matching this schema:
{
  "hasSensitiveData": boolean,
  "findings": [
    {
      "type": "password" | "email" | "api_key" | "gov_id" | "network_ip" | "token",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM",
      "title": "Short title like 'Visible Plaintext Password'",
      "exactSnippet": "Exact text or key visible in image",
      "vulnerabilityDescription": "Why exposing this is dangerous"
    }
  ],
  "recommendation": "Advice on whether to cancel or redact"
}`;

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [
              {
                parts: [
                  { text: prompt },
                  {
                    inlineData: {
                      mimeType: mimeType || 'image/jpeg',
                      data: base64Image,
                    },
                  },
                ],
              },
            ],
            generationConfig: { responseMimeType: 'application/json' },
          }),
        }
      );

      if (!response.ok) return null;
      const json = await response.json();
      const text = json?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!text) return null;

      return JSON.parse(text) as AIImageScanResult;
    } catch (err) {
      console.error('Gemini vision scan error:', err);
      return null;
    }
  }

  /**
   * Semantic domain analysis (Extracts brand roots, acronyms, and common tracker prefixes)
   */
  static semanticDomainAnalysis(trackerDomain: string, sourceDomain: string): AITrackerAnalysis {
    const cleanTracker = trackerDomain.toLowerCase().replace(/^www\./, '');
    const cleanSource = sourceDomain.toLowerCase().replace(/^www\./, '');

    // Extract root brand tokens
    // e.g. "youtube.com" -> "youtube", "theguardian.com" -> "guardian"
    const getRoot = (d: string) => {
      const parts = d.split('.');
      if (parts.length >= 2) {
        return parts[parts.length - 2].replace(/^(the|my)/, '');
      }
      return d;
    };

    const sourceRoot = getRoot(cleanSource);

    // Exact or direct subdomain match
    if (cleanTracker === cleanSource || cleanTracker.endsWith(`.${cleanSource}`) || cleanTracker.includes(sourceRoot)) {
      return {
        name: `${cleanSource} In-House Infrastructure`,
        company: cleanSource,
        isFirstParty: true,
        category: 'first-party',
        purpose: 'Internal site content delivery, API routing, and recommendation data (retained in-house).',
      };
    }

    // Brand acronyms and common CDN associations
    const BRAND_SIBLINGS: Record<string, { roots: string[]; company: string; purpose: string }> = {
      google: {
        roots: ['google', 'youtube', 'googlevideo', 'ytimg', 'gstatic', 'googleapis', 'googleusercontent', 'ggpht', 'doubleclick'],
        company: 'Google / Alphabet',
        purpose: 'Google internal video CDN & recommendation algorithms (data kept within Google account ecosystem).',
      },
      meta: {
        roots: ['facebook', 'instagram', 'fbcdn', 'whatsapp', 'messenger', 'meta', 'connect.facebook'],
        company: 'Meta Platforms',
        purpose: 'Meta media CDN & feed personalization algorithms.',
      },
      amazon: {
        roots: ['amazon', 'media-amazon', 'ssl-images-amazon', 'a2z', 'cloudfront', 'amazon-adsystem'],
        company: 'Amazon',
        purpose: 'Amazon product media CDN & e-commerce telemetry.',
      },
      guardian: {
        roots: ['guardian', 'guim', 'theguardian'],
        company: 'Guardian Media Group',
        purpose: 'The Guardian in-house journalism CDN & page assets.',
      },
      reddit: {
        roots: ['reddit', 'redd', 'redditmedia', 'redditstatic'],
        company: 'Reddit',
        purpose: 'Reddit native media delivery & feed updates.',
      },
      netflix: {
        roots: ['netflix', 'nflxext', 'nflximg', 'nflxvideo'],
        company: 'Netflix',
        purpose: 'Netflix encrypted video streaming CDN.',
      },
      spotify: {
        roots: ['spotify', 'scdn', 'spotifycdn'],
        company: 'Spotify',
        purpose: 'Spotify audio stream delivery.',
      },
      twitter: {
        roots: ['twitter', 'twimg', 't.co', 'x.com'],
        company: 'X / Twitter',
        purpose: 'X / Twitter media infrastructure.',
      },
      microsoft: {
        roots: ['microsoft', 'live', 'office', 'bing', 'azure', 'github', 'linkedin', 'msn', 'windows'],
        company: 'Microsoft Corporation',
        purpose: 'Microsoft cloud infrastructure & account services.',
      },
    };

    for (const [_key, info] of Object.entries(BRAND_SIBLINGS)) {
      const sourceMatches = info.roots.some(r => cleanSource.includes(r));
      const trackerMatches = info.roots.some(r => cleanTracker.includes(r));
      if (sourceMatches && trackerMatches) {
        return {
          name: `${info.company} Native Service`,
          company: info.company,
          isFirstParty: true,
          category: 'first-party',
          purpose: info.purpose,
        };
      }
    }

    // Common Third-Party Ad & Surveillance Networks
    if (/criteo|taboola|outbrain|adnxs|pubmatic|rubicon|moatads|openx|adroll|bidswitch/.test(cleanTracker)) {
      return {
        name: cleanTracker,
        company: cleanTracker.split('.')[0].toUpperCase(),
        isFirstParty: false,
        category: 'advertising',
        purpose: 'Behavioral retargeting & cross-site ad broker. Builds browsing profiles across independent websites.',
      };
    }

    if (/hotjar|clarity|fullstory|mouseflow|smartlook|crazyegg/.test(cleanTracker)) {
      return {
        name: cleanTracker,
        company: cleanTracker.split('.')[0].toUpperCase(),
        isFirstParty: false,
        category: 'session_replay',
        purpose: 'Session replay surveillance: Logs mouse movements, clicks, scroll heatmaps, and typed inputs.',
      };
    }

    if (/google-analytics|googletagmanager|segment|mixpanel|amplitude|heap/.test(cleanTracker)) {
      return {
        name: cleanTracker,
        company: 'Third-Party Analytics',
        isFirstParty: false,
        category: 'analytics',
        purpose: 'Telemetry & user flow tracking across pages.',
      };
    }

    // Default third-party
    return {
      name: cleanTracker,
      company: cleanTracker,
      isFirstParty: false,
      category: 'unknown',
      purpose: 'External third-party domain request.',
    };
  }
}
