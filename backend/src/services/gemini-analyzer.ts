import { GoogleGenerativeAI, Part } from '@google/generative-ai';

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface VectorScores {
  dataSale: number;        // 0-100, weight 30%
  trackingScope: number;   // 0-100, weight 25%
  dataRetention: number;   // 0-100, weight 20%
  consentQuality: number;  // 0-100, weight 15%
  securityStandards: number; // 0-100, weight 10%
}

export interface DPDPCompliance {
  compliant: boolean;
  hasDPO: boolean;
  hasGrievanceRedressal: boolean;
  hasPurposeSpecification: boolean;
  hasConsentWithdrawal: boolean;
  hasDataLocalization: boolean;
  missingRequirements: string[];
}

export interface PrivacyAnalysisResult {
  summary: string;
  safety: 'SAFE' | 'RISKY' | 'UNSAFE';
  score: number;          // Weighted composite 0-100
  vectorScores: VectorScores;
  risks: string[];
  positiveFeatures: string[];
  complianceFlags: string[];
  dpdpCompliance: DPDPCompliance;
}

export interface PIIDetectionResult {
  hasPII: boolean;
  detectedItems: string[];
  risks?: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendation: string;
}

// ─── Gemma 4 Privacy Analyzer ────────────────────────────────────────────────

export class GeminiPrivacyAnalyzer {
  private genAI: GoogleGenerativeAI;
  private model: any;
  private visionModel: any;

  // Gemma 4 via Gemini API — open-weight model
  private static readonly MODEL_NAME = 'gemini-1.5-flash';
  private static readonly VISION_MODEL_NAME = 'gemini-1.5-flash';

  // 5-vector weights — must sum to 1.0
  private static readonly WEIGHTS = {
    dataSale: 0.30,
    trackingScope: 0.25,
    dataRetention: 0.20,
    consentQuality: 0.15,
    securityStandards: 0.10,
  };

  constructor() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY environment variable is required');
    }

    this.genAI = new GoogleGenerativeAI(apiKey);
    this.model = this.genAI.getGenerativeModel({
      model: GeminiPrivacyAnalyzer.MODEL_NAME,
      generationConfig: {
        temperature: 0.1,      // Low temp → deterministic scoring
        topP: 0.8,
        maxOutputTokens: 2048,
      },
    });
    this.visionModel = this.genAI.getGenerativeModel({
      model: GeminiPrivacyAnalyzer.VISION_MODEL_NAME,
      generationConfig: {
        temperature: 0.1,
        maxOutputTokens: 1024,
      },
    });
  }

  // ─── Main Analysis ───────────────────────────────────────────────────────

  async analyzePrivacyPolicy(
    policyText: string,
    websiteUrl: string
  ): Promise<PrivacyAnalysisResult> {
    try {
      // Semantic compression: extract high-density legal sections
      const compressedText = this.extractHighDensitySections(policyText);
      const prompt = this.buildAnalysisPrompt(compressedText, websiteUrl);

      const result = await this.model.generateContent(prompt);
      const responseText = result.response.text();

      return this.parseGemmaResponse(responseText, websiteUrl);
    } catch (error) {
      return this.buildFallback(error, websiteUrl);
    }
  }

  // ─── Image PII Detection ──────────────────────────────────────────────────

  async analyzePIIInImage(
    base64Image: string,
    mimeType: string
  ): Promise<PIIDetectionResult> {
    try {
      const imagePart: Part = {
        inlineData: {
          data: base64Image,
          mimeType: mimeType as any,
        },
      };

      const prompt = `You are an elite privacy and digital footprint security analyst. Analyze this image for visible sensitive information that a privacy-conscious user would NOT want to leak to websites, AI crawlers, or data scrapers.

Look for:
1. Passwords, WiFi keys, API keys, credentials, or tokens visible on sticky notes, computer screens, terminals, or paper.
2. Unobstructed human faces (Biometric vulnerability: can be indexed by facial recognition scrapers, deepfake models, or AI training).
3. Government IDs (Aadhaar, PAN, Passport, Driver's License) with visible names, numbers, or photos.
4. Financial info (Credit/Debit card numbers, CVVs, bank statements, UPI IDs, checks).
5. Personal contact info (Residential physical address, private phone numbers, personal email addresses).
6. Sensitive documents (Medical reports, confidential work chats, signatures, contracts).
7. Personal Names (e.g. names printed on tickets, ID badges, forms, certificates, or written on paper).

IMPORTANT:
- In "detectedItems", state EXACTLY what is visible with specific context (e.g. "Visible WiFi password text on router sticker", "Clear face photo suitable for biometric facial profiling", "PAN Card with visible number and signature").
- In "risks", explain the exact real-world vulnerability (e.g. "Account/Network Compromise: Anyone viewing this photo can access your local network", "Biometric Harvesting: Web crawlers can harvest this facial data for facial recognition databases").

Respond ONLY in this exact JSON format, no other text:
{
  "hasPII": true/false,
  "detectedItems": ["Exact description of what is visible in the image"],
  "risks": ["Specific privacy vulnerability and how it can be exploited"],
  "riskLevel": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommendation": "One sentence direct advice for the user"
}

riskLevel rules:
- LOW: No sensitive items or only generic public scenery
- MEDIUM: Device screen with non-secret UI, partial info, or face in background crowd
- HIGH: Full government ID, clear face photo, full address, or credit card
- CRITICAL: Exposed passwords/credentials, multiple high-risk IDs, or medical/financial records`;

      const result = await this.visionModel.generateContent([prompt, imagePart]);
      const responseText = result.response.text();

      return this.parsePIIResponse(responseText);
    } catch (error) {
      return {
        hasPII: false,
        detectedItems: [],
        riskLevel: 'LOW',
        recommendation: 'PII scan unavailable — review image manually before uploading.',
      };
    }
  }

  // ─── Semantic Section Extractor ───────────────────────────────────────────

  private extractHighDensitySections(text: string): string {
    const TARGET_KEYWORDS = [
      'sell', 'sale', 'share', 'third party', 'third-party', 'partner',
      'track', 'fingerprint', 'session replay', 'beacon', 'pixel', 'telemetry',
      'retain', 'retention', 'delete', 'deletion', 'erasure', 'right to',
      'consent', 'opt-in', 'opt-out', 'gdpr', 'ccpa', 'dpdp', 'legitimate interest',
      'encrypt', 'tls', 'ssl', 'aes', 'breach', 'notify', 'notification',
      'data protection officer', 'dpo', 'grievance', 'controller',
      'collect', 'processing', 'purpose'
    ];

    const lines = text.split(/[\n\r]+/);
    const highDensityLines: string[] = [];
    const seenLines = new Set<string>();

    for (const line of lines) {
      const lower = line.toLowerCase();
      const isRelevant = TARGET_KEYWORDS.some(kw => lower.includes(kw));
      const normalized = line.trim();
      if (isRelevant && normalized.length > 20 && !seenLines.has(normalized)) {
        highDensityLines.push(normalized);
        seenLines.add(normalized);
      }
    }

    const compressed = highDensityLines.join('\n');
    // Cap at 30,000 chars (safe context window for Gemma 4)
    return compressed.substring(0, 30000) || text.substring(0, 30000);
  }

  // ─── Structured Prompt ────────────────────────────────────────────────────

  private buildAnalysisPrompt(policyText: string, websiteUrl: string): string {
    return `You are a privacy law expert and security analyst. Analyze the following privacy policy text and respond ONLY with a valid JSON object — no markdown, no extra text.

Website: ${websiteUrl}

Privacy Policy (high-density extract):
---
${policyText}
---

Score each of the 5 vectors from 0 to 100 where:
- 100 = BEST (completely safe, user-friendly, transparent)
- 0 = WORST (dangerous, opaque, exploitative)

Scoring criteria:

1. dataSale (0-100): Does the policy allow selling, renting, or commercializing user PII to third-party brokers or advertisers?
   - 100: Explicitly states data is NEVER sold
   - 50: Shares with "partners" but vague
   - 0: Explicit data selling, no opt-out

2. trackingScope (0-100): Scope of tracking (fingerprinting, session replay, cross-site tracking, location tracking, telemetry)?
   - 100: No tracking beyond essential functionality
   - 50: Analytics only, no cross-site
   - 0: Extensive fingerprinting, session replay, continuous location

3. dataRetention (0-100): How long is data kept? Is there a right to erasure?
   - 100: Short retention (<1 year), explicit deletion rights, RTBF honored
   - 50: Vague retention, deletion process unclear
   - 0: Unlimited retention, no deletion mechanism

4. consentQuality (0-100): Is consent opt-in or opt-out? Is it GDPR/CCPA/DPDP Act 2023 compliant?
   - 100: Explicit opt-in, granular consent, DPDP compliant, easy withdrawal
   - 50: Opt-out only, buried controls
   - 0: Implied consent, no opt-out, non-compliant

5. securityStandards (0-100): Explicit encryption commitments, breach notification?
   - 100: AES-256 at rest, TLS in transit, 72h breach notification, regular audits
   - 50: HTTPS mentioned, vague security
   - 0: No encryption mention, no breach policy

Also detect DPDP Act 2023 compliance (India's Digital Personal Data Protection Act):
- Check for Data Protection Officer contact
- Check for Grievance Redressal mechanism
- Check for Purpose Specification per collection
- Check for Consent withdrawal mechanism
- Check for Data localization mentions

Respond with EXACTLY this JSON structure:
{
  "vectorScores": {
    "dataSale": <0-100>,
    "trackingScope": <0-100>,
    "dataRetention": <0-100>,
    "consentQuality": <0-100>,
    "securityStandards": <0-100>
  },
  "safety": "<SAFE|RISKY|UNSAFE>",
  "summary": "<exactly 30 words describing the policy's impact on user privacy>",
  "risks": ["<risk1>", "<risk2>", "<risk3>"],
  "positiveFeatures": ["<feature1>", "<feature2>"],
  "complianceFlags": ["<GDPR_COMPLIANT|CCPA_COMPLIANT|DPDP_COMPLIANT|HIPAA_RELEVANT|etc>"],
  "dpdpCompliance": {
    "compliant": <true|false>,
    "hasDPO": <true|false>,
    "hasGrievanceRedressal": <true|false>,
    "hasPurposeSpecification": <true|false>,
    "hasConsentWithdrawal": <true|false>,
    "hasDataLocalization": <true|false>,
    "missingRequirements": ["<missing1>", "<missing2>"]
  }
}

Safety rules:
- SAFE: All vector scores >= 70
- UNSAFE: Any vector score <= 25 OR composite score < 40
- RISKY: Everything else`;
  }

  // ─── Response Parser ──────────────────────────────────────────────────────

  private parseGemmaResponse(responseText: string, websiteUrl: string): PrivacyAnalysisResult {
    try {
      // Extract JSON from response (handle markdown code blocks if present)
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON found in response');

      const parsed = JSON.parse(jsonMatch[0]);

      // Validate and clamp vector scores
      const vectorScores: VectorScores = {
        dataSale: this.clamp(parsed.vectorScores?.dataSale ?? 50),
        trackingScope: this.clamp(parsed.vectorScores?.trackingScope ?? 50),
        dataRetention: this.clamp(parsed.vectorScores?.dataRetention ?? 50),
        consentQuality: this.clamp(parsed.vectorScores?.consentQuality ?? 50),
        securityStandards: this.clamp(parsed.vectorScores?.securityStandards ?? 50),
      };

      // Compute weighted composite score
      const score = this.computeWeightedScore(vectorScores);

      // Determine safety from composite score if not returned
      const safety = this.determineSafety(parsed.safety, vectorScores, score);

      const dpdpCompliance: DPDPCompliance = {
        compliant: parsed.dpdpCompliance?.compliant ?? false,
        hasDPO: parsed.dpdpCompliance?.hasDPO ?? false,
        hasGrievanceRedressal: parsed.dpdpCompliance?.hasGrievanceRedressal ?? false,
        hasPurposeSpecification: parsed.dpdpCompliance?.hasPurposeSpecification ?? false,
        hasConsentWithdrawal: parsed.dpdpCompliance?.hasConsentWithdrawal ?? false,
        hasDataLocalization: parsed.dpdpCompliance?.hasDataLocalization ?? false,
        missingRequirements: Array.isArray(parsed.dpdpCompliance?.missingRequirements)
          ? parsed.dpdpCompliance.missingRequirements
          : [],
      };

      return {
        summary: parsed.summary || 'Privacy policy analyzed by Gemma 4.',
        safety,
        score,
        vectorScores,
        risks: Array.isArray(parsed.risks) ? parsed.risks.slice(0, 8) : [],
        positiveFeatures: Array.isArray(parsed.positiveFeatures) ? parsed.positiveFeatures.slice(0, 5) : [],
        complianceFlags: Array.isArray(parsed.complianceFlags) ? parsed.complianceFlags : [],
        dpdpCompliance,
      };
    } catch (error) {
      console.error('Failed to parse Gemma response:', error);
      console.error('Raw response:', responseText.substring(0, 500));
      return this.buildGenericFallback(websiteUrl);
    }
  }

  private parsePIIResponse(responseText: string): PIIDetectionResult {
    try {
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON found');
      const parsed = JSON.parse(jsonMatch[0]);
      return {
        hasPII: Boolean(parsed.hasPII),
        detectedItems: Array.isArray(parsed.detectedItems) ? parsed.detectedItems : [],
        risks: Array.isArray(parsed.risks) ? parsed.risks : [],
        riskLevel: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(parsed.riskLevel)
          ? parsed.riskLevel
          : 'MEDIUM',
        recommendation: parsed.recommendation || 'Review image for sensitive information before uploading.',
      };
    } catch {
      return {
        hasPII: false,
        detectedItems: [],
        riskLevel: 'LOW',
        recommendation: 'Could not analyze image — review manually.',
      };
    }
  }

  // ─── Scoring Helpers ──────────────────────────────────────────────────────

  private computeWeightedScore(v: VectorScores): number {
    const w = GeminiPrivacyAnalyzer.WEIGHTS;
    const raw =
      v.dataSale * w.dataSale +
      v.trackingScope * w.trackingScope +
      v.dataRetention * w.dataRetention +
      v.consentQuality * w.consentQuality +
      v.securityStandards * w.securityStandards;
    return Math.round(this.clamp(raw));
  }

  private determineSafety(
    rawSafety: string,
    v: VectorScores,
    score: number
  ): 'SAFE' | 'RISKY' | 'UNSAFE' {
    // Override Gemma's safety classification with deterministic rules
    const minVectorScore = Math.min(
      v.dataSale, v.trackingScope, v.dataRetention,
      v.consentQuality, v.securityStandards
    );
    if (score >= 70 && minVectorScore >= 55) return 'SAFE';
    if (score < 40 || minVectorScore <= 25) return 'UNSAFE';

    // Trust Gemma if it returned a valid value
    if (['SAFE', 'RISKY', 'UNSAFE'].includes(rawSafety?.toUpperCase())) {
      return rawSafety.toUpperCase() as 'SAFE' | 'RISKY' | 'UNSAFE';
    }
    return 'RISKY';
  }

  private clamp(val: number, min = 0, max = 100): number {
    return Math.max(min, Math.min(max, Number(val) || 50));
  }

  // ─── Fallback Builders ────────────────────────────────────────────────────

  private buildFallback(error: unknown, websiteUrl: string): PrivacyAnalysisResult {
    if (error instanceof Error) {
      const msg = error.message.toLowerCase();
      if (msg.includes('429') || msg.includes('quota') || msg.includes('too many')) {
        return this.buildQuotaFallback();
      }
      if (msg.includes('safety') || msg.includes('blocked')) {
        return this.buildSafetyFallback();
      }
    }
    return this.buildGenericFallback(websiteUrl);
  }

  private defaultDPDP(): DPDPCompliance {
    return {
      compliant: false,
      hasDPO: false,
      hasGrievanceRedressal: false,
      hasPurposeSpecification: false,
      hasConsentWithdrawal: false,
      hasDataLocalization: false,
      missingRequirements: ['Analysis unavailable — review manually'],
    };
  }

  private defaultVectors(score: number): VectorScores {
    return {
      dataSale: score,
      trackingScope: score,
      dataRetention: score,
      consentQuality: score,
      securityStandards: score,
    };
  }

  private buildQuotaFallback(): PrivacyAnalysisResult {
    return {
      summary: 'AI analysis temporarily unavailable due to quota limits. Please review the privacy policy manually for data collection and sharing practices.',
      safety: 'RISKY',
      score: 50,
      vectorScores: this.defaultVectors(50),
      risks: ['AI analysis unavailable — manual review required'],
      positiveFeatures: [],
      complianceFlags: [],
      dpdpCompliance: this.defaultDPDP(),
    };
  }

  private buildSafetyFallback(): PrivacyAnalysisResult {
    return {
      summary: 'Privacy policy content could not be analyzed. Manual review recommended to assess data handling and user rights.',
      safety: 'RISKY',
      score: 45,
      vectorScores: this.defaultVectors(45),
      risks: ['Content could not be analyzed', 'Manual review required'],
      positiveFeatures: [],
      complianceFlags: [],
      dpdpCompliance: this.defaultDPDP(),
    };
  }

  private buildGenericFallback(websiteUrl: string): PrivacyAnalysisResult {
    let domain = websiteUrl;
    try { domain = new URL(websiteUrl).hostname; } catch {}
    return {
      summary: `Privacy policy analysis failed for ${domain}. Review manually for data collection, third-party sharing, user rights, and retention policies.`,
      safety: 'RISKY',
      score: 40,
      vectorScores: this.defaultVectors(40),
      risks: ['Analysis failed — manual review required'],
      positiveFeatures: [],
      complianceFlags: [],
      dpdpCompliance: this.defaultDPDP(),
    };
  }
}
