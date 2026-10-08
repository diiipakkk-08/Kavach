import express, { Request, Response } from 'express';
import { GeminiPrivacyAnalyzer } from '../services/gemini-analyzer.js';
import { PolicyScraper } from '../services/policy-scraper.js';

const router = express.Router();

interface AnalyzeRequest {
  url: string;
  policyUrl?: string;
}

interface AnalyzeTextRequest {
  url: string;
  policyText: string; // Raw text from content script DOM extraction
}

// Initialize Gemma analyzer
let analyzer: GeminiPrivacyAnalyzer;
try {
  analyzer = new GeminiPrivacyAnalyzer();
  console.log('✅ Gemma 4 Privacy Analyzer initialized');
} catch (error) {
  console.error('❌ Failed to initialize Gemma analyzer:', error);
}

function detectIndustryType(url: string): string {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (hostname.includes('bank') || hostname.includes('credit') || hostname.includes('finance') || hostname.includes('pay')) return 'Financial';
    if (hostname.includes('health') || hostname.includes('medical') || hostname.includes('clinic') || hostname.includes('pharma')) return 'Healthcare';
    if (hostname.includes('shop') || hostname.includes('store') || hostname.includes('commerce') || hostname.includes('amazon') || hostname.includes('flipkart')) return 'E-commerce';
    if (hostname.includes('social') || hostname.includes('instagram') || hostname.includes('facebook') || hostname.includes('twitter') || hostname.includes('linkedin')) return 'Social Media';
    if (hostname.includes('edu') || hostname.includes('university') || hostname.includes('school') || hostname.includes('college')) return 'Education';
    if (hostname.includes('gov') || hostname.includes('government') || hostname.includes('nic.in')) return 'Government';
    if (hostname.includes('news') || hostname.includes('blog') || hostname.includes('journal') || hostname.includes('media')) return 'Media';
    if (hostname.includes('game') || hostname.includes('gaming') || hostname.includes('steam') || hostname.includes('xbox')) return 'Gaming';
    return 'Technology';
  } catch {
    return 'Unknown';
  }
}

function buildAnalyzeResponse(analysis: any, url: string, finalPolicyUrl: string, scrapedContent: any) {
  return {
    success: true,
    data: {
      summary: analysis.summary,
      safety: analysis.safety,
      score: analysis.score,
      vectorScores: analysis.vectorScores,
      risks: analysis.risks || [],
      positiveFeatures: analysis.positiveFeatures || [],
      complianceFlags: analysis.complianceFlags || [],
      dpdpCompliance: analysis.dpdpCompliance,
      dataSharing: [],
      industryType: detectIndustryType(url),
      analysisDepth: 'Gemma 4 — 5-Vector Weighted Analysis',
      model: 'gemma-3-27b-it',
      policyMetadata: {
        url: finalPolicyUrl,
        title: scrapedContent?.title || 'Privacy Policy',
        lastModified: scrapedContent?.lastModified,
        contentLength: scrapedContent?.text?.length || 0,
        analyzedAt: new Date().toISOString(),
      },
    },
    policyUrl: finalPolicyUrl,
  };
}

/**
 * POST /api/privacy-policy/analyze
 * Analyzes a website's privacy policy (auto-discovers + scrapes the URL)
 */
router.post('/analyze', async (req: Request, res: Response): Promise<void> => {
  try {
    const { url, policyUrl }: AnalyzeRequest = req.body;

    if (!url) {
      res.status(400).json({ success: false, error: 'Website URL is required' });
      return;
    }

    if (!analyzer) {
      res.status(503).json({ success: false, error: 'Privacy analyzer unavailable. Check GEMINI_API_KEY.' });
      return;
    }

    try { new URL(url); } catch {
      res.status(400).json({ success: false, error: 'Invalid URL format' });
      return;
    }

    let finalPolicyUrl = policyUrl;

    if (!finalPolicyUrl) {
      console.log(`🔍 Searching for privacy policy on ${url}`);
      const foundPolicyResult = await PolicyScraper.findPrivacyPolicyUrl(url);
      if (!foundPolicyResult.privacyPolicyUrl) {
        res.status(404).json({ success: false, error: 'No privacy policy found on this website' });
        return;
      }
      finalPolicyUrl = foundPolicyResult.privacyPolicyUrl;
    }

    console.log(`📄 Scraping privacy policy from ${finalPolicyUrl}`);
    const scrapedContent = await PolicyScraper.scrapePrivacyPolicy(finalPolicyUrl);

    if (!scrapedContent.text || scrapedContent.text.length < 100) {
      res.status(400).json({ success: false, error: 'Privacy policy content is too short or empty' });
      return;
    }

    console.log(`🤖 Analyzing with Gemma 4 (${scrapedContent.text.length} chars)...`);
    const analysis = await analyzer.analyzePrivacyPolicy(scrapedContent.text, url);

    console.log(`✅ Analysis complete — Score: ${analysis.score}, Safety: ${analysis.safety}`);
    res.json(buildAnalyzeResponse(analysis, url, finalPolicyUrl, scrapedContent));

  } catch (error) {
    handleRouteError(error, res, 'Failed to analyze privacy policy');
  }
});

/**
 * POST /api/privacy-policy/analyze-text
 * Accepts raw policy text extracted by the content script (no re-scraping needed)
 */
router.post('/analyze-text', async (req: Request, res: Response): Promise<void> => {
  try {
    const { url, policyText }: AnalyzeTextRequest = req.body;

    if (!url) {
      res.status(400).json({ success: false, error: 'Website URL is required' });
      return;
    }

    if (!policyText || policyText.trim().length < 100) {
      res.status(400).json({ success: false, error: 'Policy text is required and must be at least 100 characters' });
      return;
    }

    if (!analyzer) {
      res.status(503).json({ success: false, error: 'Privacy analyzer unavailable. Check GEMINI_API_KEY.' });
      return;
    }

    console.log(`🤖 Analyzing injected policy text from ${url} (${policyText.length} chars)...`);
    const analysis = await analyzer.analyzePrivacyPolicy(policyText, url);

    console.log(`✅ Analysis complete — Score: ${analysis.score}, Safety: ${analysis.safety}`);
    res.json(buildAnalyzeResponse(analysis, url, url, { text: policyText, title: 'Policy (Content Script)', lastModified: undefined }));

  } catch (error) {
    handleRouteError(error, res, 'Failed to analyze policy text');
  }
});

/**
 * GET /api/privacy-policy/find
 * Find privacy policy URL for a given website
 */
router.get('/find', async (req: Request, res: Response): Promise<void> => {
  try {
    const { url } = req.query;
    if (!url || typeof url !== 'string') {
      res.status(400).json({ success: false, error: 'Website URL is required as query parameter' });
      return;
    }

    try { new URL(url); } catch {
      res.status(400).json({ success: false, error: 'Invalid URL format' });
      return;
    }

    const policyResult = await PolicyScraper.findPrivacyPolicyUrl(url);

    if (!policyResult.privacyPolicyUrl) {
      res.status(404).json({ success: false, error: 'No privacy policy found on this website' });
      return;
    }

    res.json({
      success: true,
      data: {
        policyUrl: policyResult.privacyPolicyUrl,
        foundAt: new Date().toISOString(),
        method: policyResult.method,
        crawledPages: policyResult.crawledPages,
        foundUrls: policyResult.foundUrls.length,
      },
    });

  } catch (error) {
    handleRouteError(error, res, 'Failed to search for privacy policy');
  }
});

function handleRouteError(error: unknown, res: Response, defaultMsg: string) {
  console.error(`❌ ${defaultMsg}:`, error);
  let errorMessage = defaultMsg;
  let statusCode = 500;

  if (error instanceof Error) {
    const msg = error.message;
    if (msg.includes('403') || msg.includes('Access denied')) { errorMessage = 'Website blocks automated access. Please manually review the privacy policy.'; statusCode = 403; }
    else if (msg.includes('404') || msg.includes('not found')) { errorMessage = 'Privacy policy not found on this website'; statusCode = 404; }
    else if (msg.includes('429') || msg.includes('Rate limited')) { errorMessage = 'Too many requests — please try again later'; statusCode = 429; }
    else if (msg.includes('timeout')) { errorMessage = 'Request timeout — the website took too long to respond'; statusCode = 408; }
    else if (msg.includes('ENOTFOUND')) { errorMessage = 'Website not found or not accessible'; statusCode = 404; }
    else if (msg.includes('quota') || msg.includes('API')) { errorMessage = 'AI analysis service temporarily unavailable'; statusCode = 503; }
    else { errorMessage = msg; }
  }

  res.status(statusCode).json({ success: false, error: errorMessage });
}

export { router as privacyPolicyRouter };
