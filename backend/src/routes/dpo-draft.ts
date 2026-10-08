import express, { Request, Response } from 'express';
import { GoogleGenerativeAI } from '@google/generative-ai';

const router = express.Router();

// DPDP Act 2023 article references
const DPDP_ARTICLES: Record<string, string> = {
  erasure: 'Section 11 — Right to Erasure and Grievance Redressal',
  correction: 'Section 11 — Right to Correction of Personal Data',
  grievance: 'Section 13 — Grievance Redressal by Data Fiduciary',
  consent_withdrawal: 'Section 5(3) — Right to Withdraw Consent',
  data_portability: 'Section 11 — Right to Nominate',
  dpo_contact: 'Section 8(9) — Data Protection Officer Obligation',
};

const GDPR_ARTICLES: Record<string, string> = {
  erasure: 'GDPR Article 17 — Right to Erasure ("Right to be Forgotten")',
  access: 'GDPR Article 15 — Right of Access by the Data Subject',
  portability: 'GDPR Article 20 — Right to Data Portability',
  objection: 'GDPR Article 21 — Right to Object to Processing',
  rectification: 'GDPR Article 16 — Right to Rectification',
};

interface DPODraftRequest {
  websiteUrl: string;
  dpoEmail?: string;
  userName?: string;
  userEmail?: string;
  concerns?: string[];  // e.g. ['data_deletion', 'data_access', 'opt_out', 'grievance']
  jurisdiction?: 'INDIA' | 'EU' | 'US' | 'GLOBAL';
}

function buildEmailPrompt(data: DPODraftRequest): string {
  const {
    websiteUrl,
    dpoEmail,
    userName = '[Your Full Name]',
    userEmail = '[Your Email Address]',
    concerns = ['data_deletion'],
    jurisdiction = 'INDIA',
  } = data;

  let domain = websiteUrl;
  try { domain = new URL(websiteUrl).hostname; } catch {}

  const concernDescriptions: Record<string, string> = {
    data_deletion: 'complete erasure of all my personal data from your systems',
    data_access: 'access to a copy of all personal data you hold about me',
    opt_out: 'opt-out from all tracking, profiling, and marketing communications',
    grievance: 'formal grievance about your data handling practices',
    data_portability: 'a portable copy of my personal data in a machine-readable format',
    consent_withdrawal: 'withdrawal of all previously granted consents',
    correction: 'correction of inaccurate personal data you hold about me',
  };

  const activeConcerns = concerns.map(c => concernDescriptions[c] || c);

  const relevantDPDP = concerns.map(c => DPDP_ARTICLES[c]).filter(Boolean);
  const relevantGDPR = concerns.map(c => GDPR_ARTICLES[c]).filter(Boolean);

  const lawRefs = jurisdiction === 'INDIA'
    ? `Under India's Digital Personal Data Protection Act 2023 (DPDP Act): ${relevantDPDP.join('; ') || 'Section 11 — User Rights'}`
    : `Under GDPR: ${relevantGDPR.join('; ') || 'Article 17 — Right to Erasure'}`;

  return `You are a privacy rights expert. Draft a formal, professional email from a user to a Data Protection Officer (DPO).

User details:
- Name: ${userName}
- Email: ${userEmail}
- Sending to: ${dpoEmail || `dpo@${domain} (or privacy@${domain})`}
- Website/Company: ${domain}
- Jurisdiction: ${jurisdiction}

User's requests:
${activeConcerns.map((c, i) => `${i + 1}. ${c}`).join('\n')}

Legal basis for requests:
${lawRefs}

Requirements for the email:
1. Start with formal salutation to Data Protection Officer / Privacy Team
2. Clearly state identity (use ${userName} and ${userEmail})
3. Cite the specific legal rights and article numbers
4. Make ONE specific, actionable request per concern
5. Set a 30-day response deadline (as mandated by DPDP Act Section 13)
6. Include a numbered list of all requested actions
7. Request written confirmation of receipt
8. Professional, firm but polite tone
9. End with formal sign-off

Respond ONLY with valid JSON:
{
  "subject": "<email subject line>",
  "body": "<complete email body with proper formatting using \\n for newlines>",
  "dpdpArticleRefs": ["<article1>", "<article2>"],
  "recommendedTo": "<suggested recipient email like dpo@${domain} or privacy@${domain}>",
  "deadline": "30 days from sending"
}`;
}

/**
 * POST /api/dpo/draft
 * Uses Gemma 4 to draft a DPDP/GDPR-compliant DPO email
 */
router.post('/draft', async (req: Request, res: Response): Promise<void> => {
  try {
    const data: DPODraftRequest = req.body;

    if (!data.websiteUrl) {
      res.status(400).json({ success: false, error: 'websiteUrl is required' });
      return;
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      res.status(503).json({ success: false, error: 'AI service not configured' });
      return;
    }

    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model: 'gemma-3-27b-it',
      generationConfig: { temperature: 0.2, maxOutputTokens: 1500 },
    });

    const prompt = buildEmailPrompt(data);

    console.log(`📧 Drafting DPO email for ${data.websiteUrl}...`);
    const result = await model.generateContent(prompt);
    const responseText = result.response.text();

    // Parse JSON from response
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('Failed to generate email — no JSON in response');

    const emailData = JSON.parse(jsonMatch[0]);

    // Collect applicable article refs
    const allRefs = new Set<string>();
    (data.concerns || ['data_deletion']).forEach(c => {
      if (DPDP_ARTICLES[c]) allRefs.add(DPDP_ARTICLES[c]);
      if (GDPR_ARTICLES[c]) allRefs.add(GDPR_ARTICLES[c]);
    });

    console.log(`✅ DPO email drafted for ${data.websiteUrl}`);
    res.json({
      success: true,
      data: {
        subject: emailData.subject,
        body: emailData.body,
        recommendedTo: emailData.recommendedTo || `dpo@${new URL(data.websiteUrl).hostname}`,
        dpdpArticleRefs: [...allRefs],
        deadline: '30 days from date of sending',
        generatedAt: new Date().toISOString(),
        model: 'gemma-3-27b-it',
      },
    });

  } catch (error) {
    console.error('❌ DPO draft error:', error);
    const msg = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ success: false, error: `Failed to draft DPO email: ${msg}` });
  }
});

/**
 * GET /api/dpo/article-refs
 * Returns DPDP Act 2023 + GDPR article references
 */
router.get('/article-refs', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      dpdpAct2023: DPDP_ARTICLES,
      gdpr: GDPR_ARTICLES,
      note: 'India\'s DPDP Act 2023 mandates 30-day response by Data Fiduciaries (Section 13)',
    },
  });
});

export default router;
