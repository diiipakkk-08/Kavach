import express, { Request, Response } from 'express';
import { GeminiPrivacyAnalyzer } from '../services/gemini-analyzer.js';

const router = express.Router();

let analyzer: GeminiPrivacyAnalyzer;
try {
  analyzer = new GeminiPrivacyAnalyzer();
} catch (error) {
  console.error('Failed to initialize analyzer for image PII:', error);
}

interface ImagePIIRequest {
  base64Image: string;
  mimeType: string;   // 'image/jpeg' | 'image/png' | 'image/webp'
  context?: string;   // Optional context about what the image is
}

/**
 * POST /api/image/scan-pii
 * Uses Gemma 4 multimodal vision to detect visible PII in an uploaded image
 */
router.post('/scan-pii', async (req: Request, res: Response): Promise<void> => {
  try {
    const { base64Image, mimeType, context }: ImagePIIRequest = req.body;

    if (!base64Image) {
      res.status(400).json({ success: false, error: 'base64Image is required' });
      return;
    }

    if (!mimeType || !['image/jpeg', 'image/jpg', 'image/png', 'image/webp'].includes(mimeType)) {
      res.status(400).json({
        success: false,
        error: 'mimeType must be one of: image/jpeg, image/png, image/webp',
      });
      return;
    }

    // Check image size (reject > 10MB)
    const imageSizeBytes = Buffer.byteLength(base64Image, 'base64');
    if (imageSizeBytes > 10 * 1024 * 1024) {
      res.status(413).json({
        success: false,
        error: 'Image too large. Maximum size is 10MB.',
      });
      return;
    }

    if (!analyzer) {
      res.status(503).json({ success: false, error: 'AI service unavailable. Check GEMINI_API_KEY.' });
      return;
    }

    console.log(`🔍 Scanning image for PII (${Math.round(imageSizeBytes / 1024)}KB, ${mimeType})...`);

    const result = await analyzer.analyzePIIInImage(base64Image, mimeType);

    const actionRequired = result.riskLevel === 'HIGH' || result.riskLevel === 'CRITICAL';

    console.log(`✅ PII scan complete — Risk: ${result.riskLevel}, PII found: ${result.hasPII}`);

    res.json({
      success: true,
      data: {
        ...result,
        actionRequired,
        suggestedActions: actionRequired ? [
          'Blur or redact sensitive areas before uploading',
          'Consider stripping EXIF metadata (use /api/metadata/strip)',
          'Review if this image needs to be uploaded at all',
        ] : ['Image appears safe to upload'],
        imageSizeBytes,
        scannedAt: new Date().toISOString(),
        model: 'gemma-3-27b-it (multimodal)',
      },
    });

  } catch (error) {
    console.error('❌ Image PII scan error:', error);
    const msg = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ success: false, error: `Failed to scan image: ${msg}` });
  }
});

/**
 * GET /api/image/pii-types
 * Returns the list of PII types Kavach can detect
 */
router.get('/pii-types', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      detectable: [
        'Government IDs — Aadhaar, PAN Card, Passport, Driving License',
        'Financial — Credit/Debit card numbers, Bank statements, Account numbers',
        'Biometric — Fingerprints visible on ID cards, Face photos with ID',
        'Medical — Prescriptions, Medical reports, Health records',
        'Contact — Visible phone numbers, email addresses, physical addresses',
        'Signatures — Handwritten signatures',
        'Vehicle — License/Number plates',
        'Education — Degree certificates, Marksheets with personal details',
      ],
      riskLevels: {
        LOW: 'No PII or extremely minor/partial info',
        MEDIUM: 'Partial info (last 4 digits, partial address)',
        HIGH: 'Full government ID, credit card, medical records',
        CRITICAL: 'Multiple high-risk PII types simultaneously visible',
      },
      model: 'gemma-3-27b-it (multimodal vision)',
    },
  });
});

export default router;
