// Load environment variables first
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { privacyPolicyRouter } from './routes/privacy-policy.js';
import { errorHandler } from './middleware/error-handler.js';
import hibpRoutes from './routes/hibp.js';
import metadataRoutes from './routes/metadata.js';
import dpoDraftRoutes from './routes/dpo-draft.js';
import imagePiiRoutes from './routes/image-pii.js';

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ───────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

// ─── CORS — allow Chrome extension origins + localhost ────────────────────────
const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    if (
      !origin ||
      origin.startsWith('chrome-extension://') ||
      origin.startsWith('moz-extension://') ||
      origin.includes('localhost') ||
      origin.includes('127.0.0.1') ||
      process.env.ALLOWED_ORIGINS?.split(',').some(o => origin.includes(o.trim()))
    ) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};
app.use(cors(corsOptions));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ─── Body Parsing — 50mb limit to support base64 image uploads ───────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'healthy',
    service: 'Kavach Privacy Guardian API',
    ai: 'Gemma 4 (gemma-3-27b-it) via Google AI',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
  });
});

// ─── API Info ─────────────────────────────────────────────────────────────────
app.get('/api', (_req, res) => {
  res.status(200).json({
    service: 'Kavach Privacy Guardian API',
    version: '2.0.0',
    model: 'Gemma 4 — gemma-3-27b-it (open-weight)',
    endpoints: {
      'GET  /health': 'Health check',
      'POST /api/privacy-policy/analyze': 'Analyze privacy policy (auto-discover + scrape URL)',
      'POST /api/privacy-policy/analyze-text': 'Analyze raw policy text from content script',
      'GET  /api/privacy-policy/find': 'Find privacy policy URL for a website',
      'POST /api/metadata/strip': 'Strip EXIF/GPS metadata from image (JPEG, PNG)',
      'GET  /api/metadata/supported': 'Supported formats + stripped fields',
      'POST /api/dpo/draft': 'Draft DPDP Act 2023 / GDPR DPO email with Gemma 4',
      'GET  /api/dpo/article-refs': 'DPDP Act + GDPR article references',
      'POST /api/image/scan-pii': 'Scan image for visible PII using Gemma 4 vision',
      'GET  /api/image/pii-types': 'Detectable PII types',
      'GET  /api/hibp/check/:email': 'Check email for data breaches',
    },
    scoring: {
      model: '5-Vector Weighted Composite Score (0-100)',
      vectors: {
        dataSale: '30% weight — PII sale, data commercialization',
        trackingScope: '25% weight — fingerprinting, cross-site tracking, session replay',
        dataRetention: '20% weight — retention windows, right to erasure',
        consentQuality: '15% weight — opt-in/out, GDPR/CCPA/DPDP 2023 compliance',
        securityStandards: '10% weight — encryption, breach notification',
      },
    },
    timestamp: new Date().toISOString(),
  });
});

// ─── API Routes ───────────────────────────────────────────────────────────────
console.log('🔗 Registering Kavach API routes...');

app.use('/api/privacy-policy', privacyPolicyRouter);
app.use('/api/hibp', hibpRoutes);
app.use('/api/metadata', metadataRoutes);
app.use('/api/dpo', dpoDraftRoutes);
app.use('/api/image', imagePiiRoutes);

console.log('✅ All routes registered');
console.log('   → /api/privacy-policy (Gemma 4 — 5-vector scoring)');
console.log('   → /api/metadata (EXIF/GPS stripping)');
console.log('   → /api/dpo (DPDP Act 2023 email drafter)');
console.log('   → /api/image (PII detection — multimodal vision)');
console.log('   → /api/hibp (breach lookup)');

// ─── Error Handling ───────────────────────────────────────────────────────────
app.use(errorHandler);

app.use('*', (_req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: 'See GET /api for available endpoints',
  });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Kavach Backend Server running on port ${PORT}`);
  console.log(`🤖 AI Model: Gemma 4 (gemma-3-27b-it) — Open-Weight via Google AI`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 CORS: Chrome extensions + localhost`);
  console.log(`📊 Scoring: 5-Vector Weighted (Data Sale 30%, Tracking 25%, Retention 20%, Consent 15%, Security 10%)`);
  console.log(`\nEndpoints: http://localhost:${PORT}/api\n`);
});

export default app;
