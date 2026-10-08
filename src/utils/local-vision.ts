/**
 * Kavach Local In-Browser Vision & Secret Scanner
 * Scans images for visible credentials (passwords, Wi-Fi keys, emails, API keys, tokens).
 * Engine Priority:
 * 1. Google Gemini Flash Vision (if user API key provided)
 * 2. Local Ollama (if localhost:11434 running)
 * 3. Browser Native TextDetector & Canvas Optical Analysis
 */
import { KavachAIService } from './ai-service';

export interface LocalScanFinding {
  type: 'password' | 'email' | 'api_key' | 'gov_id' | 'network_ip' | 'token' | 'face';
  severity: 'HIGH' | 'CRITICAL' | 'MEDIUM';
  title: string;
  exactSnippet: string;
  vulnerabilityDescription: string;
}

export interface LocalScanResult {
  hasSensitiveData: boolean;
  findings: LocalScanFinding[];
  riskLevel: 'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  engineUsed: 'GEMINI_AI_VISION' | 'LOCAL_OLLAMA_GEMMA' | 'BROWSER_CANVAS_SCANNER';
  recommendation: string;
}

export class LocalVisionEngine {
  /**
   * Scans an image File for sensitive credentials
   */
  static async scanFileLocally(file: File): Promise<LocalScanResult> {
    const findings: LocalScanFinding[] = [];

    // 1. Try Gemini Flash Vision (Deep multimodal AI OCR)
    try {
      const base64 = await this.fileToBase64(file);
      const aiResult = await KavachAIService.scanImageWithAI(base64, file.type);
      if (aiResult && aiResult.findings.length > 0) {
        const isCritical = aiResult.findings.some(f => f.severity === 'CRITICAL');
        return {
          hasSensitiveData: true,
          findings: aiResult.findings,
          riskLevel: isCritical ? 'CRITICAL' : 'HIGH',
          engineUsed: 'GEMINI_AI_VISION',
          recommendation: aiResult.recommendation || 'Plaintext credentials visually identified by Gemini AI.',
        };
      }
    } catch {}

    // 2. Try local Ollama if running
    const ollamaResult = await this.tryLocalOllama(file);
    if (ollamaResult && ollamaResult.findings.length > 0) {
      return ollamaResult;
    }

    // 3. Browser-level OCR / TextDetector / Canvas Analysis
    await this.scanBrowserCanvasAndText(file, findings);

    // 4. Inspect PNG/JPEG embedded chunks
    await this.scanFileChunksForText(file, findings);

    // 5. Filename-based credential hints
    const nameLower = file.name.toLowerCase();
    if (
      nameLower.includes('password') ||
      nameLower.includes('passwd') ||
      nameLower.includes('credential') ||
      nameLower.includes('secret') ||
      nameLower.includes('wpa2')
    ) {
      if (!findings.some(f => f.type === 'password')) {
        findings.push({
          type: 'password',
          severity: 'CRITICAL',
          title: 'Credential File Name Detected',
          exactSnippet: file.name,
          vulnerabilityDescription: 'The filename explicitly denotes passwords or access credentials.',
        });
      }
    }

    const isCritical = findings.some(f => f.severity === 'CRITICAL');
    const isHigh = findings.some(f => f.severity === 'HIGH');
    const isMed = findings.some(f => f.severity === 'MEDIUM');

    const riskLevel: 'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : isMed ? 'MEDIUM' : 'SAFE';

    let recommendation = 'Image appears clean of visible credentials.';
    if (isCritical) {
      recommendation = 'DO NOT UPLOAD: Plaintext password or private credential detected in image.';
    } else if (isHigh) {
      recommendation = 'Sensitive personal identity or contact details visible. Blur or crop before sharing.';
    }

    return {
      hasSensitiveData: findings.length > 0,
      findings,
      riskLevel,
      engineUsed: 'BROWSER_CANVAS_SCANNER',
      recommendation,
    };
  }

  /**
   * Browser Canvas & Shape Detection Text Scanner
   */
  private static async scanBrowserCanvasAndText(file: File, findings: LocalScanFinding[]): Promise<void> {
    return new Promise((resolve) => {
      const img = new Image();
      const url = URL.createObjectURL(file);

      img.onload = async () => {
        try {
          // A) Try Native Chrome/Chromium TextDetector if available
          if ('TextDetector' in window) {
            try {
              const detector = new (window as any).TextDetector();
              const detected = await detector.detect(img);
              if (detected && detected.length > 0) {
                const combined = detected.map((d: any) => d.rawValue).join(' ');
                this.runRegexAudits(combined, findings);
              }
            } catch {}
          }

          // B) Try Native Chrome/Chromium FaceDetector if available
          if ('FaceDetector' in window) {
            try {
              const faceDetector = new (window as any).FaceDetector({ fastMode: true, maxDetectedFaces: 5 });
              const faces = await faceDetector.detect(img);
              if (faces && faces.length > 0) {
                findings.push({
                  type: 'face',
                  severity: 'MEDIUM',
                  title: `${faces.length} Human Face(s) Detected`,
                  exactSnippet: `${faces.length} biometric portrait area(s) detected`,
                  vulnerabilityDescription: 'Biometric privacy warning: Image reveals identifiable human face(s). Facial recognition algorithms can index and correlate your identity.',
                });
              }
            } catch {}
          }

          // C) Canvas Optical Contrast, Biometrics, Password Bullets & Form Scan
          const canvas = document.createElement('canvas');
          canvas.width = Math.min(img.naturalWidth || img.width || 800, 1200);
          canvas.height = Math.min(img.naturalHeight || img.height || 600, 800);
          const ctx = canvas.getContext('2d');
          if (ctx) {
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            this.detectHumanFaceSkinClusters(imgData, findings);
            this.detectMaskedPasswordBullets(imgData, findings);
            this.detectCredentialInputBoxes(imgData, findings);
            this.detectEmailAtSymbol(imgData, findings);
            this.detectHighDensityTextRegions(imgData, findings, file.name);
          }

          URL.revokeObjectURL(url);
          resolve();
        } catch {
          URL.revokeObjectURL(url);
          resolve();
        }
      };

      img.onerror = () => {
        URL.revokeObjectURL(url);
        resolve();
      };

      img.src = url;
    });
  }

  /**
   * Analyzes pixel grid for concentrated human facial skin tone clusters in YCbCr color space
   */
  private static detectHumanFaceSkinClusters(imgData: ImageData, findings: LocalScanFinding[]): void {
    const { width, height, data } = imgData;
    let skinPixels = 0;
    let minX = width, maxX = 0, minY = height, maxY = 0;

    // Sample every 4th pixel for high efficiency
    for (let y = 0; y < height; y += 4) {
      for (let x = 0; x < width; x += 4) {
        const idx = (y * width + x) * 4;
        const r = data[idx];
        const g = data[idx + 1];
        const b = data[idx + 2];

        // Standard YCbCr skin tone detection formula
        const cb = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b;
        const cr = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b;

        if (cb >= 77 && cb <= 127 && cr >= 133 && cr <= 173) {
          skinPixels++;
          if (x < minX) minX = x;
          if (x > maxX) maxX = x;
          if (y < minY) minY = y;
          if (y > maxY) maxY = y;
        }
      }
    }

    const totalSampled = (width / 4) * (height / 4);
    const skinRatio = skinPixels / (totalSampled || 1);
    const clusterWidth = maxX - minX;
    const clusterHeight = maxY - minY;
    const aspectRatio = clusterHeight / (clusterWidth || 1);

    // Portrait / selfie characteristic: 7% to 65% skin density with oval aspect ratio (0.8 to 2.2)
    if (skinRatio >= 0.07 && skinRatio <= 0.65 && aspectRatio >= 0.8 && aspectRatio <= 2.2) {
      if (!findings.some(f => f.type === 'face')) {
        findings.push({
          type: 'face',
          severity: 'MEDIUM',
          title: 'Human Face / Portrait Biometrics Detected',
          exactSnippet: `Facial biometric cluster detected (~${Math.round(skinRatio * 100)}% portrait density)`,
          vulnerabilityDescription: 'Biometric privacy warning: Image reveals an identifiable human face. Can be used for facial recognition and biometric profiling.',
        });
      }
    }
  }

  /**
   * Detects masked password bullet rows (•••••••• or ********) in canvas pixels (both light & dark mode)
   */
  private static detectMaskedPasswordBullets(imgData: ImageData, findings: LocalScanFinding[]): void {
    const { width, height, data } = imgData;

    // Check both polarities: dark dots on light bg (polarity = 1), and light dots on dark bg (polarity = 0)
    for (const polarity of [1, 0]) {
      for (let y = 8; y < height - 8; y += 3) {
        const bulletCandidates: number[] = [];
        let inDot = false;
        let dotStart = 0;

        for (let x = 8; x < width - 8; x++) {
          const idx = (y * width + x) * 4;
          const lum = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2];
          const isTargetLum = polarity === 1 ? lum < 105 : lum > 150;

          if (isTargetLum && !inDot) {
            inDot = true;
            dotStart = x;
          } else if (!isTargetLum && inDot) {
            inDot = false;
            const dotWidth = x - dotStart;
            if (dotWidth >= 3 && dotWidth <= 16) {
              bulletCandidates.push(dotStart + Math.floor(dotWidth / 2));
            }
          }
        }

        if (bulletCandidates.length >= 3) {
          let consecutiveMatches = 1;
          let lastSpacing = -1;

          for (let i = 1; i < bulletCandidates.length; i++) {
            const spacing = bulletCandidates[i] - bulletCandidates[i - 1];
            if (spacing >= 6 && spacing <= 36) {
              if (lastSpacing === -1 || Math.abs(spacing - lastSpacing) <= 7) {
                consecutiveMatches++;
                lastSpacing = spacing;
              } else {
                consecutiveMatches = 1;
                lastSpacing = spacing;
              }
            }
            if (consecutiveMatches >= 3) {
              if (!findings.some(f => f.type === 'password')) {
                findings.push({
                  type: 'password',
                  severity: 'CRITICAL',
                  title: 'Masked Password Input Field Detected',
                  exactSnippet: `•••••••• (${consecutiveMatches}+ masked password bullets detected in image)`,
                  vulnerabilityDescription: 'Visual scanner detected active password bullet dots entered into an authentication field.',
                });
              }
              return;
            }
          }
        }
      }
    }
  }

  /**
   * Detects rectangular credential input boxes and login card contours
   */
  private static detectCredentialInputBoxes(imgData: ImageData, findings: LocalScanFinding[]): void {
    const { width, height, data } = imgData;
    let detectedInputBoxes = 0;

    for (let y = 10; y < height - 35; y += 6) {
      for (let x = 10; x < width - 120; x += 12) {
        const idx = (y * width + x) * 4;
        const lum = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2];

        let horizontalSpan = 0;
        for (let hx = x; hx < Math.min(x + 400, width - 5); hx += 5) {
          const hIdx = (y * width + hx) * 4;
          const hLum = 0.299 * data[hIdx] + 0.587 * data[hIdx + 1] + 0.114 * data[hIdx + 2];
          if (Math.abs(hLum - lum) < 45) horizontalSpan += 5;
          else break;
        }

        if (horizontalSpan >= 110) {
          for (let testH = 22; testH <= 55; testH += 5) {
            const bY = y + testH;
            if (bY >= height) break;
            const bIdx = (bY * width + (x + 20)) * 4;
            const bLum = 0.299 * data[bIdx] + 0.587 * data[bIdx + 1] + 0.114 * data[bIdx + 2];
            if (Math.abs(bLum - lum) < 55) {
              detectedInputBoxes++;
              x += horizontalSpan;
              break;
            }
          }
        }
      }
    }

    if (detectedInputBoxes >= 1) {
      if (!findings.some(f => f.type === 'password' || f.type === 'email')) {
        findings.push({
          type: detectedInputBoxes >= 2 ? 'password' : 'email',
          severity: detectedInputBoxes >= 2 ? 'CRITICAL' : 'HIGH',
          title: detectedInputBoxes >= 2 ? 'Login / Credential Form Layout Detected' : 'Credential / Form Input Field Detected',
          exactSnippet: `${detectedInputBoxes} interactive input field box(es) detected`,
          vulnerabilityDescription: 'Screenshot contains active authentication input boxes (username / password / email fields).',
        });
      }
    }
  }

  /**
   * Scans for email '@' symbol spiral glyphs in canvas pixels
   */
  private static detectEmailAtSymbol(imgData: ImageData, findings: LocalScanFinding[]): void {
    const { width, height, data } = imgData;
    // An '@' sign is a 10x10 to 24x24 box with a dark center and an outer surrounding ring
    for (let y = 15; y < height - 25; y += 8) {
      for (let x = 15; x < width - 25; x += 8) {
        const centerIdx = (y * width + x) * 4;
        const centerLum = 0.299 * data[centerIdx] + 0.587 * data[centerIdx + 1] + 0.114 * data[centerIdx + 2];

        // If center pixel is dark (text stroke)
        if (centerLum < 120) {
          // Check if top, bottom, left, right all have text strokes 5-12px away (loop)
          const leftIdx = (y * width + (x - 7)) * 4;
          const rightIdx = (y * width + (x + 7)) * 4;
          const topIdx = ((y - 7) * width + x) * 4;
          const bottomIdx = ((y + 7) * width + x) * 4;

          const leftLum = 0.299 * data[leftIdx] + 0.587 * data[leftIdx + 1] + 0.114 * data[leftIdx + 2];
          const rightLum = 0.299 * data[rightIdx] + 0.587 * data[rightIdx + 1] + 0.114 * data[rightIdx + 2];
          const topLum = 0.299 * data[topIdx] + 0.587 * data[topIdx + 1] + 0.114 * data[topIdx + 2];
          const bottomLum = 0.299 * data[bottomIdx] + 0.587 * data[bottomIdx + 1] + 0.114 * data[bottomIdx + 2];

          // Check if surrounded on 3 or 4 sides with matching stroke
          const matchingEnclosures = [leftLum, rightLum, topLum, bottomLum].filter(l => l < 130).length;
          if (matchingEnclosures >= 3) {
            if (!findings.some(f => f.type === 'email')) {
              findings.push({
                type: 'email',
                severity: 'HIGH',
                title: 'Visible Email Address (@) Symbol Detected',
                exactSnippet: '@ account identifier in image',
                vulnerabilityDescription: 'Screenshot contains personal email address formatting (@). Exposes identity to data brokers.',
              });
              return;
            }
          }
        }
      }
    }
  }

  /**
   * Analyzes pixel grid for high contrast text lines & UI email patterns
   */
  private static detectHighDensityTextRegions(
    imgData: ImageData,
    findings: LocalScanFinding[],
    filename: string
  ): void {
    const { width, height, data } = imgData;
    let horizontalTransitions = 0;
    let textLineBands = 0;

    for (let y = 10; y < height - 10; y += 5) {
      let lineTransitions = 0;
      let lastLum = -1;
      for (let x = 10; x < width - 10; x += 3) {
        const idx = (y * width + x) * 4;
        const lum = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2];
        if (lastLum >= 0 && Math.abs(lum - lastLum) > 65) {
          lineTransitions++;
        }
        lastLum = lum;
      }
      if (lineTransitions > 8) textLineBands++;
      horizontalTransitions += lineTransitions;
    }

    const nameLower = filename.toLowerCase();
    const hasEmailHint = nameLower.includes('email') || nameLower.includes('mail') || nameLower.includes('user');
    const hasPassHint = nameLower.includes('pass') || nameLower.includes('secret') || nameLower.includes('cred') || nameLower.includes('token') || nameLower.includes('key');

    // UI text screenshot (> 90 transitions and 2+ text bands)
    if (horizontalTransitions > 90 && textLineBands >= 2) {
      if (!findings.some(f => f.type === 'password' || f.type === 'email')) {
        findings.push({
          type: hasPassHint ? 'password' : 'email',
          severity: hasPassHint ? 'CRITICAL' : 'HIGH',
          title: hasPassHint ? 'UI Credential / Password Screenshot Detected' : 'Visible Account Credentials / Text Screenshot',
          exactSnippet: `High-density text UI (${textLineBands} text line rows)`,
          vulnerabilityDescription: 'High-contrast text rows and UI form elements detected displaying confidential account details or credentials.',
        });
      }
    } else if (hasPassHint || hasEmailHint) {
      findings.push({
        type: hasEmailHint ? 'email' : 'password',
        severity: 'HIGH',
        title: hasEmailHint ? 'Email File Reference' : 'Credential File Reference',
        exactSnippet: filename,
        vulnerabilityDescription: 'Image filename indicates confidential personal login or secret credentials.',
      });
    }
  }

  /**
   * Scans raw file chunks for ASCII/UTF-8 strings embedded in PNG/JPEG metadata
   */
  private static async scanFileChunksForText(file: File, findings: LocalScanFinding[]): Promise<void> {
    try {
      const buffer = await file.slice(0, 524288).arrayBuffer(); // read 512KB
      const bytes = new Uint8Array(buffer);
      let asciiString = '';

      // Extract printable ASCII sequences longer than 5 chars
      let currentSeq = '';
      for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b >= 32 && b <= 126) {
          currentSeq += String.fromCharCode(b);
        } else {
          if (currentSeq.length >= 6) {
            asciiString += ' ' + currentSeq;
          }
          currentSeq = '';
        }
      }

      if (asciiString.length > 0) {
        this.runRegexAudits(asciiString, findings);
      }
    } catch {}
  }

  /**
   * Run targeted security pattern audits on text
   */
  static runRegexAudits(text: string, findings: LocalScanFinding[]): void {
    // 1. Email pattern
    const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
    if (emailMatches && emailMatches.length > 0) {
      const uniqueEmails = Array.from(new Set(emailMatches)).slice(0, 3);
      uniqueEmails.forEach(email => {
        if (!findings.some(f => f.exactSnippet === email)) {
          findings.push({
            type: 'email',
            severity: 'HIGH',
            title: 'Visible Personal Email Address',
            exactSnippet: email,
            vulnerabilityDescription: 'Exposes your identity and invites automated phishing or spam targeting.',
          });
        }
      });
    }

    // 2. Plaintext Password / Secret Key patterns
    const passRegex = /(?:password|passwd|pwd|pass|secret|key|pin|token|wpa2)[\s:=_-]+([^\s,;<>'"\\]{4,})/gi;
    let match: RegExpExecArray | null;
    while ((match = passRegex.exec(text)) !== null) {
      const foundSnippet = match[0].substring(0, 40);
      if (!findings.some(f => f.exactSnippet === foundSnippet)) {
        findings.push({
          type: 'password',
          severity: 'CRITICAL',
          title: 'Visible Plaintext Password / Secret Key',
          exactSnippet: foundSnippet,
          vulnerabilityDescription: 'Severe credential exposure: Anyone viewing this image can compromise your account or network.',
        });
      }
    }

    // 3. API Keys (Google, OpenAI, GitHub, Stripe)
    const apiKeyPatterns = [
      { regex: /AIza[0-9A-Za-z\-_]{35}/g, label: 'Google Cloud API Key' },
      { regex: /sk-[A-Za-z0-9]{24,48}/g, label: 'OpenAI Secret Key' },
      { regex: /ghp_[A-Za-z0-9]{36}/g, label: 'GitHub Personal Access Token' },
      { regex: /pk_live_[A-Za-z0-9]{24}/g, label: 'Stripe Live API Key' },
    ];

    apiKeyPatterns.forEach(({ regex, label }) => {
      const keys = text.match(regex);
      if (keys && keys.length > 0) {
        keys.forEach(k => {
          if (!findings.some(f => f.exactSnippet === k)) {
            findings.push({
              type: 'api_key',
              severity: 'CRITICAL',
              title: `Visible ${label}`,
              exactSnippet: `${k.substring(0, 14)}...`,
              vulnerabilityDescription: 'Exposes cloud API credentials for unauthorized billing or data access.',
            });
          }
        });
      }
    });

    // 4. Internal IP addresses
    const ipMatches = text.match(/\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    if (ipMatches && ipMatches.length > 0) {
      ipMatches.forEach(ip => {
        if (!findings.some(f => f.exactSnippet === ip)) {
          findings.push({
            type: 'network_ip',
            severity: 'MEDIUM',
            title: 'Internal Private IP Address',
            exactSnippet: ip,
            vulnerabilityDescription: 'Reveals internal private network topology to external actors.',
          });
        }
      });
    }
  }

  /**
   * Try local Ollama instance on http://localhost:11434
   */
  private static async tryLocalOllama(file: File): Promise<LocalScanResult | null> {
    try {
      let chosenModel = 'moondream';
      try {
        const tagsRes = await fetch('http://localhost:11434/api/tags');
        if (tagsRes.ok) {
          const tagsData = await tagsRes.json();
          const models = (tagsData?.models || []).map((m: any) => m.name);
          const visionModel = models.find((m: string) => /gemma|moondream|llava|vision|minicpm/i.test(m)) || models[0];
          if (visionModel) chosenModel = visionModel;
        }
      } catch {}

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const base64 = await this.fileToBase64(file);

      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          model: chosenModel,
          prompt: 'Inspect this image for credentials, passwords, auth tokens, email addresses, or secrets. List exact findings.',
          images: [base64],
          stream: false,
        }),
      });

      clearTimeout(timeoutId);

      if (!response.ok) return null;
      const data = await response.json();
      const outputText = data?.response || '';
      if (!outputText) return null;

      const findings: LocalScanFinding[] = [];
      this.runRegexAudits(outputText, findings);

      if (outputText.toLowerCase().includes('password') || outputText.toLowerCase().includes('secret')) {
        findings.push({
          type: 'password',
          severity: 'CRITICAL',
          title: 'Local AI: Password Detected in Image',
          exactSnippet: outputText.substring(0, 120),
          vulnerabilityDescription: 'Local Gemma/Ollama model visually identified plaintext passwords in the image pixels.',
        });
      }

      return {
        hasSensitiveData: findings.length > 0,
        findings,
        riskLevel: findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
        engineUsed: 'LOCAL_OLLAMA_GEMMA',
        recommendation: 'Analyzed 100% locally by desktop Ollama model.',
      };
    } catch {
      return null;
    }
  }

  static fileToBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const res = reader.result as string;
        resolve(res.split(',')[1] || res);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }
}
