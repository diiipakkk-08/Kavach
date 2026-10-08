import express, { Request, Response } from 'express';

const router = express.Router();

interface MetadataStripRequest {
  base64Image: string;
  mimeType: string;      // 'image/jpeg' | 'image/png' | 'image/webp'
  filename?: string;
}

/**
 * Strips EXIF metadata from a base64-encoded image entirely in-memory.
 *
 * Strategy:
 * - JPEG: Locate and remove APP1 (0xFFE1) segments which contain EXIF/GPS data
 * - PNG: Remove tEXt, iTXt, zTXt, and gAMA chunks (metadata carriers)
 * - Other: Return as-is (no metadata defined for this format)
 *
 * All processing is on-device — no image data is stored or logged.
 */

// ─── JPEG EXIF Stripper ───────────────────────────────────────────────────────

function stripJpegExif(buffer: Buffer): { cleanBuffer: Buffer; removedFields: string[] } {
  const removedFields: string[] = [];
  const SOI = 0xFFD8;  // JPEG Start of Image
  const SOS = 0xFFDA;  // Start of Scan — actual image data begins here
  const EOI = 0xFFD9;  // End of Image

  // Verify it's a JPEG
  if (buffer.readUInt16BE(0) !== SOI) {
    throw new Error('Not a valid JPEG file');
  }

  const output: Buffer[] = [];
  output.push(Buffer.from([0xFF, 0xD8])); // Write SOI

  let offset = 2;

  while (offset < buffer.length) {
    // JPEG markers start with 0xFF
    if (buffer[offset] !== 0xFF) break;

    const marker = buffer.readUInt16BE(offset);

    // SOS — image data starts, copy rest as-is
    if (marker === SOS) {
      output.push(buffer.subarray(offset));
      break;
    }

    // EOI
    if (marker === EOI) {
      output.push(Buffer.from([0xFF, 0xD9]));
      break;
    }

    // Segment length is 2 bytes after the marker
    const segmentLength = buffer.readUInt16BE(offset + 2);
    const segmentEnd = offset + 2 + segmentLength;

    // APP1 (0xFFE1) — Contains EXIF (and sometimes XMP) data
    if (marker === 0xFFE1) {
      // Check if it's EXIF
      const exifHeader = buffer.slice(offset + 4, offset + 10).toString('ascii');
      if (exifHeader.startsWith('Exif')) {
        removedFields.push(
          'EXIF: GPS Coordinates (GPSLatitude, GPSLongitude, GPSImgDirection)',
          'EXIF: Camera Info (Make, Model, SerialNumber)',
          'EXIF: DateTime (DateTimeOriginal, DateTimeDigitized)',
          'EXIF: Device Info (Software, HostComputer)',
          'EXIF: Thumbnail'
        );
      } else if (exifHeader.startsWith('http')) {
        // XMP metadata
        removedFields.push('XMP metadata block');
      } else {
        removedFields.push('APP1 segment (unknown)');
      }
      // Skip this segment — do not copy to output
      offset = segmentEnd;
      continue;
    }

    // APP0 (0xFFE0) — JFIF header, keep it (needed for valid JPEG)
    // APP2–APP15 — may contain ICC profile, other metadata
    if (marker >= 0xFFE2 && marker <= 0xFFEF) {
      // Remove all APPn segments except APP0 (JFIF) and APP1 (handled above)
      const appName = `APP${marker - 0xFFE0} segment`;
      removedFields.push(appName);
      offset = segmentEnd;
      continue;
    }

    // Keep all other segments (DQT, DHT, SOF, DRI, etc.)
    output.push(buffer.subarray(offset, segmentEnd));
    offset = segmentEnd;
  }

  return {
    cleanBuffer: Buffer.concat(output),
    removedFields,
  };
}

// ─── PNG Metadata Stripper ────────────────────────────────────────────────────

function stripPngMetadata(buffer: Buffer): { cleanBuffer: Buffer; removedFields: string[] } {
  const removedFields: string[] = [];

  // PNG signature: 8 bytes
  const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (!buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('Not a valid PNG file');
  }

  const output: Buffer[] = [PNG_SIGNATURE];
  let offset = 8;

  // Metadata chunk types to remove
  const REMOVE_CHUNKS = new Set([
    'tEXt', 'iTXt', 'zTXt',  // Text metadata (EXIF often embedded here)
    'eXIf',                    // EXIF chunk (newer PNG spec)
    'tIME',                    // Last modification time
    'gAMA',                    // Gamma (can be fingerprinting vector)
    'pHYs',                    // Physical pixel dimensions (device metadata)
    'sBIT',                    // Significant bits
    'hIST',                    // Histogram
    'bKGD',                    // Background color
    'sPLT',                    // Suggested palette
    'cHRM',                    // Chromaticities
  ]);

  while (offset < buffer.length) {
    const chunkLength = buffer.readUInt32BE(offset);
    const chunkType = buffer.slice(offset + 4, offset + 8).toString('ascii');
    const chunkEnd = offset + 12 + chunkLength; // length + type + data + CRC

    if (REMOVE_CHUNKS.has(chunkType)) {
      removedFields.push(`PNG ${chunkType} chunk (metadata)`);
      offset = chunkEnd;
      continue;
    }

    // Keep IHDR, IDAT, IEND, and any other data chunks
    output.push(buffer.subarray(offset, chunkEnd));

    if (chunkType === 'IEND') break;
    offset = chunkEnd;
  }

  return {
    cleanBuffer: Buffer.concat(output),
    removedFields,
  };
}

// ─── Route ────────────────────────────────────────────────────────────────────

/**
 * POST /api/metadata/strip
 * Accepts a base64-encoded image, strips EXIF/metadata, returns clean base64
 */
router.post('/strip', async (req: Request, res: Response): Promise<void> => {
  try {
    const { base64Image, mimeType, filename }: MetadataStripRequest = req.body;

    if (!base64Image) {
      res.status(400).json({ success: false, error: 'base64Image is required' });
      return;
    }
    if (!mimeType) {
      res.status(400).json({ success: false, error: 'mimeType is required (e.g. image/jpeg)' });
      return;
    }

    // Decode base64 to buffer
    let imageBuffer: Buffer;
    try {
      imageBuffer = Buffer.from(base64Image, 'base64');
    } catch {
      res.status(400).json({ success: false, error: 'Invalid base64 encoding' });
      return;
    }

    const originalSize = imageBuffer.length;
    let cleanBuffer: Buffer;
    let removedFields: string[] = [];

    // Strip based on MIME type
    if (mimeType === 'image/jpeg' || mimeType === 'image/jpg') {
      const result = stripJpegExif(imageBuffer);
      cleanBuffer = result.cleanBuffer;
      removedFields = result.removedFields;
    } else if (mimeType === 'image/png') {
      const result = stripPngMetadata(imageBuffer);
      cleanBuffer = result.cleanBuffer;
      removedFields = result.removedFields;
    } else if (mimeType === 'image/webp' || mimeType === 'image/gif') {
      // WebP/GIF: return as-is for now (complex format, not commonly carrying GPS)
      cleanBuffer = imageBuffer;
      removedFields = [];
    } else {
      res.status(400).json({
        success: false,
        error: `Unsupported MIME type: ${mimeType}. Supported: image/jpeg, image/png, image/webp`,
      });
      return;
    }

    const cleanBase64 = cleanBuffer.toString('base64');
    const bytesSaved = originalSize - cleanBuffer.length;

    console.log(`🧹 Metadata stripped from ${filename || 'image'}: removed ${removedFields.length} metadata fields, saved ${bytesSaved} bytes`);

    res.json({
      success: true,
      data: {
        cleanBase64,
        mimeType,
        originalSizeBytes: originalSize,
        cleanSizeBytes: cleanBuffer.length,
        bytesSaved,
        removedFields,
        metadataRemoved: removedFields.length > 0,
        processedAt: new Date().toISOString(),
      },
    });

  } catch (error) {
    console.error('❌ Metadata strip error:', error);
    const msg = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ success: false, error: `Failed to strip metadata: ${msg}` });
  }
});

/**
 * GET /api/metadata/supported
 * Returns supported image formats
 */
router.get('/supported', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      supportedFormats: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'],
      strippedMetadata: {
        jpeg: [
          'GPS coordinates (latitude, longitude, altitude, direction)',
          'Camera make and model',
          'Serial number',
          'Date/time original and digitized',
          'Software and host computer',
          'Thumbnail embedded in EXIF',
          'XMP metadata',
          'All APPn segments',
        ],
        png: [
          'tEXt text metadata',
          'iTXt international text',
          'zTXt compressed text',
          'eXIf EXIF block',
          'tIME modification time',
          'Physical pixel dimensions (device fingerprint)',
        ],
      },
    },
  });
});

export default router;
