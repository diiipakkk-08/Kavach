/**
 * Kavach Filename Privacy Auditor & Sanitizer
 * Detects embedded capture dates, timestamps, app names (WhatsApp), and camera hardware in filenames.
 */

export interface FilenameAuditResult {
  hasLeaks: boolean;
  leaks: string[];
  suggestedName: string;
  originalName: string;
}

export class FilenameInspector {
  static auditFilename(filename: string): FilenameAuditResult {
    const leaks: string[] = [];
    const extMatch = filename.match(/\.([a-zA-Z0-9]+)$/);
    const ext = extMatch ? `.${extMatch[1]}` : '';
    const baseName = filename.replace(/\.[a-zA-Z0-9]+$/, '');

    // 1. Detect ISO or compact dates (e.g., 2026-10-08, 20261008, 2026_10_08)
    const dateMatch = baseName.match(/(20\d{2})[-_. ]?(0[1-9]|1[0-2])[-_. ]?([0-2][0-9]|3[01])/);
    if (dateMatch) {
      leaks.push(`Capture Date (${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]})`);
    }

    // 2. Detect compact timestamps (e.g., 143022, 14-30-22)
    const timeMatch = baseName.match(/(?:at\s+|T|_|-)([0-1][0-9]|2[0-3])[-_.:]([0-5][0-9])[-_.:]([0-5][0-9])/);
    if (timeMatch) {
      leaks.push(`Exact Time (${timeMatch[1]}:${timeMatch[2]}:${timeMatch[3]})`);
    }

    // 3. Detect messaging apps (e.g. WhatsApp: IMG-20261008-WA0004)
    if (/WA\d{4}|WhatsApp/i.test(baseName)) {
      leaks.push('WhatsApp Media Counter & Origin');
    }

    // 4. Detect device/OS camera tags
    if (/iPhone|iOS/i.test(baseName)) {
      leaks.push('Apple iPhone Device Tag');
    } else if (/Pixel/i.test(baseName)) {
      leaks.push('Google Pixel Camera Tag');
    } else if (/Samsung|Galaxy/i.test(baseName)) {
      leaks.push('Samsung Device Tag');
    } else if (/Screenshot|Screen\s*Shot/i.test(baseName)) {
      leaks.push('OS Desktop/Mobile Screenshot Indicator');
    }

    // 5. Detect personal names or common document types
    if (/resume|cv|invoice|passport|aadhaar|pan|tax|statement/i.test(baseName)) {
      leaks.push('Sensitive Document Type Keyword');
    }

    const hasLeaks = leaks.length > 0;
    const randomSuffix = Math.random().toString(36).substring(2, 7);
    const suggestedName = hasLeaks ? `upload_clean_${randomSuffix}${ext}` : filename;

    return {
      hasLeaks,
      leaks,
      suggestedName,
      originalName: filename,
    };
  }
}
