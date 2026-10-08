/**
 * Kavach EXIF & GPS Parser
 * Pure TypeScript binary parser for JPEG/TIFF EXIF data.
 * Zero external dependencies. Extracts exact GPS coordinates, camera model, timestamps.
 */

export interface GpsCoordinates {
  latitude: number;          // Decimal, e.g. 22.5726
  longitude: number;         // Decimal, e.g. 88.3639
  latitudeDMS: string;       // E.g. "22° 34' 21.4\" N"
  longitudeDMS: string;      // E.g. "88° 21' 49.8\" E"
  altitude?: number;         // Meters
  mapsUrl: string;           // Google Maps link
  osmUrl: string;            // OpenStreetMap link
}

export interface ExifMetadataResult {
  hasGps: boolean;
  gps?: GpsCoordinates;
  cameraMake?: string;       // E.g. "Apple"
  cameraModel?: string;      // E.g. "iPhone 14 Pro"
  software?: string;         // E.g. "17.4.1" or "Photoshop"
  dateTimeOriginal?: string; // E.g. "2024:06:14 18:22:04"
  metadataSizeEstimate: number; // Bytes saved if stripped
  fieldsFound: string[];
}

export class ExifParser {
  /**
   * Parse an image File or ArrayBuffer to extract EXIF and GPS data.
   */
  static async parseFile(file: File): Promise<ExifMetadataResult> {
    try {
      // Read the first 128KB — EXIF APP1 header is always near the beginning of JPEG
      const sliceSize = Math.min(file.size, 131072);
      const buffer = await file.slice(0, sliceSize).arrayBuffer();
      return this.parseBuffer(buffer, file.size);
    } catch (err) {
      console.warn('ExifParser failed:', err);
      return {
        hasGps: false,
        metadataSizeEstimate: 0,
        fieldsFound: [],
      };
    }
  }

  static parseBuffer(buffer: ArrayBuffer, totalFileSize: number): ExifMetadataResult {
    const data = new DataView(buffer);
    const result: ExifMetadataResult = {
      hasGps: false,
      metadataSizeEstimate: 0,
      fieldsFound: [],
    };

    // Check for JPEG SOI (0xFFD8)
    if (data.byteLength < 4 || data.getUint16(0) !== 0xffd8) {
      return result;
    }

    let offset = 2;
    const length = data.byteLength;

    // Scan JPEG markers for APP1 (0xFFE1) containing Exif
    while (offset < length - 4) {
      const marker = data.getUint16(offset);
      offset += 2;

      // APP1 Marker
      if (marker === 0xffe1) {
        const app1Length = data.getUint16(offset);
        result.metadataSizeEstimate = app1Length;
        const exifHeader = data.getUint32(offset + 2); // 'Exif' in ASCII = 0x45786966

        if (exifHeader === 0x45786966 && data.getUint16(offset + 6) === 0x0000) {
          const tiffStart = offset + 8;
          this.parseTiff(data, tiffStart, result);
        }
        break;
      } else if ((marker & 0xff00) === 0xff00 && marker !== 0xff00 && marker !== 0xffd8 && marker !== 0xffd9) {
        // Skip other markers
        const sectionLength = data.getUint16(offset);
        offset += sectionLength;
      } else {
        break;
      }
    }

    return result;
  }

  private static parseTiff(data: DataView, tiffStart: number, result: ExifMetadataResult): void {
    if (tiffStart + 8 > data.byteLength) return;

    // Byte order: 0x4949 ('II') = little-endian, 0x4D4D ('MM') = big-endian
    const byteOrder = data.getUint16(tiffStart);
    const littleEndian = byteOrder === 0x4949;

    // Verify 42 (0x002A)
    if (data.getUint16(tiffStart + 2, littleEndian) !== 0x002a) return;

    const firstIfdOffset = data.getUint32(tiffStart + 4, littleEndian);
    if (tiffStart + firstIfdOffset >= data.byteLength) return;

    let gpsIfdOffset = 0;

    // Read IFD0 tags
    const numEntries = data.getUint16(tiffStart + firstIfdOffset, littleEndian);
    let entryOffset = tiffStart + firstIfdOffset + 2;

    for (let i = 0; i < numEntries && entryOffset + 12 <= data.byteLength; i++) {
      const tag = data.getUint16(entryOffset, littleEndian);
      const type = data.getUint16(entryOffset + 2, littleEndian);
      const count = data.getUint32(entryOffset + 4, littleEndian);
      const valueOffset = entryOffset + 8;

      if (tag === 0x010f) { // Make
        result.cameraMake = this.readString(data, tiffStart, valueOffset, count, littleEndian);
        result.fieldsFound.push(`Make: ${result.cameraMake}`);
      } else if (tag === 0x0110) { // Model
        result.cameraModel = this.readString(data, tiffStart, valueOffset, count, littleEndian);
        result.fieldsFound.push(`Model: ${result.cameraModel}`);
      } else if (tag === 0x0131) { // Software
        result.software = this.readString(data, tiffStart, valueOffset, count, littleEndian);
        result.fieldsFound.push(`Software: ${result.software}`);
      } else if (tag === 0x0132) { // DateTime
        result.dateTimeOriginal = this.readString(data, tiffStart, valueOffset, count, littleEndian);
        result.fieldsFound.push(`Date/Time: ${result.dateTimeOriginal}`);
      } else if (tag === 0x8825) { // GPS IFD Pointer
        gpsIfdOffset = data.getUint32(valueOffset, littleEndian);
      }

      entryOffset += 12;
    }

    // If GPS IFD pointer exists, parse GPS tags
    if (gpsIfdOffset > 0 && tiffStart + gpsIfdOffset + 2 <= data.byteLength) {
      this.parseGpsIfd(data, tiffStart, tiffStart + gpsIfdOffset, littleEndian, result);
    }
  }

  private static parseGpsIfd(
    data: DataView,
    tiffStart: number,
    gpsStart: number,
    littleEndian: boolean,
    result: ExifMetadataResult
  ): void {
    const numGpsEntries = data.getUint16(gpsStart, littleEndian);
    let entryOffset = gpsStart + 2;

    let latRef = 'N';
    let lonRef = 'E';
    let latValues: number[] | null = null;
    let lonValues: number[] | null = null;
    let altitude: number | undefined;

    for (let i = 0; i < numGpsEntries && entryOffset + 12 <= data.byteLength; i++) {
      const tag = data.getUint16(entryOffset, littleEndian);
      const valueOffset = entryOffset + 8;

      if (tag === 0x0001) { // GPSLatitudeRef
        latRef = String.fromCharCode(data.getUint8(valueOffset)).toUpperCase();
      } else if (tag === 0x0002) { // GPSLatitude (3 Rationals)
        latValues = this.readRationals(data, tiffStart, valueOffset, 3, littleEndian);
      } else if (tag === 0x0003) { // GPSLongitudeRef
        lonRef = String.fromCharCode(data.getUint8(valueOffset)).toUpperCase();
      } else if (tag === 0x0004) { // GPSLongitude (3 Rationals)
        lonValues = this.readRationals(data, tiffStart, valueOffset, 3, littleEndian);
      } else if (tag === 0x0006) { // GPSAltitude (1 Rational)
        const altRationals = this.readRationals(data, tiffStart, valueOffset, 1, littleEndian);
        if (altRationals && altRationals.length > 0) altitude = Math.round(altRationals[0]);
      }

      entryOffset += 12;
    }

    if (latValues && lonValues && latValues.length === 3 && lonValues.length === 3) {
      const latDecimal = (latValues[0] + latValues[1] / 60 + latValues[2] / 3600) * (latRef === 'S' ? -1 : 1);
      const lonDecimal = (lonValues[0] + lonValues[1] / 60 + lonValues[2] / 3600) * (lonRef === 'W' ? -1 : 1);

      const latDMS = `${Math.floor(latValues[0])}° ${Math.floor(latValues[1])}' ${latValues[2].toFixed(1)}" ${latRef}`;
      const lonDMS = `${Math.floor(lonValues[0])}° ${Math.floor(lonValues[1])}' ${lonValues[2].toFixed(1)}" ${lonRef}`;

      result.hasGps = true;
      result.gps = {
        latitude: parseFloat(latDecimal.toFixed(6)),
        longitude: parseFloat(lonDecimal.toFixed(6)),
        latitudeDMS: latDMS,
        longitudeDMS: lonDMS,
        altitude,
        mapsUrl: `https://www.google.com/maps?q=${latDecimal.toFixed(6)},${lonDecimal.toFixed(6)}`,
        osmUrl: `https://www.openstreetmap.org/?mlat=${latDecimal.toFixed(6)}&mlon=${lonDecimal.toFixed(6)}#map=16/${latDecimal.toFixed(6)}/${lonDecimal.toFixed(6)}`,
      };

      result.fieldsFound.push(`GPS: ${latDMS}, ${lonDMS}`);
    }
  }

  private static readString(
    data: DataView,
    tiffStart: number,
    valueOffset: number,
    count: number,
    littleEndian: boolean
  ): string {
    let strOffset = valueOffset;
    if (count > 4) {
      strOffset = tiffStart + data.getUint32(valueOffset, littleEndian);
    }
    let str = '';
    for (let i = 0; i < count && strOffset + i < data.byteLength; i++) {
      const code = data.getUint8(strOffset + i);
      if (code === 0) break; // null terminator
      str += String.fromCharCode(code);
    }
    return str.trim();
  }

  private static readRationals(
    data: DataView,
    tiffStart: number,
    valueOffset: number,
    count: number,
    littleEndian: boolean
  ): number[] | null {
    const offset = tiffStart + data.getUint32(valueOffset, littleEndian);
    if (offset + count * 8 > data.byteLength) return null;

    const values: number[] = [];
    for (let i = 0; i < count; i++) {
      const num = data.getUint32(offset + i * 8, littleEndian);
      const den = data.getUint32(offset + i * 8 + 4, littleEndian);
      values.push(den === 0 ? 0 : num / den);
    }
    return values;
  }
}
