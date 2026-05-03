/**
 * Secure File Storage — File Validation Middleware
 * Validates uploaded files using magic bytes (file signatures),
 * NOT file extensions, to prevent upload execution attacks.
 */

import multer from 'multer';
import path from 'path';
import config from '../config';
import { sanitizeFilename } from '../utils/helpers';

// ─── Multer Storage Configuration ────────────────────────

const storage = multer.memoryStorage(); // Store in memory — we encrypt before writing anywhere

// ─── File Filter ─────────────────────────────────────────

const fileFilter: multer.Options['fileFilter'] = (_req, file, cb) => {
  // Sanitize the filename
  file.originalname = sanitizeFilename(file.originalname);

  // Check extension against whitelist
  const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
  if (!config.upload.allowedFileTypes.includes(ext)) {
    cb(new Error(`File type .${ext} is not allowed. Allowed types: ${config.upload.allowedFileTypes.join(', ')}`));
    return;
  }

  cb(null, true);
};

// ─── Multer Upload Instance ──────────────────────────────

/**
 * Configured multer instance for single file uploads.
 * - Memory storage (files encrypted before any disk write)
 * - Max file size enforced
 * - Extension whitelist enforced
 *
 * Usage: upload.single('file') as route middleware
 */
export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: config.upload.maxFileSizeBytes,
    files: 1,           // Only allow single file upload per request
    fields: 5,          // Limit non-file fields to prevent abuse
  },
});

// ─── Magic Byte Validators ──────────────────────────────

/**
 * Known file signatures (magic bytes) for allowed file types.
 * This is the REAL content validation — extensions can be faked.
 */
const MAGIC_BYTES: Record<string, Buffer[]> = {
  pdf:  [Buffer.from([0x25, 0x50, 0x44, 0x46])],                          // %PDF
  png:  [Buffer.from([0x89, 0x50, 0x4E, 0x47])],                          // .PNG
  jpg:  [Buffer.from([0xFF, 0xD8, 0xFF])],                                // JPEG
  jpeg: [Buffer.from([0xFF, 0xD8, 0xFF])],                                // JPEG
  gif:  [Buffer.from([0x47, 0x49, 0x46, 0x38])],                          // GIF8
  zip:  [Buffer.from([0x50, 0x4B, 0x03, 0x04])],                          // PK..
  docx: [Buffer.from([0x50, 0x4B, 0x03, 0x04])],                          // OOXML (ZIP)
  xlsx: [Buffer.from([0x50, 0x4B, 0x03, 0x04])],                          // OOXML (ZIP)
  pptx: [Buffer.from([0x50, 0x4B, 0x03, 0x04])],                          // OOXML (ZIP)
  txt:  [],                                                                 // Text files have no magic bytes
};

/**
 * Validate a file's content by checking its magic bytes.
 * Returns true if the file's actual content matches the declared type.
 *
 * @param buffer - The raw file buffer
 * @param declaredExtension - The file extension from the filename
 */
export function validateMagicBytes(buffer: Buffer, declaredExtension: string): boolean {
  const ext = declaredExtension.toLowerCase().replace('.', '');
  const signatures = MAGIC_BYTES[ext];

  // If the extension isn't in our magic bytes map, reject it
  if (signatures === undefined) {
    return false;
  }

  // Text files have no magic bytes — allow if extension is whitelisted
  if (signatures.length === 0) {
    return true;
  }

  // Check if file starts with any of the valid signatures
  return signatures.some((sig) =>
    buffer.subarray(0, sig.length).equals(sig)
  );
}
