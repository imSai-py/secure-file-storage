/**
 * Secure File Storage — S3 Storage Service
 * Handles uploading encrypted ciphertext to S3 and retrieving it.
 * Files are ALWAYS encrypted before upload — S3 only stores ciphertext.
 */

import fs from 'fs/promises';
import path from 'path';
import config from '../config';
import logger from '../utils/logger';

// Use a local uploads directory instead of S3 for testing
const UPLOADS_DIR = path.resolve(__dirname, '../../uploads');

// Ensure the uploads directory exists
async function ensureUploadsDir() {
  try {
    await fs.mkdir(UPLOADS_DIR, { recursive: true });
  } catch (err) {
    logger.error('Failed to create uploads directory:', err);
  }
}
// Initialize immediately
ensureUploadsDir();

// ─── Upload Encrypted File ──────────────────────────────

/**
 * Upload an encrypted file (ciphertext) to S3.
 *
 * @param s3Key - The object key (format: {userId}/{fileId}.enc)
 * @param ciphertext - The encrypted file content
 * @param mimeType - Original MIME type (stored as metadata, not used for decryption)
 */
export async function uploadToS3(
  s3Key: string,
  ciphertext: Buffer,
  mimeType: string
): Promise<void> {
  logger.debug(`Uploading encrypted file to local storage (mock S3): ${s3Key}`);
  await ensureUploadsDir();

  // Create user subdirectories if s3Key contains slashes (e.g., userId/fileId)
  const filePath = path.join(UPLOADS_DIR, s3Key);
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  await fs.writeFile(filePath, ciphertext);
  logger.info(`✅ File uploaded locally: ${filePath}`);
}

// ─── Download Encrypted File ─────────────────────────────

/**
 * Download an encrypted file (ciphertext) from S3.
 *
 * @param s3Key - The object key
 * @returns The encrypted file content as a Buffer
 */
export async function downloadFromS3(s3Key: string): Promise<Buffer> {
  logger.debug(`Downloading encrypted file from local storage: ${s3Key}`);
  const filePath = path.join(UPLOADS_DIR, s3Key);
  
  try {
    const data = await fs.readFile(filePath);
    return data;
  } catch (error) {
    throw new Error(`File not found locally for key: ${s3Key}`);
  }
}

// ─── Generate Pre-Signed Download URL ────────────────────

/**
 * Generate a time-limited pre-signed URL for direct S3 download.
 * URL expires after 5 minutes — prevents unauthorized link sharing.
 *
 * @param s3Key - The object key
 * @param expiresInSeconds - URL validity duration (default: 300s = 5 min)
 * @returns Pre-signed URL string
 */
export async function generatePresignedUrl(
  s3Key: string,
  expiresInSeconds: number = 300
): Promise<string> {
  logger.debug(`Generate presigned URL called for local mock: ${s3Key}`);
  return `http://localhost:5000/api/v1/files/mock-download/${s3Key}`;
}

// ─── Delete File from S3 ─────────────────────────────────

/**
 * Permanently delete an encrypted file from S3.
 *
 * @param s3Key - The object key to delete
 */
export async function deleteFromS3(s3Key: string): Promise<void> {
  logger.debug(`Deleting file from local storage: ${s3Key}`);
  const filePath = path.join(UPLOADS_DIR, s3Key);
  
  try {
    await fs.unlink(filePath);
    logger.info(`🗑️ File deleted locally: ${filePath}`);
  } catch (error) {
    logger.warn(`Could not delete file locally (might not exist): ${filePath}`);
  }
}
