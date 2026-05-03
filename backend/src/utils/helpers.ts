/**
 * Secure File Storage — Utility Helpers
 * Shared helper functions used across the application.
 */

import crypto from 'crypto';

/**
 * Generate a SHA-256 checksum of a buffer.
 * Used for file integrity verification.
 */
export function generateChecksum(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Sanitize a filename to prevent path traversal and injection.
 * Strips directory components, null bytes, and dangerous characters.
 */
export function sanitizeFilename(filename: string): string {
  return filename
    .replace(/\0/g, '')              // Remove null bytes
    .replace(/\.\./g, '')            // Remove directory traversal
    .replace(/[/\\]/g, '')           // Remove path separators
    .replace(/[<>:"|?*]/g, '_')      // Replace dangerous chars
    .trim()
    .substring(0, 255);              // Limit length
}

/**
 * Extract the file extension from a filename.
 */
export function getFileExtension(filename: string): string {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

/**
 * Get the client's real IP address from the request,
 * accounting for reverse proxies (X-Forwarded-For).
 */
export function getClientIp(req: { ip?: string; headers: Record<string, string | string[] | undefined> }): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || '0.0.0.0';
}

/**
 * Generate a unique S3 object key for a file.
 * Format: {userId}/{uuid}.enc
 */
export function generateS3Key(userId: string, fileId: string): string {
  return `${userId}/${fileId}.enc`;
}
