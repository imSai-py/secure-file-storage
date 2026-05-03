/**
 * Secure File Storage — File Controller
 * Handles upload, download, list, metadata, and delete operations.
 * Every operation enforces ownership-based authorization.
 * Unauthorized access returns 404 (IDOR prevention) and is audit-logged.
 */

import { Response } from 'express';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../config/database';
import { getCachedMasterKey } from '../config/redis';
import { encryptFile, decryptFile } from '../services/encryptionService';
import { uploadToS3, downloadFromS3, deleteFromS3 } from '../services/storageService';
import { logAuditEvent } from '../services/auditService';
import { validateMagicBytes } from '../middleware/fileValidator';
import { AuthenticatedRequest, FileRecord, FileMetadataResponse } from '../types';
import { generateChecksum, generateS3Key, getClientIp, sanitizeFilename } from '../utils/helpers';
import logger from '../utils/logger';

// ─── Helper: Get Master Key ─────────────────────────────

/**
 * Retrieve the user's cached master key from Redis.
 * If the key has expired (session timeout), the user must re-login.
 */
async function requireMasterKey(userId: string): Promise<Buffer | null> {
  const masterKey = await getCachedMasterKey(userId);
  if (!masterKey) {
    logger.warn(`Master key not found in cache for user ${userId}. Session may have expired.`);
  }
  return masterKey;
}

// ─── Upload File ─────────────────────────────────────────

/**
 * Upload and encrypt a file.
 * Pipeline: validate → checksum → get master key → encrypt → S3 → metadata → audit
 */
export async function uploadFile(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) { res.status(401).json({ success: false, message: 'Unauthorized' }); return; }
    if (!req.file) { res.status(400).json({ success: false, message: 'No file provided' }); return; }

    const file = req.file;
    const userId = req.user.id;

    // Validate magic bytes
    const ext = path.extname(file.originalname);
    if (!validateMagicBytes(file.buffer, ext)) {
      res.status(400).json({ success: false, message: 'File content does not match its declared type.' });
      return;
    }

    // Get cached master key
    const masterKey = await requireMasterKey(userId);
    if (!masterKey) {
      res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
      return;
    }

    const checksum = generateChecksum(file.buffer);
    const fileId = uuidv4();
    const s3Key = generateS3Key(userId, fileId);

    // Encrypt file using envelope encryption with user's master key
    const encrypted = encryptFile(file.buffer, masterKey);

    await uploadToS3(s3Key, encrypted.ciphertext, file.mimetype);

    const sanitizedName = sanitizeFilename(file.originalname);
    await query(
      `INSERT INTO files (id, owner_id, original_name, mime_type, file_size, s3_key, encrypted_dek, iv, auth_tag, checksum_sha256)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [fileId, userId, sanitizedName, file.mimetype, file.size, s3Key, encrypted.encryptedDek, encrypted.iv, encrypted.authTag, checksum]
    );

    // Audit log: successful upload
    await logAuditEvent(userId, 'upload', fileId, getClientIp(req), req.headers['user-agent'] || 'unknown', {
      originalName: sanitizedName, fileSize: file.size, mimeType: file.mimetype,
    });

    res.status(201).json({
      success: true, message: 'File uploaded and encrypted successfully',
      data: { fileId, originalName: sanitizedName, mimeType: file.mimetype, fileSize: file.size, checksum, createdAt: new Date() },
    });
  } catch (error) {
    logger.error('File upload error:', error);
    res.status(500).json({ success: false, message: 'File upload failed' });
  }
}

// ─── List User's Files ───────────────────────────────────

/** List all files owned by the authenticated user (metadata only). */
export async function listFiles(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) { res.status(401).json({ success: false, message: 'Unauthorized' }); return; }

    const files = await query<FileRecord>(
      `SELECT id, original_name, mime_type, file_size, checksum_sha256, created_at, updated_at
       FROM files WHERE owner_id = $1 ORDER BY created_at DESC`, [req.user.id]
    );

    const response: FileMetadataResponse[] = files.map((f) => ({
      id: f.id, originalName: f.original_name, mimeType: f.mime_type,
      fileSize: f.file_size, checksum: f.checksum_sha256, createdAt: f.created_at, updatedAt: f.updated_at,
    }));

    res.status(200).json({ success: true, message: 'Files retrieved successfully', data: response });
  } catch (error) {
    logger.error('List files error:', error);
    res.status(500).json({ success: false, message: 'Failed to retrieve files' });
  }
}

// ─── Get File Metadata ───────────────────────────────────

/** Get metadata for a specific file (ownership required). Returns 404 for unauthorized access. */
export async function getFileMetadata(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) { res.status(401).json({ success: false, message: 'Unauthorized' }); return; }

    const files = await query<FileRecord>(
      `SELECT id, original_name, mime_type, file_size, checksum_sha256, created_at, updated_at
       FROM files WHERE id = $1 AND owner_id = $2`, [req.params.fileId, req.user.id]
    );

    if (files.length === 0) {
      // Audit log: unauthorized access attempt (IDOR prevention — return 404, not 403)
      await logAuditEvent(req.user.id, 'access_denied', req.params.fileId, getClientIp(req),
        req.headers['user-agent'] || 'unknown', { endpoint: 'getFileMetadata' });
      res.status(404).json({ success: false, message: 'File not found' });
      return;
    }

    const f = files[0];
    res.status(200).json({
      success: true, message: 'File metadata retrieved',
      data: { id: f.id, originalName: f.original_name, mimeType: f.mime_type, fileSize: f.file_size, checksum: f.checksum_sha256, createdAt: f.created_at, updatedAt: f.updated_at },
    });
  } catch (error) {
    logger.error('Get file metadata error:', error);
    res.status(500).json({ success: false, message: 'Failed to retrieve file metadata' });
  }
}

// ─── Download (Decrypt) File ─────────────────────────────

/** Download and decrypt a file (ownership required). Verifies integrity via SHA-256 checksum. */
export async function downloadFile(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) { res.status(401).json({ success: false, message: 'Unauthorized' }); return; }

    // Gate 2: Ownership check — returns 404 for IDOR prevention
    const files = await query<FileRecord>(`SELECT * FROM files WHERE id = $1 AND owner_id = $2`, [req.params.fileId, req.user.id]);
    if (files.length === 0) {
      // Audit log: unauthorized download attempt
      await logAuditEvent(req.user.id, 'access_denied', req.params.fileId, getClientIp(req),
        req.headers['user-agent'] || 'unknown', { endpoint: 'downloadFile' });
      res.status(404).json({ success: false, message: 'File not found' });
      return;
    }

    // Get cached master key
    const masterKey = await requireMasterKey(req.user.id);
    if (!masterKey) {
      res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
      return;
    }

    const fileRecord = files[0];
    const ciphertext = await downloadFromS3(fileRecord.s3_key);

    // Decrypt file using master key + stored encrypted DEK
    const plaintext = decryptFile(
      { ciphertext, iv: fileRecord.iv, authTag: fileRecord.auth_tag, encryptedDek: fileRecord.encrypted_dek },
      masterKey
    );

    // Integrity check — SHA-256 of decrypted content must match stored checksum
    const downloadChecksum = generateChecksum(plaintext);
    if (downloadChecksum !== fileRecord.checksum_sha256) {
      logger.error(`⚠️ INTEGRITY VIOLATION: File ${req.params.fileId} checksum mismatch!`);
      res.status(500).json({ success: false, message: 'File integrity check failed. The file may have been tampered with.' });
      return;
    }

    // Audit log: successful download
    await logAuditEvent(req.user.id, 'download', req.params.fileId, getClientIp(req), req.headers['user-agent'] || 'unknown');

    res.set({
      'Content-Type': fileRecord.mime_type,
      'Content-Disposition': `attachment; filename="${fileRecord.original_name}"`,
      'Content-Length': plaintext.length.toString(),
      'X-Content-Type-Options': 'nosniff',
    });
    res.status(200).send(plaintext);
  } catch (error) {
    logger.error('File download error:', error);
    res.status(500).json({ success: false, message: 'File download failed' });
  }
}

// ─── Delete File ─────────────────────────────────────────

/** Permanently delete a file from S3 and PostgreSQL (ownership required). */
export async function deleteFile(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) { res.status(401).json({ success: false, message: 'Unauthorized' }); return; }

    const files = await query<FileRecord>(
      `SELECT id, s3_key, original_name FROM files WHERE id = $1 AND owner_id = $2`, [req.params.fileId, req.user.id]
    );
    if (files.length === 0) {
      // Audit log: unauthorized delete attempt
      await logAuditEvent(req.user.id, 'access_denied', req.params.fileId, getClientIp(req),
        req.headers['user-agent'] || 'unknown', { endpoint: 'deleteFile' });
      res.status(404).json({ success: false, message: 'File not found' });
      return;
    }

    await deleteFromS3(files[0].s3_key);
    await query('DELETE FROM files WHERE id = $1', [req.params.fileId]);

    // Audit log: successful deletion
    await logAuditEvent(req.user.id, 'delete', req.params.fileId, getClientIp(req),
      req.headers['user-agent'] || 'unknown', { deletedFile: files[0].original_name });

    res.status(200).json({ success: true, message: 'File deleted successfully' });
  } catch (error) {
    logger.error('File delete error:', error);
    res.status(500).json({ success: false, message: 'File deletion failed' });
  }
}
