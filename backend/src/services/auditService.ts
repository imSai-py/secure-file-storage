/**
 * Secure File Storage — Audit Service
 * Logs all security-relevant operations for compliance and forensics.
 * Every file operation creates an immutable audit trail entry.
 */

import { query } from '../config/database';
import { AuditAction, AuditLogEntry } from '../types';
import logger from '../utils/logger';

/**
 * Log an auditable event to the database.
 *
 * @param userId - The user who performed the action
 * @param action - The type of action (upload, download, delete, etc.)
 * @param fileId - The file involved (null for auth events)
 * @param ipAddress - Client IP address
 * @param userAgent - Client User-Agent header
 * @param metadata - Additional contextual data
 */
export async function logAuditEvent(
  userId: string | null,
  action: AuditAction,
  fileId: string | null,
  ipAddress: string,
  userAgent: string,
  metadata: Record<string, unknown> = {}
): Promise<void> {
  try {
    await query(
      `INSERT INTO audit_logs (user_id, action, file_id, ip_address, user_agent, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, action, fileId, ipAddress, userAgent, JSON.stringify(metadata)]
    );
    logger.debug(`📝 Audit log: ${action} by user ${userId}${fileId ? ` on file ${fileId}` : ''}`);
  } catch (error) {
    // Audit logging should never crash the main operation — log the error and continue
    logger.error('Failed to write audit log:', error);
  }
}

/**
 * Retrieve audit logs for a specific user.
 *
 * @param userId - The user to fetch logs for
 * @param limit - Maximum number of entries to return
 * @param offset - Pagination offset
 */
export async function getUserAuditLogs(
  userId: string,
  limit: number = 50,
  offset: number = 0
): Promise<AuditLogEntry[]> {
  return query<AuditLogEntry>(
    `SELECT * FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
    [userId, limit, offset]
  );
}

/**
 * Retrieve audit logs for a specific file.
 *
 * @param fileId - The file to fetch logs for
 */
export async function getFileAuditLogs(fileId: string): Promise<AuditLogEntry[]> {
  return query<AuditLogEntry>(
    `SELECT * FROM audit_logs WHERE file_id = $1 ORDER BY created_at DESC`,
    [fileId]
  );
}
