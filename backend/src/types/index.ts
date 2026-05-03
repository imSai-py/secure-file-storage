/**
 * Secure File Storage — Type Definitions
 * Central type definitions for the entire backend application.
 */

import { Request } from 'express';

// ─── User Types ───────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  password: string;
  mfa_secret: string | null;
  role: UserRole;
  // Key management — master key encrypted with PBKDF2-derived key
  key_salt: Buffer;
  encrypted_master_key: Buffer;
  mk_iv: Buffer;
  mk_auth_tag: Buffer;
  created_at: Date;
  updated_at: Date;
}

export type UserRole = 'user' | 'admin';

export interface UserPayload {
  id: string;
  email: string;
  role: UserRole;
}

export interface AuthenticatedRequest extends Request {
  user?: UserPayload;
}

// ─── File Types ───────────────────────────────────────────

export interface FileRecord {
  id: string;
  owner_id: string;
  original_name: string;
  mime_type: string;
  file_size: number;
  s3_key: string;
  encrypted_dek: Buffer;
  iv: Buffer;
  auth_tag: Buffer;
  checksum_sha256: string;
  created_at: Date;
  updated_at: Date;
}

export interface FileMetadataResponse {
  id: string;
  originalName: string;
  mimeType: string;
  fileSize: number;
  checksum: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface FileUploadResult {
  fileId: string;
  originalName: string;
  mimeType: string;
  fileSize: number;
  checksum: string;
  createdAt: Date;
}

// ─── File Permission Types ────────────────────────────────

export type PermissionLevel = 'viewer' | 'editor';

export interface FilePermission {
  id: string;
  file_id: string;
  user_id: string;
  permission: PermissionLevel;
  granted_by: string;
  expires_at: Date | null;
  created_at: Date;
}

// ─── Audit Log Types ─────────────────────────────────────

export type AuditAction = 'upload' | 'download' | 'delete' | 'share' | 'login' | 'login_failed' | 'register' | 'logout' | 'access_denied';

export interface AuditLogEntry {
  id: string;
  user_id: string;
  action: AuditAction;
  file_id: string | null;
  ip_address: string;
  user_agent: string;
  metadata: Record<string, unknown>;
  created_at: Date;
}

// ─── Encryption Types ─────────────────────────────────────

export interface EncryptionResult {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  encryptedDek: Buffer;
}

export interface DecryptionInput {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  encryptedDek: Buffer;
}

// ─── Auth Types ───────────────────────────────────────────

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface RegisterInput {
  email: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

// ─── API Response Types ───────────────────────────────────

export interface ApiResponse<T = unknown> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
}
