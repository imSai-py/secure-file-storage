/**
 * Secure File Storage — Database Migration
 * Creates all required tables if they don't exist.
 * Run with: npm run db:migrate
 */

import pool from './database';
import { logger } from '../utils/logger';

const MIGRATION_SQL = `
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Users Table ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email                 VARCHAR(255) UNIQUE NOT NULL,
    password              VARCHAR(255) NOT NULL,
    mfa_secret            VARCHAR(255),
    role                  VARCHAR(10) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    -- Key management: master key encrypted with PBKDF2-derived key from user password
    key_salt              BYTEA NOT NULL,           -- PBKDF2 salt for key derivation
    encrypted_master_key  BYTEA NOT NULL,           -- User master key encrypted with derived KEK
    mk_iv                 BYTEA NOT NULL,           -- IV used to encrypt the master key
    mk_auth_tag           BYTEA NOT NULL,           -- GCM auth tag for master key encryption
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── Files Metadata Table ────────────────────────────────
CREATE TABLE IF NOT EXISTS files (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name   VARCHAR(255) NOT NULL,
    mime_type       VARCHAR(100) NOT NULL,
    file_size       BIGINT NOT NULL,
    s3_key          VARCHAR(500) NOT NULL,
    encrypted_dek   BYTEA NOT NULL,
    iv              BYTEA NOT NULL,
    auth_tag        BYTEA NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── File Permissions Table (reserved for future file sharing) ──
CREATE TABLE IF NOT EXISTS file_permissions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission      VARCHAR(10) NOT NULL DEFAULT 'viewer' CHECK (permission IN ('viewer', 'editor')),
    granted_by      UUID REFERENCES users(id),
    expires_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(file_id, user_id)
);

-- ─── Audit Logs Table ────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID REFERENCES users(id),
    action          VARCHAR(50) NOT NULL,
    file_id         UUID,
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── Indexes for Performance ─────────────────────────────
CREATE INDEX IF NOT EXISTS idx_files_owner_id ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_file_permissions_file_id ON file_permissions(file_id);
CREATE INDEX IF NOT EXISTS idx_file_permissions_user_id ON file_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_file_id ON audit_logs(file_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
`;

async function migrate(): Promise<void> {
  logger.info('🔄 Running database migrations...');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(MIGRATION_SQL);
    await client.query('COMMIT');
    logger.info('✅ Database migration completed successfully.');
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('❌ Migration failed:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

// Run if called directly
migrate()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
