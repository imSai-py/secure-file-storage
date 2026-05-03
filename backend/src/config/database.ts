/**
 * Secure File Storage — PostgreSQL Database Connection
 * Uses connection pooling for efficient query handling.
 * Includes the migration script to create all required tables.
 */

import { Pool } from 'pg';
import config from './index';
import { logger } from '../utils/logger';

// ─── Connection Pool ─────────────────────────────────────

export const pool = new Pool({
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.user,
  password: config.database.password,
  max: 20,                    // Maximum connections in pool
  idleTimeoutMillis: 30000,   // Close idle connections after 30s
  connectionTimeoutMillis: 5000,
  ssl: config.server.isProduction ? { rejectUnauthorized: true } : false,
});

// ─── Connection Health Check ─────────────────────────────

export async function testDatabaseConnection(): Promise<void> {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    logger.info(`✅ PostgreSQL connected: ${result.rows[0].now}`);
    client.release();
  } catch (error) {
    logger.error('❌ PostgreSQL connection failed:', error);
    throw error;
  }
}

// ─── Query Helper ────────────────────────────────────────

export async function query<T>(text: string, params?: unknown[]): Promise<T[]> {
  const result = await pool.query(text, params);
  return result.rows as T[];
}

export default pool;
