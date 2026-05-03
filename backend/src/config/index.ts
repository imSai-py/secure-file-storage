/**
 * Secure File Storage — Central Configuration
 * Loads and validates all environment variables using Zod schemas.
 * Fails fast on startup if any required config is missing.
 */

import dotenv from 'dotenv';
import { z } from 'zod';
import path from 'path';

// Load .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// ─── Configuration Schema ────────────────────────────────

const envSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().default('5000').transform(Number),

  // PostgreSQL
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.string().default('5432').transform(Number),
  DB_NAME: z.string().default('secure_file_storage'),
  DB_USER: z.string().default('postgres'),
  DB_PASSWORD: z.string(),

  // Redis
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().default('6379').transform(Number),
  REDIS_PASSWORD: z.string().default(''),

  // AWS S3
  AWS_REGION: z.string().default('ap-south-1'),
  AWS_ACCESS_KEY_ID: z.string(),
  AWS_SECRET_ACCESS_KEY: z.string(),
  S3_BUCKET_NAME: z.string(),

  // Note: KMS removed — keys derived from user credentials via PBKDF2

  // JWT
  JWT_ACCESS_SECRET: z.string(),
  JWT_REFRESH_SECRET: z.string(),
  JWT_ACCESS_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),

  // File Upload
  MAX_FILE_SIZE_MB: z.string().default('50').transform(Number),
  ALLOWED_FILE_TYPES: z.string().default('pdf,docx,xlsx,pptx,txt,png,jpg,jpeg,gif,zip'),

  // CORS
  FRONTEND_URL: z.string().default('http://localhost:5173'),
});

// ─── Parse and Validate ──────────────────────────────────

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid environment configuration:');
  console.error(parsed.error.format());
  process.exit(1);
}

const env = parsed.data;

// ─── Export Structured Config ────────────────────────────

export const config = {
  server: {
    nodeEnv: env.NODE_ENV,
    port: env.PORT,
    isProduction: env.NODE_ENV === 'production',
  },
  database: {
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
  },
  redis: {
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
  },
  aws: {
    region: env.AWS_REGION,
    accessKeyId: env.AWS_ACCESS_KEY_ID,
    secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
    s3BucketName: env.S3_BUCKET_NAME,
  },
  jwt: {
    accessSecret: env.JWT_ACCESS_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    accessExpiry: env.JWT_ACCESS_EXPIRY,
    refreshExpiry: env.JWT_REFRESH_EXPIRY,
  },
  upload: {
    maxFileSizeMb: env.MAX_FILE_SIZE_MB,
    maxFileSizeBytes: env.MAX_FILE_SIZE_MB * 1024 * 1024,
    allowedFileTypes: env.ALLOWED_FILE_TYPES.split(',').map((t) => t.trim()),
  },
  cors: {
    frontendUrl: env.FRONTEND_URL,
  },
} as const;

export default config;
