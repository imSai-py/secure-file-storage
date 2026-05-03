/**
 * Secure File Storage — Authentication Service
 * Handles user registration, login, token generation, and token refresh.
 * Uses bcrypt for password hashing, PBKDF2 for encryption key derivation,
 * and JWT (RS256-style HMAC) for stateless auth.
 */

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../config/database';
import { cacheMasterKey } from '../config/redis';
import { generateUserMasterKey, decryptUserMasterKey } from './encryptionService';
import config from '../config';
import { User, UserPayload, TokenPair, RegisterInput, LoginInput } from '../types';
import logger from '../utils/logger';

// ─── Constants ───────────────────────────────────────────

const BCRYPT_ROUNDS = 12;

// ─── Register User ───────────────────────────────────────

/**
 * Register a new user with email and password.
 *
 * Security steps:
 * 1. Check for existing email
 * 2. Hash password with bcrypt (cost 12)
 * 3. Generate a user master key, encrypted with a PBKDF2-derived key from the password
 * 4. Store everything in the users table
 *
 * @param input - Email and plaintext password
 * @returns The created user's ID and email
 */
export async function registerUser(input: RegisterInput): Promise<{ id: string; email: string }> {
  // Check if email already exists
  const existing = await query<User>(
    'SELECT id FROM users WHERE email = $1',
    [input.email.toLowerCase()]
  );

  if (existing.length > 0) {
    throw new Error('Email already registered');
  }

  // Hash password with bcrypt
  const hashedPassword = await bcrypt.hash(input.password, BCRYPT_ROUNDS);

  // Generate master key encrypted with password-derived key
  const keyData = generateUserMasterKey(input.password);

  // Insert user with key management data
  const result = await query<User>(
    `INSERT INTO users (email, password, key_salt, encrypted_master_key, mk_iv, mk_auth_tag)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, email`,
    [
      input.email.toLowerCase(),
      hashedPassword,
      keyData.keySalt,
      keyData.encryptedMasterKey,
      keyData.mkIv,
      keyData.mkAuthTag,
    ]
  );

  logger.info(`✅ New user registered: ${result[0].email}`);
  return { id: result[0].id, email: result[0].email };
}

// ─── Login User ──────────────────────────────────────────

/**
 * Authenticate a user with email and password.
 * On success, decrypts the user's master key and caches it in Redis.
 *
 * @param input - Email and plaintext password
 * @returns JWT token pair and user payload
 */
export async function loginUser(input: LoginInput): Promise<{ user: UserPayload; tokens: TokenPair }> {
  // Find user by email (include key management fields)
  const users = await query<User>(
    `SELECT id, email, password, role, key_salt, encrypted_master_key, mk_iv, mk_auth_tag
     FROM users WHERE email = $1`,
    [input.email.toLowerCase()]
  );

  if (users.length === 0) {
    throw new Error('Invalid email or password');
  }

  const user = users[0];

  // Verify password with bcrypt
  const isValid = await bcrypt.compare(input.password, user.password);
  if (!isValid) {
    throw new Error('Invalid email or password');
  }

  // Decrypt the user's master key using their password
  const masterKey = decryptUserMasterKey(
    input.password,
    user.key_salt,
    user.encrypted_master_key,
    user.mk_iv,
    user.mk_auth_tag
  );

  // Cache the decrypted master key in Redis (TTL = 15 minutes)
  await cacheMasterKey(user.id, masterKey);

  // Zero the master key from local memory
  masterKey.fill(0);

  // Generate JWT tokens
  const payload: UserPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
  };

  const tokens = generateTokenPair(payload);

  logger.info(`✅ User logged in: ${user.email}`);
  return { user: payload, tokens };
}

// ─── Token Generation ────────────────────────────────────

/**
 * Generate a JWT access/refresh token pair.
 */
export function generateTokenPair(payload: UserPayload): TokenPair {
  const accessToken = jwt.sign(payload, config.jwt.accessSecret, {
    expiresIn: config.jwt.accessExpiry,
    jwtid: uuidv4(),
  });

  const refreshToken = jwt.sign(
    { id: payload.id },
    config.jwt.refreshSecret,
    {
      expiresIn: config.jwt.refreshExpiry,
      jwtid: uuidv4(),
    }
  );

  return { accessToken, refreshToken };
}

// ─── Verify Access Token ─────────────────────────────────

/**
 * Verify and decode a JWT access token.
 */
export function verifyAccessToken(token: string): UserPayload {
  return jwt.verify(token, config.jwt.accessSecret) as UserPayload;
}

// ─── Verify Refresh Token ────────────────────────────────

/**
 * Verify and decode a JWT refresh token.
 */
export function verifyRefreshToken(token: string): { id: string } {
  return jwt.verify(token, config.jwt.refreshSecret) as { id: string };
}

// ─── Refresh Token Flow ──────────────────────────────────

/**
 * Generate a new token pair using a valid refresh token.
 * Note: The master key in Redis TTL is refreshed when accessed,
 * so the user's session stays alive as long as they're active.
 */
export async function refreshTokens(refreshToken: string): Promise<TokenPair> {
  const decoded = verifyRefreshToken(refreshToken);

  // Fetch current user data (role may have changed)
  const users = await query<User>(
    'SELECT id, email, role FROM users WHERE id = $1',
    [decoded.id]
  );

  if (users.length === 0) {
    throw new Error('User not found');
  }

  const user = users[0];
  const payload: UserPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
  };

  return generateTokenPair(payload);
}
