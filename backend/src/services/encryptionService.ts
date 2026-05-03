/**
 * Secure File Storage — Encryption Service
 * Implements AES-256-GCM envelope encryption with PBKDF2 key derivation.
 *
 * SECURITY ARCHITECTURE:
 * 1. Each user has a master key, encrypted with a key derived from their password (PBKDF2)
 * 2. Each file gets a unique Data Encryption Key (DEK)
 * 3. The DEK encrypts the file using AES-256-GCM (AEAD)
 * 4. The DEK itself is encrypted by the user's master key
 * 5. The plaintext DEK and master key are NEVER persisted — only in memory during operations
 */

import crypto from 'crypto';
import { EncryptionResult, DecryptionInput } from '../types';
import logger from '../utils/logger';

// ─── Constants ───────────────────────────────────────────

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;          // 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH = 16;    // 128-bit authentication tag
const KEY_LENGTH = 32;         // 256-bit keys
const SALT_LENGTH = 32;        // 256-bit salt
const PBKDF2_ITERATIONS = 100000;  // OWASP recommended minimum
const PBKDF2_DIGEST = 'sha512';

// ─── PBKDF2 Key Derivation ──────────────────────────────

/**
 * Derive a 256-bit key from a password using PBKDF2-SHA512.
 * The high iteration count (100,000) makes brute-force infeasible.
 *
 * @param password - User's plaintext password
 * @param salt - Random salt (unique per user)
 * @returns 256-bit derived key
 */
export function deriveKeyFromPassword(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, PBKDF2_DIGEST);
}

// ─── User Master Key Management ─────────────────────────

/**
 * Generate a new master key for a user and encrypt it with their password-derived key.
 * Called once during user registration.
 *
 * Flow:
 * 1. Generate random salt for PBKDF2
 * 2. Derive a Key Encryption Key (KEK) from password + salt
 * 3. Generate a random 256-bit master key
 * 4. Encrypt the master key with the KEK using AES-256-GCM
 * 5. Zero all sensitive material from memory
 *
 * @param password - User's plaintext password (available only during registration)
 * @returns Salt, encrypted master key, IV, and auth tag for storage in DB
 */
export function generateUserMasterKey(password: string): {
  keySalt: Buffer;
  encryptedMasterKey: Buffer;
  mkIv: Buffer;
  mkAuthTag: Buffer;
} {
  // Step 1: Generate random salt
  const salt = crypto.randomBytes(SALT_LENGTH);

  // Step 2: Derive KEK from password
  const kek = deriveKeyFromPassword(password, salt);

  // Step 3: Generate random master key
  const masterKey = crypto.randomBytes(KEY_LENGTH);

  // Step 4: Encrypt master key with KEK
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encryptedMasterKey = Buffer.concat([cipher.update(masterKey), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Step 5: Zero sensitive material
  masterKey.fill(0);
  kek.fill(0);

  logger.debug('Generated and encrypted new user master key.');

  return {
    keySalt: salt,
    encryptedMasterKey,
    mkIv: iv,
    mkAuthTag: authTag,
  };
}

/**
 * Decrypt a user's master key using their password.
 * Called during login to recover the master key for the session.
 *
 * @param password - User's plaintext password
 * @param salt - Stored PBKDF2 salt
 * @param encryptedMasterKey - Stored encrypted master key
 * @param iv - Stored IV
 * @param authTag - Stored GCM auth tag
 * @returns Decrypted 256-bit master key
 * @throws If password is wrong (GCM auth tag verification fails)
 */
export function decryptUserMasterKey(
  password: string,
  salt: Buffer,
  encryptedMasterKey: Buffer,
  iv: Buffer,
  authTag: Buffer
): Buffer {
  // Derive KEK from password + stored salt
  const kek = deriveKeyFromPassword(password, salt);

  // Decrypt master key
  const decipher = crypto.createDecipheriv(ALGORITHM, kek, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  const masterKey = Buffer.concat([decipher.update(encryptedMasterKey), decipher.final()]);

  // Zero KEK
  kek.fill(0);

  return masterKey;
}

// ─── File Encryption ─────────────────────────────────────

/**
 * Encrypt file data using envelope encryption with the user's master key.
 *
 * Flow:
 * 1. Generate a random 256-bit DEK
 * 2. Encrypt the file with the DEK using AES-256-GCM
 * 3. Encrypt the DEK with the user's master key using AES-256-GCM
 * 4. Pack the encrypted DEK + its IV + its auth tag together
 * 5. Zero the plaintext DEK from memory
 *
 * @param fileBuffer - Raw file content to encrypt
 * @param masterKey - User's decrypted master key (from Redis cache)
 * @returns Ciphertext, IV, auth tag, and encrypted DEK bundle
 */
export function encryptFile(fileBuffer: Buffer, masterKey: Buffer): EncryptionResult {
  logger.debug('Starting file encryption with envelope encryption...');

  // Step 1: Generate random DEK
  const dek = crypto.randomBytes(KEY_LENGTH);

  // Step 2: Encrypt file with DEK
  const fileIv = crypto.randomBytes(IV_LENGTH);
  const fileCipher = crypto.createCipheriv(ALGORITHM, dek, fileIv, { authTagLength: AUTH_TAG_LENGTH });
  const ciphertext = Buffer.concat([fileCipher.update(fileBuffer), fileCipher.final()]);
  const fileAuthTag = fileCipher.getAuthTag();

  // Step 3: Encrypt DEK with master key
  const dekIv = crypto.randomBytes(IV_LENGTH);
  const dekCipher = crypto.createCipheriv(ALGORITHM, masterKey, dekIv, { authTagLength: AUTH_TAG_LENGTH });
  const encryptedDekData = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
  const dekAuthTag = dekCipher.getAuthTag();

  // Step 4: Pack encrypted DEK bundle: [dekIv (12) | dekAuthTag (16) | encryptedDekData (32)]
  const encryptedDek = Buffer.concat([dekIv, dekAuthTag, encryptedDekData]);

  // Step 5: Zero plaintext DEK
  dek.fill(0);

  logger.debug('File encryption completed successfully.');

  return {
    ciphertext,
    iv: fileIv,
    authTag: fileAuthTag,
    encryptedDek,
  };
}

// ─── File Decryption ─────────────────────────────────────

/**
 * Decrypt file data using the stored encrypted DEK and the user's master key.
 *
 * Flow:
 * 1. Unpack the encrypted DEK bundle (IV + auth tag + ciphertext)
 * 2. Decrypt the DEK using the user's master key
 * 3. Decrypt the file using the recovered DEK
 * 4. GCM automatically verifies integrity — if tampered, decryption FAILS
 * 5. Zero the plaintext DEK
 *
 * @param input - Ciphertext, IV, auth tag, and encrypted DEK bundle
 * @param masterKey - User's decrypted master key (from Redis cache)
 * @returns Decrypted plaintext file content
 */
export function decryptFile(input: DecryptionInput, masterKey: Buffer): Buffer {
  logger.debug('Starting file decryption...');

  // Step 1: Unpack encrypted DEK bundle
  const dekIv = input.encryptedDek.subarray(0, IV_LENGTH);
  const dekAuthTag = input.encryptedDek.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const encryptedDekData = input.encryptedDek.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

  // Step 2: Decrypt DEK with master key
  const dekDecipher = crypto.createDecipheriv(ALGORITHM, masterKey, dekIv, { authTagLength: AUTH_TAG_LENGTH });
  dekDecipher.setAuthTag(dekAuthTag);
  const dek = Buffer.concat([dekDecipher.update(encryptedDekData), dekDecipher.final()]);

  // Step 3: Decrypt file with DEK
  const fileDecipher = crypto.createDecipheriv(ALGORITHM, dek, input.iv, { authTagLength: AUTH_TAG_LENGTH });
  fileDecipher.setAuthTag(input.authTag);
  const plaintext = Buffer.concat([fileDecipher.update(input.ciphertext), fileDecipher.final()]);

  // Step 4: Zero DEK
  dek.fill(0);

  logger.debug('File decryption completed successfully.');

  return plaintext;
}
