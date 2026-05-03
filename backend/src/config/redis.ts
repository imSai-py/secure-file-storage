/**
 * Secure File Storage — Redis Client
 * Used for caching decrypted user master keys during active sessions.
 * Master keys are stored with a TTL matching the access token expiry.
 */

import Redis from 'ioredis';
import config from './index';
import { logger } from '../utils/logger';

let redisClient: Redis;

/**
 * Initialize Redis connection.
 * Falls back to an in-memory Map if Redis is unavailable (development only).
 */
export function getRedisClient(): Redis {
  if (!redisClient) {
    redisClient = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password || undefined,
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => {
        if (times > 3) {
          logger.error('Redis connection failed after 3 retries');
          return null; // Stop retrying
        }
        return Math.min(times * 200, 2000);
      },
    });

    redisClient.on('connect', () => logger.info('✅ Redis connected'));
    redisClient.on('error', (err) => logger.error('❌ Redis error:', err));
  }
  return redisClient;
}

// ─── Master Key Cache Operations ─────────────────────────

const MASTER_KEY_PREFIX = 'user_master_key:';
const MASTER_KEY_TTL = 900; // 15 minutes (matches access token expiry)

// In-memory fallback for local testing without Redis
const inMemoryCache = new Map<string, { value: string, expiresAt: number }>();

/**
 * Cache a user's decrypted master key.
 */
export async function cacheMasterKey(userId: string, masterKey: Buffer): Promise<void> {
  try {
    const redis = getRedisClient();
    if (redis.status === 'ready') {
      await redis.set(
        `${MASTER_KEY_PREFIX}${userId}`,
        masterKey.toString('hex'),
        'EX',
        MASTER_KEY_TTL
      );
      return;
    }
  } catch (err) {
    // Fallback to in-memory
  }
  
  inMemoryCache.set(`${MASTER_KEY_PREFIX}${userId}`, {
    value: masterKey.toString('hex'),
    expiresAt: Date.now() + MASTER_KEY_TTL * 1000,
  });
}

/**
 * Retrieve a cached master key.
 */
export async function getCachedMasterKey(userId: string): Promise<Buffer | null> {
  try {
    const redis = getRedisClient();
    if (redis.status === 'ready') {
      const hex = await redis.get(`${MASTER_KEY_PREFIX}${userId}`);
      if (!hex) return null;
      await redis.expire(`${MASTER_KEY_PREFIX}${userId}`, MASTER_KEY_TTL);
      return Buffer.from(hex, 'hex');
    }
  } catch (err) {
    // Fallback
  }

  const cached = inMemoryCache.get(`${MASTER_KEY_PREFIX}${userId}`);
  if (!cached) return null;
  if (Date.now() > cached.expiresAt) {
    inMemoryCache.delete(`${MASTER_KEY_PREFIX}${userId}`);
    return null;
  }
  cached.expiresAt = Date.now() + MASTER_KEY_TTL * 1000;
  return Buffer.from(cached.value, 'hex');
}

/**
 * Remove a cached master key (called on logout).
 */
export async function removeCachedMasterKey(userId: string): Promise<void> {
  try {
    const redis = getRedisClient();
    if (redis.status === 'ready') {
      await redis.del(`${MASTER_KEY_PREFIX}${userId}`);
      return;
    }
  } catch (err) {
    // Fallback
  }
  
  inMemoryCache.delete(`${MASTER_KEY_PREFIX}${userId}`);
}

export default getRedisClient;
