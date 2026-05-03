/**
 * Secure File Storage — Rate Limiter Middleware
 * Prevents brute-force attacks and API abuse using sliding window rate limiting.
 */

import rateLimit from 'express-rate-limit';

/**
 * General API rate limiter: 100 requests per 15 minutes per IP.
 */
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,
  message: {
    success: false,
    message: 'Too many requests. Please try again later.',
  },
  standardHeaders: true,      // Return rate limit info in RateLimit-* headers
  legacyHeaders: false,
});

/**
 * Auth rate limiter: 10 attempts per 15 minutes per IP.
 * Tighter limit to prevent credential brute-forcing.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Upload rate limiter: 10 uploads per minute per IP.
 * Prevents storage abuse and DoS via large file uploads.
 */
export const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 10,
  message: {
    success: false,
    message: 'Upload rate limit exceeded. Please wait before uploading again.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Download rate limiter: 30 downloads per minute per IP.
 */
export const downloadLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 30,
  message: {
    success: false,
    message: 'Download rate limit exceeded. Please wait before downloading again.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
