/**
 * Secure File Storage — Authentication Middleware
 * Verifies JWT access tokens on protected routes.
 * Logs failed authentication attempts for security monitoring.
 */

import { Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/authService';
import { logAuditEvent } from '../services/auditService';
import { AuthenticatedRequest } from '../types';
import { getClientIp } from '../utils/helpers';
import logger from '../utils/logger';

/**
 * JWT authentication middleware.
 * Expects: Authorization: Bearer <token>
 * Attaches decoded user to req.user on success.
 * Logs failed authentication attempts.
 */
export function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // Log missing token attempt
    logAuditEvent(
      null,
      'access_denied',
      null,
      getClientIp(req),
      req.headers['user-agent'] || 'unknown',
      { reason: 'Missing or malformed authorization header', path: req.path }
    ).catch(() => {}); // Fire and forget — don't block the response

    res.status(401).json({
      success: false,
      message: 'Access denied. No token provided.',
    });
    return;
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    // Log invalid/expired token attempt
    logAuditEvent(
      null,
      'access_denied',
      null,
      getClientIp(req),
      req.headers['user-agent'] || 'unknown',
      { reason: 'Invalid or expired token', path: req.path }
    ).catch(() => {});

    logger.warn(`Authentication failed: ${(error as Error).message}`);
    res.status(401).json({
      success: false,
      message: 'Invalid or expired token.',
    });
  }
}

/**
 * Admin-only authorization middleware.
 * Must be used AFTER the authenticate middleware.
 */
export function requireAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  if (!req.user || req.user.role !== 'admin') {
    res.status(403).json({
      success: false,
      message: 'Access denied. Admin privileges required.',
    });
    return;
  }
  next();
}
