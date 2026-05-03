/**
 * Secure File Storage — Auth Controller
 * Handles HTTP request/response for authentication endpoints.
 * Logs failed login attempts and unauthorized access for security monitoring.
 */

import { Request, Response } from 'express';
import { z } from 'zod';
import { registerUser, loginUser, refreshTokens } from '../services/authService';
import { logAuditEvent } from '../services/auditService';
import { removeCachedMasterKey } from '../config/redis';
import { AuthenticatedRequest } from '../types';
import { getClientIp } from '../utils/helpers';
import logger from '../utils/logger';

// ─── Validation Schemas ──────────────────────────────────

const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

// ─── Register ────────────────────────────────────────────

export async function register(req: Request, res: Response): Promise<void> {
  try {
    // Validate input
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        success: false,
        message: 'Validation failed',
        error: parsed.error.errors.map((e) => e.message).join(', '),
      });
      return;
    }

    const user = await registerUser(parsed.data);

    // Audit log
    await logAuditEvent(
      user.id,
      'register',
      null,
      getClientIp(req),
      req.headers['user-agent'] || 'unknown',
      { email: user.email }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: { id: user.id, email: user.email },
    });
  } catch (error) {
    const message = (error as Error).message;

    if (message === 'Email already registered') {
      res.status(409).json({ success: false, message });
      return;
    }

    logger.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
}

// ─── Login ───────────────────────────────────────────────

export async function login(req: Request, res: Response): Promise<void> {
  try {
    // Validate input
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        success: false,
        message: 'Validation failed',
        error: parsed.error.errors.map((e) => e.message).join(', '),
      });
      return;
    }

    const { user, tokens } = await loginUser(parsed.data);

    // Audit log — successful login
    await logAuditEvent(
      user.id,
      'login',
      null,
      getClientIp(req),
      req.headers['user-agent'] || 'unknown'
    );

    // Set refresh token in httpOnly cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user,
        accessToken: tokens.accessToken,
      },
    });
  } catch (error) {
    const message = (error as Error).message;

    if (message === 'Invalid email or password') {
      // ─── Audit log: FAILED login attempt ───────────────
      await logAuditEvent(
        null,
        'login_failed',
        null,
        getClientIp(req),
        req.headers['user-agent'] || 'unknown',
        { attemptedEmail: req.body?.email || 'unknown' }
      );

      res.status(401).json({ success: false, message });
      return;
    }

    logger.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
}

// ─── Refresh Token ───────────────────────────────────────

export async function refresh(req: Request, res: Response): Promise<void> {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      res.status(401).json({
        success: false,
        message: 'Refresh token not provided',
      });
      return;
    }

    const tokens = await refreshTokens(refreshToken);

    // Set new refresh token cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: 'Token refreshed',
      data: { accessToken: tokens.accessToken },
    });
  } catch (error) {
    logger.error('Token refresh error:', error);
    res.status(401).json({ success: false, message: 'Invalid refresh token' });
  }
}

// ─── Logout ──────────────────────────────────────────────

export async function logout(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (req.user) {
      // Remove cached master key from Redis
      await removeCachedMasterKey(req.user.id);

      await logAuditEvent(
        req.user.id,
        'logout',
        null,
        getClientIp(req),
        req.headers['user-agent'] || 'unknown'
      );
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
}
