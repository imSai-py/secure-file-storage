/**
 * Secure File Storage — Auth Routes
 */

import { Router } from 'express';
import { register, login, refresh, logout } from '../controllers/authController';
import { authenticate } from '../middleware/auth';
import { authLimiter } from '../middleware/rateLimiter';

const router = Router();

router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.post('/refresh', refresh);
router.post('/logout', authenticate, logout);

export default router;
