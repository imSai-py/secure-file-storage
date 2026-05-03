/**
 * Secure File Storage — Express Application
 * Configures all middleware, security headers, and routes.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import config from './config';
import routes from './routes';
import { generalLimiter } from './middleware/rateLimiter';
import logger from './utils/logger';

const app = express();

// ─── Security Headers (Helmet) ───────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

// ─── CORS ────────────────────────────────────────────────
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─── Request Parsing ─────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// ─── Logging ─────────────────────────────────────────────
app.use(morgan('combined', {
  stream: { write: (message: string) => logger.info(message.trim()) },
}));

// ─── Rate Limiting ───────────────────────────────────────
app.use(generalLimiter);

// ─── Trust Proxy (for accurate IP behind load balancer) ──
app.set('trust proxy', 1);

// ─── Health Check ────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.status(200).json({
    success: true,
    message: 'Secure File Storage API is running',
    timestamp: new Date().toISOString(),
    environment: config.server.nodeEnv,
  });
});

// ─── API Routes ──────────────────────────────────────────
app.use('/api/v1', routes);

// ─── 404 Handler ─────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// ─── Global Error Handler ────────────────────────────────
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error('Unhandled error:', err);

  // Don't leak error details in production
  const message = config.server.isProduction ? 'Internal server error' : err.message;

  res.status(500).json({ success: false, message });
});

export default app;
