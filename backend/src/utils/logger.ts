/**
 * Secure File Storage — Logger Utility
 * Structured logging with Winston for security audit trails.
 */

import winston from 'winston';
import config from '../config';

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  config.server.isProduction
    ? winston.format.json()
    : winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, stack }) => {
          return `${timestamp} [${level}]: ${stack || message}`;
        })
      )
);

export const logger = winston.createLogger({
  level: config.server.isProduction ? 'info' : 'debug',
  format: logFormat,
  defaultMeta: { service: 'secure-file-storage' },
  transports: [
    new winston.transports.Console(),
    // In production, also write to file for persistent audit trails
    ...(config.server.isProduction
      ? [
          new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
          new winston.transports.File({ filename: 'logs/combined.log' }),
        ]
      : []),
  ],
});

export default logger;
