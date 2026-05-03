/**
 * Secure File Storage — Server Entry Point
 * Initializes database connection and starts the Express server.
 */

import app from './app';
import config from './config';
import { testDatabaseConnection } from './config/database';
import logger from './utils/logger';

async function startServer(): Promise<void> {
  try {
    // Test database connection
    await testDatabaseConnection();

    // Start Express server
    app.listen(config.server.port, () => {
      logger.info('═══════════════════════════════════════════════');
      logger.info('  🔐 Secure File Storage API');
      logger.info(`  📡 Running on: http://localhost:${config.server.port}`);
      logger.info(`  🌍 Environment: ${config.server.nodeEnv}`);
      logger.info(`  📁 Max file size: ${config.upload.maxFileSizeMb}MB`);
      logger.info(`  🔑 Encryption: AES-256-GCM + AWS KMS`);
      logger.info('═══════════════════════════════════════════════');
    });
  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

startServer();
// Trigger reload
