/**
 * Secure File Storage — File Routes
 */

import { Router } from 'express';
import { uploadFile, listFiles, getFileMetadata, downloadFile, deleteFile } from '../controllers/fileController';
import { authenticate } from '../middleware/auth';
import { upload } from '../middleware/fileValidator';
import { uploadLimiter, downloadLimiter } from '../middleware/rateLimiter';

const router = Router();

// All file routes require authentication
router.use(authenticate);

router.post('/upload', uploadLimiter, upload.single('file'), uploadFile);
router.get('/', listFiles);
router.get('/:fileId/metadata', getFileMetadata);
router.get('/:fileId', downloadLimiter, downloadFile);
router.delete('/:fileId', deleteFile);

export default router;
