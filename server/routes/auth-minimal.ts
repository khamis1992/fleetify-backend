/**
 * Minimal auth routes for debugging
 */

import { Router } from 'express';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { createClient } from '@supabase/supabase-js';
import { asyncHandler, AppError } from '../middleware/errorHandler';
import { authRateLimit } from '../config/rateLimit';
import { logger } from '../utils/logger';
import { cacheHelpers } from '../utils/redis';

const router = Router();

// Test endpoint
router.get('/test', (req, res) => {
  res.json({
    message: 'Auth routes are working!',
    timestamp: new Date().toISOString()
  });
});

// Default endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'Auth routes endpoint',
    availableRoutes: ['/test', '/login', '/register']
  });
});

export default router;