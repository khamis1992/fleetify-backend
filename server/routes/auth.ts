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

// Only create Supabase client if environment variables are available
let supabase: ReturnType<typeof createClient> | null = null;

if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
} else {
  logger.warn('Supabase not configured - auth routes will be disabled');
}

// Validation schemas
const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
});

const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  companyName: z.string().min(1, 'Company name is required'),
  phone: z.string().optional(),
});

// Test endpoint
router.get('/test', (req, res) => {
  res.json({
    message: 'Auth routes are working!',
    timestamp: new Date().toISOString()
  });
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Authenticate user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     expiresIn:
 *                       type: number
 *       401:
 *         description: Invalid credentials
 */
router.post('/login', authRateLimit, asyncHandler(async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);

  // Check if Supabase is configured
  if (!supabase) {
    throw new AppError('Authentication service not available', 503, true, 'SERVICE_UNAVAILABLE');
  }

  // For now, return a simple success response
  // TODO: Implement full authentication with Supabase
  res.json({
    success: true,
    message: 'Login endpoint functional',
    data: {
      email,
      status: 'authenticated',
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Authentication]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post('/logout', asyncHandler(async (req, res) => {
  res.json({
    success: true,
    message: 'Logout successful',
  });
}));

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user info
 *     tags: [Authentication]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User info retrieved successfully
 *       401:
 *         description: Not authenticated
 */
router.get('/me', asyncHandler(async (req, res) => {
  res.json({
    success: true,
    data: {
      message: 'User endpoint functional',
      authenticated: false,
      timestamp: new Date().toISOString()
    }
  });
}));

// Default endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'Auth routes endpoint',
    availableRoutes: ['/test', '/login', '/logout', '/me', '/register']
  });
});

export default router;