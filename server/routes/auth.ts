/**
 * Authentication API endpoints
 * Handles user registration, login, logout, and profile management
 */

import { Router } from 'express';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { createClient } from '@supabase/supabase-js';
import { asyncHandler, AppError } from '../middleware/errorHandler';
import { authRateLimit } from '../config/rateLimit';
import { logger } from '../utils/logger';
import { optionalAuth, validateAuth } from '../middleware/auth';

const router = Router();

// Only create Supabase client if environment variables are available
let supabase: ReturnType<typeof createClient> | null = null;

if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
} else {
  logger.warn('Supabase not configured - auth routes will have limited functionality');
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
    supabaseConfigured: !!supabase,
    timestamp: new Date().toISOString()
  });
});

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register new user
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
 *                 minLength: 8
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               companyName:
 *                 type: string
 *               phone:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Invalid input
 *       409:
 *         description: User already exists
 *       503:
 *         description: Service unavailable
 */
router.post('/register', authRateLimit, asyncHandler(async (req, res) => {
  const validatedData = registerSchema.parse(req.body);

  // Check if Supabase is configured
  if (!supabase) {
    throw new AppError('Registration service not available - Supabase not configured', 503, true, 'SERVICE_UNAVAILABLE');
  }

  try {
    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('profiles')
      .select('id')
      .eq('email', validatedData.email)
      .single();

    if (existingUser) {
      throw new AppError('User with this email already exists', 409, true, 'USER_EXISTS');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(validatedData.password, 10);

    // Create user in Supabase auth
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email: validatedData.email,
      password: validatedData.password,
      email_confirm: true,
    });

    if (authError || !authData.user) {
      logger.error('Auth user creation failed', { error: authError });
      throw new AppError('Failed to create user account', 500, true, 'AUTH_ERROR');
    }

    // Create company
    const { data: company, error: companyError } = await supabase
      .from('companies')
      .insert({
        name: validatedData.companyName,
        created_by: authData.user.id,
      })
      .select()
      .single();

    if (companyError || !company) {
      logger.error('Company creation failed', { error: companyError });
      throw new AppError('Failed to create company', 500, true, 'COMPANY_ERROR');
    }

    // Create user profile
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .insert({
        id: authData.user.id,
        email: validatedData.email,
        first_name: validatedData.firstName,
        last_name: validatedData.lastName,
        company_id: company.id,
        role: 'admin',
        is_active: true,
      })
      .select()
      .single();

    if (profileError || !profile) {
      logger.error('Profile creation failed', { error: profileError });
      throw new AppError('Failed to create user profile', 500, true, 'PROFILE_ERROR');
    }

    logger.info('User registered successfully', {
      userId: authData.user.id,
      email: validatedData.email,
      companyId: company.id,
    });

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: authData.user.id,
        email: validatedData.email,
        role: 'admin',
        companyId: company.id,
      },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: authData.user.id,
          email: validatedData.email,
          firstName: validatedData.firstName,
          lastName: validatedData.lastName,
          role: 'admin',
        },
        company: {
          id: company.id,
          name: validatedData.companyName,
        },
        token,
        expiresIn: 604800, // 7 days in seconds
      }
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Registration error', { error });
    throw new AppError('Registration failed', 500, true, 'REGISTRATION_ERROR');
  }
}));

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
 *       401:
 *         description: Invalid credentials
 *       503:
 *         description: Service unavailable
 */
router.post('/login', authRateLimit, asyncHandler(async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);

  // Check if Supabase is configured
  if (!supabase) {
    throw new AppError('Authentication service not available - Supabase not configured', 503, true, 'SERVICE_UNAVAILABLE');
  }

  try {
    // Authenticate with Supabase
    const { data: authData, error: authError } = await supabase.auth.admin.signInWithPassword({
      email,
      password,
    });

    if (authError || !authData.user) {
      logger.warn('Login failed - invalid credentials', { email });
      throw new AppError('Invalid email or password', 401, true, 'INVALID_CREDENTIALS');
    }

    // Get user profile
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('id, email, role, company_id, first_name, last_name, is_active')
      .eq('id', authData.user.id)
      .single();

    if (profileError || !profile || !profile.is_active) {
      logger.warn('User profile not found or inactive', { userId: authData.user.id });
      throw new AppError('User account is inactive', 401, true, 'ACCOUNT_INACTIVE');
    }

    logger.info('User logged in successfully', {
      userId: authData.user.id,
      email: profile.email,
    });

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: authData.user.id,
        email: profile.email,
        role: profile.role,
        companyId: profile.company_id,
      },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: profile.id,
          email: profile.email,
          firstName: profile.first_name,
          lastName: profile.last_name,
          role: profile.role,
          companyId: profile.company_id,
        },
        token,
        expiresIn: 604800, // 7 days in seconds
      }
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Login error', { error });
    throw new AppError('Login failed', 500, true, 'LOGIN_ERROR');
  }
}));

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post('/logout', asyncHandler(async (req, res) => {
  res.json({
    success: true,
    message: 'Logout successful',
    timestamp: new Date().toISOString(),
  });
}));

/**
 * @swagger
 * /api/auth/logout:
 *   get:
 *     summary: Logout user (GET alternative)
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.get('/logout', asyncHandler(async (req, res) => {
  res.json({
    success: true,
    message: 'Logout successful',
    timestamp: new Date().toISOString(),
  });
}));

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user info
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User info retrieved successfully
 *       401:
 *         description: Not authenticated
 */
router.get('/me', validateAuth, asyncHandler(async (req, res) => {
  if (!req.user) {
    throw new AppError('User not authenticated', 401);
  }

  res.json({
    success: true,
    data: {
      user: {
        id: req.user.id,
        email: req.user.email,
        role: req.user.role,
        companyId: req.user.companyId,
        permissions: req.user.permissions,
      },
      timestamp: new Date().toISOString()
    }
  });
}));

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh authentication token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 description: Current JWT token
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid token
 */
router.post('/refresh', optionalAuth, asyncHandler(async (req, res) => {
  if (!req.user) {
    throw new AppError('Authentication required', 401);
  }

  // Generate new JWT token
  const token = jwt.sign(
    {
      userId: req.user.id,
      email: req.user.email,
      role: req.user.role,
      companyId: req.user.companyId,
    },
    process.env.JWT_SECRET!,
    { expiresIn: '7d' }
  );

  res.json({
    success: true,
    message: 'Token refreshed successfully',
    data: {
      token,
      expiresIn: 604800, // 7 days in seconds
    }
  });
}));

// Default endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'Auth routes endpoint',
    availableRoutes: ['/test', '/login', '/logout', '/me', '/register', '/refresh'],
    supabaseConfigured: !!supabase,
  });
});

export default router;
