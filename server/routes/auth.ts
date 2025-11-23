/**
 * Authentication routes
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
const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

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

const resetPasswordSchema = z.object({
  email: z.string().email('Invalid email format'),
});

const confirmResetSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters'),
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

  // Get user profile
  const { data: profile, error: profileError } = await supabase
    .from('profiles')
    .select(`
      *,
      companies:company_id (
        id,
        name,
        is_active
      )
    `)
    .eq('email', email.toLowerCase())
    .eq('is_active', true)
    .single();

  if (profileError || !profile) {
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  // For this implementation, we'll use Supabase auth for password verification
  const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (authError || !authData.user) {
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  // Create JWT token for backend authentication
  const token = jwt.sign(
    {
      userId: profile.id,
      email: profile.email,
      companyId: profile.company_id,
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: '7d',
      issuer: 'fleetifyapp',
      audience: 'fleetifyapp-users',
    }
  );

  // Set HTTP-only cookie
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
  });

  // Cache user session
  await cacheHelpers.set(
    `session:${profile.id}`,
    JSON.stringify({
      userId: profile.id,
      email: profile.email,
      companyId: profile.company_id,
      lastActivity: new Date().toISOString(),
    }),
    7 * 24 * 60 * 60 // 7 days
  );

  logger.logAuth('login_success', profile.id, {
    email: profile.email,
    companyId: profile.company_id,
    ip: req.ip,
  });

  res.json({
    success: true,
    data: {
      user: {
        id: profile.id,
        email: profile.email,
        firstName: profile.first_name,
        lastName: profile.last_name,
        role: profile.role,
        companyId: profile.company_id,
        company: profile.companies,
      },
      expiresIn: 7 * 24 * 60 * 60,
    },
    message: 'Login successful',
  });
}));

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register new user and company
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
 *     responses:
 *       201:
 *         description: Registration successful
 *       400:
 *         description: Bad request
 */
router.post('/register', authRateLimit, asyncHandler(async (req, res) => {
  const {
    email,
    password,
    firstName,
    lastName,
    companyName,
    phone,
  } = registerSchema.parse(req.body);

  const emailLower = email.toLowerCase();

  // Check if user already exists
  const { data: existingUser } = await supabase
    .from('profiles')
    .select('id')
    .eq('email', emailLower)
    .single();

  if (existingUser) {
    throw new AppError('User with this email already exists', 409, 'USER_EXISTS');
  }

  // Create company first
  const { data: company, error: companyError } = await supabase
    .from('companies')
    .insert({
      name: companyName,
      is_active: true,
      created_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (companyError || !company) {
    throw new AppError('Failed to create company', 500, 'COMPANY_CREATE_FAILED');
  }

  // Create user in Supabase Auth
  const { data: authData, error: authError } = await supabase.auth.signUp({
    email: emailLower,
    password,
    options: {
      data: {
        firstName,
        lastName,
        companyId: company.id,
      },
    },
  });

  if (authError || !authData.user) {
    // Rollback company creation on auth failure
    await supabase.from('companies').delete().eq('id', company.id);
    throw new AppError('Failed to create user account', 500, 'AUTH_CREATE_FAILED');
  }

  // Create user profile
  const { data: profile, error: profileError } = await supabase
    .from('profiles')
    .insert({
      id: authData.user.id,
      email: emailLower,
      first_name: firstName,
      last_name: lastName,
      phone,
      company_id: company.id,
      role: 'admin', // First user in company becomes admin
      is_active: true,
      created_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (profileError || !profile) {
    // Rollback on profile creation failure
    await supabase.auth.admin.deleteUser(authData.user.id);
    await supabase.from('companies').delete().eq('id', company.id);
    throw new AppError('Failed to create user profile', 500, 'PROFILE_CREATE_FAILED');
  }

  logger.logAuth('register_success', profile.id, {
    email: profile.email,
    companyId: company.id,
    companyName: company.name,
    ip: req.ip,
  });

  res.status(201).json({
    success: true,
    data: {
      user: {
        id: profile.id,
        email: profile.email,
        firstName: profile.first_name,
        lastName: profile.last_name,
        role: profile.role,
        companyId: company.id,
      },
      company: {
        id: company.id,
        name: company.name,
      },
    },
    message: 'Registration successful',
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
  const token = req.cookies?.auth_token;

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

      // Clear user session cache
      await cacheHelpers.del(`session:${decoded.userId}`);

      // Invalidate Supabase session
      await supabase.auth.signOut();

      logger.logAuth('logout_success', decoded.userId, {
        ip: req.ip,
      });
    } catch (error) {
      // Token was invalid, but still proceed with logout
      logger.logAuth('logout_invalid_token', undefined, {
        ip: req.ip,
      });
    }
  }

  // Clear HTTP-only cookie
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });

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
  const token = req.cookies?.auth_token;

  if (!token) {
    throw new AppError('Not authenticated', 401, 'NOT_AUTHENTICATED');
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

  // Try to get from cache first
  const cached = await cacheHelpers.get(`session:${decoded.userId}`);

  if (cached) {
    const session = JSON.parse(cached);
    return res.json({
      success: true,
      data: session,
    });
  }

  // Fallback to database
  const { data: profile, error } = await supabase
    .from('profiles')
    .select(`
      *,
      companies:company_id (
        id,
        name,
        is_active
      )
    `)
    .eq('id', decoded.userId)
    .eq('is_active', true)
    .single();

  if (error || !profile) {
    throw new AppError('User not found', 401, 'USER_NOT_FOUND');
  }

  const userData = {
    userId: profile.id,
    email: profile.email,
    firstName: profile.first_name,
    lastName: profile.last_name,
    role: profile.role,
    companyId: profile.company_id,
    company: profile.companies,
    lastActivity: new Date().toISOString(),
  };

  // Update cache
  await cacheHelpers.set(
    `session:${decoded.userId}`,
    JSON.stringify(userData),
    60 * 60 // 1 hour
  );

  res.json({
    success: true,
    data: userData,
  });
}));

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh authentication token
 *     tags: [Authentication]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 */
router.post('/refresh', asyncHandler(async (req, res) => {
  const token = req.cookies?.auth_token;

  if (!token) {
    throw new AppError('No token provided', 401, 'NO_TOKEN');
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

  // Create new token
  const newToken = jwt.sign(
    {
      userId: decoded.userId,
      email: decoded.email,
      companyId: decoded.companyId,
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: '7d',
      issuer: 'fleetifyapp',
      audience: 'fleetifyapp-users',
    }
  );

  // Update HTTP-only cookie
  res.cookie('auth_token', newToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
  });

  res.json({
    success: true,
    message: 'Token refreshed successfully',
  });
}));

export default router;