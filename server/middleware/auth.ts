/**
 * Authentication and authorization middleware
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { AppError } from './errorHandler';
import { logger } from '../utils/logger';
import { getUserPermissions } from '../services/rbac';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: string;
        companyId: string;
        permissions: string[];
      };
    }
  }
}

// Supabase clients - only create if environment variables are available
let supabase: ReturnType<typeof createClient> | null = null;
let supabaseAnon: ReturnType<typeof createClient> | null = null;

if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
}

if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
  supabaseAnon = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
  );
}

/**
 * Extract JWT token from Authorization header or cookies
 * Supports both "Bearer <token>" and direct token formats
 */
const extractToken = (req: Request): string | null => {
  // Check Authorization header first (preferred method)
  const authHeader = req.headers.authorization;
  if (authHeader) {
    // Handle "Bearer <token>" format
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }
    // Handle direct token format
    return authHeader;
  }

  // Fallback to cookies for backward compatibility
  const token = req.cookies?.auth_token;
  if (token) {
    return token;
  }

  return null;
};

/**
 * Validates JWT token from Authorization header or HTTP-only cookie
 * Supports both Supabase JWT tokens and custom JWT tokens
 */
export const validateAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = extractToken(req);
    const isSupabaseToken = req.headers.authorization?.startsWith('Bearer ') || false;

    if (!token) {
      throw new AppError('Authentication required - missing token', 401, true, 'MISSING_TOKEN');
    }

    let userId: string;
    let decoded: any;

    // Check if Supabase is configured
    if (!supabase && !supabaseAnon) {
      // If Supabase is not configured, verify with custom JWT secret
      decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
      userId = decoded.userId || decoded.sub;
      
      if (!userId) {
        throw new AppError('Invalid authentication token', 401, true, 'INVALID_TOKEN');
      }

      logger.warn('Supabase not configured - using decoded token info only');
      req.user = {
        id: userId,
        email: decoded.email || '',
        role: decoded.role || 'user',
        companyId: decoded.companyId || '',
        permissions: decoded.permissions || [],
      };
      return next();
    }

    // For Supabase tokens (Bearer tokens), validate via Supabase Auth
    if (isSupabaseToken && supabaseAnon) {
      // Use supabaseAnon client to get user from the token
      const { data: { user }, error: authError } = await supabaseAnon.auth.getUser(token);
      
      if (authError || !user) {
        logger.warn('Supabase token validation failed', { error: authError?.message });
        throw new AppError('Invalid authentication token', 401, true, 'INVALID_TOKEN');
      }
      userId = user.id;
    } else {
      // For custom JWT tokens (e.g., from cookies), verify with JWT_SECRET
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
        if (!decoded.userId && !decoded.sub) {
          throw new AppError('Invalid authentication token', 401, true, 'INVALID_TOKEN');
        }
        userId = decoded.userId || decoded.sub;
      } catch (jwtError) {
        // If custom JWT fails, try Supabase validation as fallback
        if (supabaseAnon) {
          const { data: { user }, error: authError } = await supabaseAnon.auth.getUser(token);
          if (authError || !user) {
            throw new AppError('Invalid authentication token', 401, true, 'INVALID_TOKEN');
          }
          userId = user.id;
        } else {
          throw jwtError;
        }
      }
    }

    // Get user profile from Supabase using service role client
    const { data: profile, error: profileError } = await supabase!
      .from('profiles')
      .select(`
        id,
        email,
        role,
        company_id,
        first_name,
        last_name,
        is_active
      `)
      .eq('id', userId)
      .eq('is_active', true)
      .single();

    if (profileError || !profile) {
      logger.warn('User profile not found or inactive', { userId, error: profileError });
      throw new AppError('User not found or inactive', 401, true, 'USER_NOT_FOUND');
    }

    // Get user permissions
    const permissions = await getUserPermissions(userId, profile.company_id);

    // Attach user to request
    req.user = {
      id: profile.id,
      email: profile.email,
      role: profile.role,
      companyId: profile.company_id,
      permissions,
    };

    logger.info('User authenticated', {
      userId: profile.id,
      email: profile.email,
      role: profile.role,
      companyId: profile.company_id,
      ip: req.ip,
      tokenType: isSupabaseToken ? 'supabase' : 'custom',
    });

    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      next(new AppError('Invalid authentication token', 401, true, 'INVALID_TOKEN'));
    } else if (error instanceof jwt.TokenExpiredError) {
      next(new AppError('Authentication token expired', 401, true, 'TOKEN_EXPIRED'));
    } else {
      next(error);
    }
  }
};

/**
 * Checks if user has required permissions
 */
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    if (!req.user.permissions.includes(permission)) {
      logger.warn('Access denied - insufficient permissions', {
        userId: req.user.id,
        requiredPermission: permission,
        userPermissions: req.user.permissions,
        path: req.path,
      });

      return next(new AppError('Insufficient permissions', 403, true, 'INSUFFICIENT_PERMISSIONS'));
    }

    next();
  };
};

/**
 * Checks if user has required role
 */
export const requireRole = (roles: string | string[]) => {
  const allowedRoles = Array.isArray(roles) ? roles : [roles];

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    if (!allowedRoles.includes(req.user.role)) {
      logger.warn('Access denied - insufficient role', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        path: req.path,
      });

      return next(new AppError('Insufficient role privileges', 403, true, 'INSUFFICIENT_ROLE'));
    }

    next();
  };
};

/**
 * Validates user has access to specific company
 */
export const requireCompanyAccess = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    const { companyId } = req.params;
    const userCompanyId = req.user.companyId;

    // Super admins can access all companies
    if (req.user.role === 'super_admin') {
      return next();
    }

    // Regular users can only access their own company
    if (companyId && companyId !== userCompanyId) {
      logger.warn('Access denied - company mismatch', {
        userId: req.user.id,
        userCompanyId,
        requestedCompanyId: companyId,
        path: req.path,
      });

      return next(new AppError('Access denied to this company', 403, true, 'COMPANY_ACCESS_DENIED'));
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication - attaches user if token exists, but doesn't require it
 * Supports both Supabase JWT tokens and custom JWT tokens
 */
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = extractToken(req);
    const isSupabaseToken = req.headers.authorization?.startsWith('Bearer ') || false;

    if (!token) {
      return next();
    }

    let userId: string | null = null;
    let decoded: any;

    // Try Supabase token validation first for Bearer tokens
    if (isSupabaseToken && supabaseAnon) {
      const { data: { user }, error } = await supabaseAnon.auth.getUser(token);
      if (!error && user) {
        userId = user.id;
      }
    }

    // If not a Supabase token or validation failed, try custom JWT
    if (!userId) {
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
        userId = decoded.userId || decoded.sub;
      } catch {
        // If custom JWT fails and we haven't tried Supabase yet, try it now
        if (!isSupabaseToken && supabaseAnon) {
          const { data: { user }, error } = await supabaseAnon.auth.getUser(token);
          if (!error && user) {
            userId = user.id;
          }
        }
      }
    }

    if (userId && supabase) {
      const { data: profile } = await supabase
        .from('profiles')
        .select('id, email, role, company_id, is_active')
        .eq('id', userId)
        .eq('is_active', true)
        .single();

      if (profile) {
        req.user = {
          id: profile.id,
          email: profile.email,
          role: profile.role,
          companyId: profile.company_id,
          permissions: await getUserPermissions(profile.id, profile.company_id),
        };
      }
    } else if (userId && decoded) {
      // If Supabase not configured, use decoded info
      req.user = {
        id: userId,
        email: decoded.email || '',
        role: decoded.role || 'user',
        companyId: decoded.companyId || '',
        permissions: decoded.permissions || [],
      };
    }

    next();
  } catch (error) {
    // Silently fail for optional auth
    logger.debug('Optional auth failed', { error: (error as Error).message });
    next();
  }
};
