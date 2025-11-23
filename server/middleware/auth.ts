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

// Supabase clients
const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

const supabase = createClient(supabaseUrl, supabaseServiceKey);
const supabaseAnon = createClient(supabaseUrl, process.env.SUPABASE_ANON_KEY!);

/**
 * Validates JWT token from HTTP-only cookie
 */
export const validateAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = req.cookies?.auth_token;

    if (!token) {
      throw new AppError('Authentication required', 401, 'MISSING_TOKEN');
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

    if (!decoded.userId) {
      throw new AppError('Invalid authentication token', 401, 'INVALID_TOKEN');
    }

    // Get user profile from Supabase
    const { data: profile, error: profileError } = await supabase
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
      .eq('id', decoded.userId)
      .eq('is_active', true)
      .single();

    if (profileError || !profile) {
      throw new AppError('User not found or inactive', 401, 'USER_NOT_FOUND');
    }

    // Get user permissions
    const permissions = await getUserPermissions(decoded.userId, profile.company_id);

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
    });

    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      next(new AppError('Invalid authentication token', 401, 'INVALID_TOKEN'));
    } else if (error instanceof jwt.TokenExpiredError) {
      next(new AppError('Authentication token expired', 401, 'TOKEN_EXPIRED'));
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

      return next(new AppError('Insufficient permissions', 403, 'INSUFFICIENT_PERMISSIONS'));
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

      return next(new AppError('Insufficient role privileges', 403, 'INSUFFICIENT_ROLE'));
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

      return next(new AppError('Access denied to this company', 403, 'COMPANY_ACCESS_DENIED'));
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication - attaches user if token exists
 */
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = req.cookies?.auth_token;

    if (!token) {
      return next();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

    if (decoded.userId) {
      const { data: profile } = await supabase
        .from('profiles')
        .select('id, email, role, company_id, is_active')
        .eq('id', decoded.userId)
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
    }

    next();
  } catch (error) {
    // Silently fail for optional auth
    next();
  }
};