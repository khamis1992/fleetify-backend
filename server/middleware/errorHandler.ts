/**
 * Centralized error handling middleware
 */

import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';

export interface ApiError extends Error {
  statusCode?: number;
  isOperational?: boolean;
  code?: string;
  details?: any;
}

export class AppError extends Error implements ApiError {
  public statusCode: number;
  public isOperational: boolean;
  public code?: string;
  public details?: any;

  constructor(
    message: string,
    statusCode: number = 500,
    isOperational: boolean = true,
    code?: string,
    details?: any
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.code = code;
    this.details = details;

    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  error: ApiError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let { statusCode = 500, message, code, details } = error;

  // Log error details
  logger.error('API Error:', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    statusCode,
    code,
    details,
  });

  // Handle specific error types
  if (error instanceof ZodError) {
    statusCode = 400;
    message = 'Validation Error';
    details = error.errors.map(err => ({
      field: err.path.join('.'),
      message: err.message,
      code: err.code,
    }));
  }

  if (error instanceof jwt.JsonWebTokenError) {
    statusCode = 401;
    message = 'Invalid authentication token';
    code = 'INVALID_TOKEN';
  }

  if (error instanceof jwt.TokenExpiredError) {
    statusCode = 401;
    message = 'Authentication token expired';
    code = 'TOKEN_EXPIRED';
  }

  // Handle Supabase errors
  if (error.message?.includes('JWT')) {
    statusCode = 401;
    message = 'Authentication failed';
    code = 'AUTH_ERROR';
  }

  // Handle database constraint errors
  if (error.message?.includes('duplicate key')) {
    statusCode = 409;
    message = 'Resource already exists';
    code = 'DUPLICATE_RESOURCE';
  }

  if (error.message?.includes('foreign key constraint')) {
    statusCode = 400;
    message = 'Invalid reference to related resource';
    code = 'INVALID_REFERENCE';
  }

  // Don't expose internal errors in production
  if (process.env.NODE_ENV === 'production' && statusCode === 500) {
    message = 'Internal server error';
    details = undefined;
  }

  const errorResponse = {
    success: false,
    error: {
      message,
      code,
      ...(details && { details }),
    },
    timestamp: new Date().toISOString(),
    path: req.path,
  };

  res.status(statusCode).json(errorResponse);
};

export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
  const error = new AppError(`Route ${req.originalUrl} not found`, 404);
  next(error);
};