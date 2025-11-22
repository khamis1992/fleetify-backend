/**
 * Rate limiting configuration
 */

import rateLimit from 'express-rate-limit';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { redisClient } from '../utils/redis';

// General API rate limiting
export const rateLimitConfig = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req: any, res: any) => {
    res.status(429).json({
      success: false,
      error: {
        message: 'Too many requests, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: '15 minutes'
      },
      timestamp: new Date().toISOString()
    });
  }
};

// Authentication-specific rate limiting (stricter)
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  skipSuccessfulRequests: true, // Don't count successful auth requests
  handler: (req: any, res: any) => {
    res.status(429).json({
      success: false,
      error: {
        message: 'Too many authentication attempts, please try again later.',
        code: 'AUTH_RATE_LIMIT_EXCEEDED',
        retryAfter: '15 minutes'
      },
      timestamp: new Date().toISOString()
    });
  }
});

// Data modification rate limiting
export const modifyRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 modification requests per minute
  message: {
    error: 'Too many modification requests, please try again later.',
    retryAfter: '1 minute'
  },
  handler: (req: any, res: any) => {
    res.status(429).json({
      success: false,
      error: {
        message: 'Too many modification requests, please try again later.',
        code: 'MODIFY_RATE_LIMIT_EXCEEDED',
        retryAfter: '1 minute'
      },
      timestamp: new Date().toISOString()
    });
  }
});

// Redis-based advanced rate limiter for user-specific limits
export const createUserRateLimiter = () => {
  return new RateLimiterRedis({
    storeClient: redisClient,
    keyPrefix: 'user_rate_limit',
    points: 1000, // Number of requests
    duration: 3600, // Per 1 hour
    blockDuration: 3600, // Block for 1 hour if limit exceeded
  });
};

export const createCompanyRateLimiter = () => {
  return new RateLimiterRedis({
    storeClient: redisClient,
    keyPrefix: 'company_rate_limit',
    points: 10000, // Number of requests
    duration: 3600, // Per 1 hour
    blockDuration: 1800, // Block for 30 minutes if limit exceeded
  });
};

// API endpoint specific rate limiters
export const endpointRateLimits = {
  // Authentication endpoints
  '/api/auth/login': {
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts, please try again later.'
  },
  '/api/auth/register': {
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: 'Too many registration attempts, please try again later.'
  },
  '/api/auth/reset-password': {
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: 'Too many password reset attempts, please try again later.'
  },

  // File upload endpoints
  '/api/vehicles/upload': {
    windowMs: 60 * 60 * 1000,
    max: 50,
    message: 'Too many file uploads, please try again later.'
  },
  '/api/violations/upload': {
    windowMs: 60 * 60 * 1000,
    max: 100,
    message: 'Too many violation uploads, please try again later.'
  },

  // Report generation endpoints
  '/api/reports': {
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: 'Too many report generation requests, please try again later.'
  },

  // Export endpoints
  '/api/export': {
    windowMs: 60 * 60 * 1000,
    max: 30,
    message: 'Too many export requests, please try again later.'
  }
};