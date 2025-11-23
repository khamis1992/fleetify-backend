/**
 * Caching middleware using Redis
 */

import { Request, Response, NextFunction } from 'express';
import { redisClient } from '../utils/redis';
import { logger } from '../utils/logger';
import crypto from 'crypto';

interface CacheOptions {
  ttl?: number; // Time to live in seconds
  key?: string; // Custom cache key
  condition?: (req: Request) => boolean; // Condition to cache
  vary?: string[]; // Headers to vary cache by
}

/**
 * Creates a cache key from request
 */
const createCacheKey = (req: Request, customKey?: string, vary?: string[]): string => {
  if (customKey) {
    return `cache:${customKey}`;
  }

  const baseUrl = req.baseUrl;
  const route = req.route?.path || req.path;
  const method = req.method;

  let key = `cache:${method}:${baseUrl}${route}`;

  // Add query parameters
  if (Object.keys(req.query).length > 0) {
    const queryString = new URLSearchParams(req.query as any).toString();
    key += `?${queryString}`;
  }

  // Add varying headers
  if (vary) {
    const headerValues = vary
      .map(header => req.get(header))
      .filter(Boolean)
      .join('|');
    if (headerValues) {
      key += `:${headerValues}`;
    }
  }

  // Add user context if authenticated
  if (req.user?.companyId) {
    key += `:company:${req.user.companyId}`;
  }

  // Hash if key gets too long
  if (key.length > 200) {
    key = `cache:hash:${crypto.createHash('md5').update(key).digest('hex')}`;
  }

  return key;
};

/**
 * Response caching middleware
 */
export const cacheMiddleware = (options: CacheOptions = {}) => {
  const { ttl = 300, key: customKey, condition, vary } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Skip caching for non-GET requests
    if (req.method !== 'GET') {
      return next();
    }

    // Check custom condition
    if (condition && !condition(req)) {
      return next();
    }

    const cacheKey = createCacheKey(req, customKey, vary);

    try {
      // Try to get cached response
      const cached = await redisClient.get(cacheKey);

      if (cached) {
        const parsed = JSON.parse(cached);

        logger.debug('Cache hit', { key: cacheKey, url: req.url });

        res.set(parsed.headers);
        res.set('X-Cache', 'HIT');
        return res.status(parsed.status).json(parsed.data);
      }

      logger.debug('Cache miss', { key: cacheKey, url: req.url });

      // Override res.json to cache the response
      const originalJson = res.json;
      const originalStatus = res.status;

      let responseData: any;
      let statusCode: number = 200;

      res.status = function(code: number) {
        statusCode = code;
        return originalStatus.call(this, code);
      };

      res.json = function(data: any) {
        responseData = data;

        // Only cache successful responses
        if (statusCode >= 200 && statusCode < 300) {
          const cacheData = {
            status: statusCode,
            headers: res.getHeaders(),
            data,
            timestamp: new Date().toISOString(),
          };

          // Cache asynchronously
          redisClient
            .setex(cacheKey, ttl, JSON.stringify(cacheData))
            .catch(error => {
              logger.error('Cache write error', { key: cacheKey, error });
            });
        }

        return originalJson.call(this, data);
      };

      next();
    } catch (error) {
      logger.error('Cache middleware error', { key: cacheKey, error });
      next();
    }
  };
};

/**
 * Invalidate cache by pattern
 */
export const invalidateCache = async (pattern: string): Promise<void> => {
  try {
    const keys = await redisClient.keys(`cache:${pattern}*`);

    if (keys.length > 0) {
      await redisClient.del(...keys);
      logger.info('Cache invalidated', { pattern, keysCount: keys.length });
    }
  } catch (error) {
    logger.error('Cache invalidation error', { pattern, error });
  }
};

/**
 * Cache invalidation middleware
 */
export const invalidateCacheMiddleware = (patterns: string[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Continue with the request
    const originalJson = res.json;

    res.json = function(data: any) {
      // Invalidate cache after successful response
      if (res.statusCode >= 200 && res.statusCode < 300) {
        patterns.forEach(pattern => {
          invalidateCache(pattern).catch(error => {
            logger.error('Cache invalidation failed', { pattern, error });
          });
        });
      }

      return originalJson.call(this, data);
    };

    next();
  };
};

/**
 * User-specific cache middleware
 */
export const userCache = (ttl: number = 300) => {
  return cacheMiddleware({
    ttl,
    vary: ['Authorization'],
    condition: (req) => !!req.user?.id,
  });
};

/**
 * Company-specific cache middleware
 */
export const companyCache = (ttl: number = 600) => {
  return cacheMiddleware({
    ttl,
    vary: ['Authorization'],
    condition: (req) => !!req.user?.companyId,
  });
};