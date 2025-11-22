/**
 * Request logging middleware
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();
  const requestId = Math.random().toString(36).substr(2, 9);

  // Add request ID to response headers
  res.set('X-Request-ID', requestId);

  // Log request
  logger.info('Request started', {
    requestId,
    method: req.method,
    url: req.url,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    userId: req.user?.id,
    companyId: req.user?.companyId,
  });

  // Override res.end to log response
  const originalEnd = res.end;

  res.end = function(chunk?: any, encoding?: any) {
    const duration = Date.now() - startTime;

    logger.info('Request completed', {
      requestId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userId: req.user?.id,
      companyId: req.user?.companyId,
    });

    return originalEnd.call(this, chunk, encoding);
  };

  next();
};