/**
 * Centralized logging utility
 */

import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

const supabase = createClient(supabaseUrl, supabaseServiceKey);

type LogLevel = 'info' | 'warn' | 'error' | 'debug';

interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, any>;
  userId?: string;
  companyId?: string;
  requestId?: string;
  ip?: string;
  userAgent?: string;
  path?: string;
  method?: string;
  statusCode?: number;
  duration?: string;
  error?: {
    message: string;
    stack?: string;
    code?: string;
    details?: any;
  };
}

class Logger {
  private isDevelopment = process.env.NODE_ENV === 'development';

  private formatMessage(entry: LogEntry): string {
    const context = entry.context ? ` ${JSON.stringify(entry.context)}` : '';
    const errorInfo = entry.error ? ` Error: ${entry.error.message}` : '';

    return `[${entry.timestamp}] ${entry.level.toUpperCase()}: ${entry.message}${context}${errorInfo}`;
  }

  private async writeToDatabase(entry: LogEntry): Promise<void> {
    // Only write logs to database in production or when explicitly enabled
    if (process.env.LOG_TO_DATABASE !== 'true' && process.env.NODE_ENV !== 'production') {
      return;
    }

    try {
      // Only log errors and warnings to database to avoid excessive writes
      if (entry.level === 'error' || entry.level === 'warn') {
        await supabase.from('application_logs').insert({
          level: entry.level,
          message: entry.message,
          context: entry.context,
          user_id: entry.userId,
          company_id: entry.companyId,
          request_id: entry.requestId,
          ip_address: entry.ip,
          user_agent: entry.userAgent,
          path: entry.path,
          method: entry.method,
          status_code: entry.statusCode,
          duration: entry.duration,
          error_details: entry.error ? {
            message: entry.error.message,
            stack: entry.error.stack,
            code: entry.error.code,
            details: entry.error.details
          } : null,
          created_at: entry.timestamp
        });
      }
    } catch (error) {
      // Don't let logging errors crash the application
      console.error('Failed to write log to database:', error);
    }
  }

  private async log(level: LogLevel, message: string, context?: Record<string, any>, error?: Error | any): Promise<void> {
    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      context,
      error: error ? {
        message: error.message || String(error),
        stack: error.stack,
        code: error.code,
        details: error.details
      } : undefined
    };

    // Console output
    const formattedMessage = this.formatMessage(entry);

    switch (level) {
      case 'error':
        console.error(formattedMessage);
        break;
      case 'warn':
        console.warn(formattedMessage);
        break;
      case 'debug':
        if (this.isDevelopment) {
          console.debug(formattedMessage);
        }
        break;
      default:
        console.log(formattedMessage);
    }

    // Write to database asynchronously
    this.writeToDatabase(entry).catch(() => {
      // Silently ignore database logging errors
    });
  }

  public info(message: string, context?: Record<string, any>): void {
    this.log('info', message, context);
  }

  public warn(message: string, context?: Record<string, any>): void {
    this.log('warn', message, context);
  }

  public error(message: string, context?: Record<string, any>, error?: Error | any): void {
    this.log('error', message, context, error);
  }

  public debug(message: string, context?: Record<string, any>): void {
    this.log('debug', message, context);
  }

  // Request-specific logging methods
  public logRequest(req: any, context?: Record<string, any>): void {
    this.info('API Request', {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      companyId: req.user?.companyId,
      ...context
    });
  }

  public logResponse(req: any, res: any, duration: number, context?: Record<string, any>): void {
    const level = res.statusCode >= 400 ? 'warn' : 'info';

    this.log(level, 'API Response', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userId: req.user?.id,
      companyId: req.user?.companyId,
      ...context
    });
  }

  public logError(error: Error, req?: any, context?: Record<string, any>): void {
    this.error('Application Error', {
      ...(req && {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id,
        companyId: req.user?.companyId
      }),
      ...context
    }, error);
  }

  public logAuth(event: string, userId?: string, context?: Record<string, any>): void {
    this.info(`Auth: ${event}`, {
      userId,
      timestamp: new Date().toISOString(),
      ...context
    });
  }

  public logDatabase(operation: string, table: string, duration?: number, context?: Record<string, any>): void {
    this.info(`Database: ${operation}`, {
      table,
      duration: duration ? `${duration}ms` : undefined,
      ...context
    });
  }

  public logCache(operation: string, key: string, hit?: boolean, context?: Record<string, any>): void {
    this.debug(`Cache: ${operation}`, {
      key,
      hit,
      ...context
    });
  }

  public logSecurity(event: string, severity: 'low' | 'medium' | 'high', context?: Record<string, any>): void {
    const level = severity === 'high' ? 'error' : severity === 'medium' ? 'warn' : 'info';
    this.log(level, `Security: ${event}`, {
      severity,
      timestamp: new Date().toISOString(),
      ...context
    });
  }
}

export const logger = new Logger();