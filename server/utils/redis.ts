/**
 * Redis client configuration and utilities
 */

import Redis from 'ioredis';
import { logger } from './logger';

class RedisClient {
  private client: Redis | null = null;
  private isConnected: boolean = false;

  constructor() {
    // Only connect if Redis URL is provided
    if (process.env.REDIS_URL || process.env.REDIS_PASSWORD) {
      this.connect();
    } else {
      logger.info('Redis not configured - caching disabled');
    }
  }

  private async connect(): Promise<void> {
    try {
      const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
      const redisPassword = process.env.REDIS_PASSWORD;

      this.client = new Redis(redisUrl, {
        password: redisPassword,
        enableReadyCheck: true,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        keepAlive: 30000,
        family: 4,
        connectTimeout: 10000,
        commandTimeout: 5000,
      });

      this.client.on('connect', () => {
        logger.info('Redis connected');
        this.isConnected = true;
      });

      this.client.on('ready', () => {
        logger.info('Redis ready');
      });

      this.client.on('error', (error) => {
        logger.error('Redis connection error', error);
        this.isConnected = false;
      });

      this.client.on('close', () => {
        logger.warn('Redis connection closed');
        this.isConnected = false;
      });

      this.client.on('reconnecting', () => {
        logger.info('Redis reconnecting...');
      });

      await this.client.connect();
    } catch (error) {
      logger.error('Failed to connect to Redis', error);
      this.client = null;
      this.isConnected = false;
    }
  }

  public getClient(): Redis {
    if (!this.client || !this.isConnected) {
      // Return a mock Redis client that gracefully handles failures
      throw new Error('Redis not available');
    }
    return this.client;
  }

  public async isConnectedToRedis(): Promise<boolean> {
    if (!this.client) return false;

    try {
      await this.client.ping();
      return true;
    } catch {
      return false;
    }
  }

  public async close(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.client = null;
      this.isConnected = false;
    }
  }
}

// Singleton instance
const redisClientInstance = new RedisClient();

// Export with fallback for when Redis is not available
export const redisClient = new Proxy({} as Redis, {
  get(target, prop) {
    try {
      return redisClientInstance.getClient()[prop as keyof Redis];
    } catch (error) {
      logger.warn('Redis not available, caching disabled', { error });
      // Return a no-op function for Redis methods
      return (...args: any[]) => Promise.resolve();
    }
  }
});

// Redis utility functions
export const cacheHelpers = {
  /**
   * Set a key-value pair with expiration
   */
  async set(key: string, value: string, ttl?: number): Promise<void> {
    try {
      if (ttl) {
        await redisClient.setex(key, ttl, value);
      } else {
        await redisClient.set(key, value);
      }
    } catch (error) {
      logger.warn('Redis SET error - caching disabled', { key, error });
      // Don't throw - just disable caching
    }
  },

  /**
   * Get a value by key
   */
  async get(key: string): Promise<string | null> {
    try {
      return await redisClient.get(key);
    } catch (error) {
      logger.warn('Redis GET error - cache miss', { key, error });
      return null; // Return null to indicate cache miss
    }
  },

  /**
   * Delete a key
   */
  async del(key: string): Promise<void> {
    try {
      await redisClient.del(key);
    } catch (error) {
      logger.warn('Redis DEL error - cache invalidation skipped', { key, error });
      // Don't throw - just skip cache invalidation
    }
  },

  /**
   * Delete multiple keys
   */
  async delMany(keys: string[]): Promise<void> {
    try {
      if (keys.length > 0) {
        await redisClient.del(...keys);
      }
    } catch (error) {
      logger.warn('Redis DELMANY error - cache invalidation skipped', { keys, error });
      // Don't throw - just skip cache invalidation
    }
  },

  /**
   * Find keys by pattern
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      return await redisClient.keys(pattern);
    } catch (error) {
      logger.warn('Redis KEYS error - returning empty array', { pattern, error });
      return [];
    }
  },

  /**
   * Set a hash field
   */
  async hSet(key: string, field: string, value: string): Promise<void> {
    try {
      await redisClient.hset(key, field, value);
    } catch (error) {
      logger.warn('Redis HSET error - caching disabled', { key, field, error });
      // Don't throw - just disable caching
    }
  },

  /**
   * Get a hash field
   */
  async hGet(key: string, field: string): Promise<string | null> {
    try {
      return await redisClient.hget(key, field);
    } catch (error) {
      logger.error('Redis HGET error', { key, field, error });
      return null;
    }
  },

  /**
   * Get all hash fields
   */
  async hGetAll(key: string): Promise<Record<string, string>> {
    try {
      return await redisClient.hgetall(key);
    } catch (error) {
      logger.error('Redis HGETALL error', { key, error });
      return {};
    }
  },

  /**
   * Delete hash field
   */
  async hDel(key: string, field: string): Promise<void> {
    try {
      await redisClient.hdel(key, field);
    } catch (error) {
      logger.error('Redis HDEL error', { key, field, error });
      throw error;
    }
  },

  /**
   * Increment a counter
   */
  async incr(key: string): Promise<number> {
    try {
      return await redisClient.incr(key);
    } catch (error) {
      logger.warn('Redis INCR error - returning 0', { key, error });
      return 0; // Return default value
    }
  },

  /**
   * Increment a counter by amount
   */
  async incrBy(key: string, amount: number): Promise<number> {
    try {
      return await redisClient.incrby(key, amount);
    } catch (error) {
      logger.warn('Redis INCRBY error - returning 0', { key, amount, error });
      return 0; // Return default value
    }
  },

  /**
   * Check if key exists
   */
  async exists(key: string): Promise<boolean> {
    try {
      const result = await redisClient.exists(key);
      return result === 1;
    } catch (error) {
      logger.error('Redis EXISTS error', { key, error });
      return false;
    }
  },

  /**
   * Set expiration on key
   */
  async expire(key: string, ttl: number): Promise<void> {
    try {
      await redisClient.expire(key, ttl);
    } catch (error) {
      logger.warn('Redis EXPIRE error - skipping expiration', { key, ttl, error });
      // Don't throw - just skip expiration
    }
  },

  /**
   * Get time to live
   */
  async ttl(key: string): Promise<number> {
    try {
      return await redisClient.ttl(key);
    } catch (error) {
      logger.error('Redis TTL error', { key, error });
      return -1;
    }
  }
};