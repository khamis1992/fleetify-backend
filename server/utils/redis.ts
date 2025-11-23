/**
 * Redis client configuration and utilities
 */

import Redis from 'ioredis';
import { logger } from './logger';

class RedisClient {
  private client: Redis | null = null;
  private isConnected: boolean = false;

  constructor() {
    this.connect();
  }

  private async connect(): Promise<void> {
    try {
      const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
      const redisPassword = process.env.REDIS_PASSWORD;

      this.client = new Redis(redisUrl, {
        password: redisPassword,
        retryDelayOnFailover: 100,
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
      throw new Error('Redis client not connected');
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

export const redisClient = redisClientInstance.getClient();

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
      logger.error('Redis SET error', { key, error });
      throw error;
    }
  },

  /**
   * Get a value by key
   */
  async get(key: string): Promise<string | null> {
    try {
      return await redisClient.get(key);
    } catch (error) {
      logger.error('Redis GET error', { key, error });
      return null;
    }
  },

  /**
   * Delete a key
   */
  async del(key: string): Promise<void> {
    try {
      await redisClient.del(key);
    } catch (error) {
      logger.error('Redis DEL error', { key, error });
      throw error;
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
      logger.error('Redis DELMANY error', { keys, error });
      throw error;
    }
  },

  /**
   * Find keys by pattern
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      return await redisClient.keys(pattern);
    } catch (error) {
      logger.error('Redis KEYS error', { pattern, error });
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
      logger.error('Redis HSET error', { key, field, error });
      throw error;
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
      logger.error('Redis INCR error', { key, error });
      throw error;
    }
  },

  /**
   * Increment a counter by amount
   */
  async incrBy(key: string, amount: number): Promise<number> {
    try {
      return await redisClient.incrby(key, amount);
    } catch (error) {
      logger.error('Redis INCRBY error', { key, amount, error });
      throw error;
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
      logger.error('Redis EXPIRE error', { key, ttl, error });
      throw error;
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