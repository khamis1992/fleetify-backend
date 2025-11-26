/**
 * Customers API endpoints
 * Manages customer data and operations
 */

import { Router } from 'express';
import { requirePermission, requireCompanyAccess } from '../middleware/auth';
import { asyncHandler, AppError } from '../middleware/errorHandler';
import { createClient } from '@supabase/supabase-js';
import { logger } from '../utils/logger';
import { z } from 'zod';

const router = Router();

// Supabase client
let supabase: ReturnType<typeof createClient> | null = null;

if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
}

// Validation schemas
const createCustomerSchema = z.object({
  name: z.string().min(1, 'Customer name is required'),
  email: z.string().email('Invalid email format'),
  phone: z.string().optional(),
  address: z.string().optional(),
  city: z.string().optional(),
  country: z.string().optional(),
  type: z.enum(['individual', 'corporate']).default('individual'),
});

const updateCustomerSchema = createCustomerSchema.partial();

/**
 * @swagger
 * /api/customers:
 *   get:
 *     summary: Get all customers
 *     tags: [Customers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Number of records to return
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *         description: Number of records to skip
 *     responses:
 *       200:
 *         description: Customers retrieved successfully
 *       401:
 *         description: Not authenticated
 */
router.get('/', requirePermission('customers:view'), asyncHandler(async (req, res) => {
  try {
    if (!req.user) {
      throw new AppError('User not authenticated', 401);
    }

    // Mock data for customers
    const mockCustomers = [
      {
        id: '1',
        name: 'Acme Corporation',
        email: 'contact@acme.com',
        phone: '+1-555-0100',
        address: '123 Business St',
        city: 'New York',
        country: 'USA',
        type: 'corporate',
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '2',
        name: 'John Smith',
        email: 'john@example.com',
        phone: '+1-555-0101',
        address: '456 Main Ave',
        city: 'Los Angeles',
        country: 'USA',
        type: 'individual',
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '3',
        name: 'Global Industries Ltd',
        email: 'info@globalind.com',
        phone: '+44-20-7946-0958',
        address: '789 Industrial Blvd',
        city: 'London',
        country: 'UK',
        type: 'corporate',
        createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      },
    ];

    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const offset = parseInt(req.query.offset as string) || 0;

    const paginatedCustomers = mockCustomers.slice(offset, offset + limit);

    logger.info('Customers retrieved', {
      userId: req.user.id,
      count: paginatedCustomers.length,
      total: mockCustomers.length,
    });

    res.json({
      success: true,
      data: paginatedCustomers,
      pagination: {
        limit,
        offset,
        total: mockCustomers.length,
        hasMore: offset + limit < mockCustomers.length,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Error fetching customers', { error });
    throw new AppError('Failed to fetch customers', 500, true, 'FETCH_ERROR');
  }
}));

/**
 * @swagger
 * /api/customers/{id}:
 *   get:
 *     summary: Get customer by ID
 *     tags: [Customers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Customer retrieved successfully
 *       404:
 *         description: Customer not found
 */
router.get('/:id', requirePermission('customers:view'), asyncHandler(async (req, res) => {
  try {
    if (!req.user) {
      throw new AppError('User not authenticated', 401);
    }

    const { id } = req.params;

    // Mock customer data
    const mockCustomer = {
      id,
      name: 'Acme Corporation',
      email: 'contact@acme.com',
      phone: '+1-555-0100',
      address: '123 Business St',
      city: 'New York',
      country: 'USA',
      type: 'corporate',
      createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      contracts: 5,
      totalSpent: '€45,000',
    };

    if (!mockCustomer) {
      throw new AppError('Customer not found', 404, true, 'NOT_FOUND');
    }

    logger.info('Customer retrieved', { userId: req.user.id, customerId: id });

    res.json({
      success: true,
      data: mockCustomer,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Error fetching customer', { error });
    throw new AppError('Failed to fetch customer', 500, true, 'FETCH_ERROR');
  }
}));

/**
 * @swagger
 * /api/customers:
 *   post:
 *     summary: Create new customer
 *     tags: [Customers]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: string
 *               city:
 *                 type: string
 *               country:
 *                 type: string
 *               type:
 *                 type: string
 *                 enum: [individual, corporate]
 *     responses:
 *       201:
 *         description: Customer created successfully
 *       400:
 *         description: Invalid input
 */
router.post('/', requirePermission('customers:create'), asyncHandler(async (req, res) => {
  try {
    if (!req.user) {
      throw new AppError('User not authenticated', 401);
    }

    const validatedData = createCustomerSchema.parse(req.body);

    // Create customer (mock)
    const newCustomer = {
      id: Math.random().toString(36).substr(2, 9),
      ...validatedData,
      createdAt: new Date().toISOString(),
    };

    logger.info('Customer created', {
      userId: req.user.id,
      customerId: newCustomer.id,
      customerName: validatedData.name,
    });

    res.status(201).json({
      success: true,
      message: 'Customer created successfully',
      data: newCustomer,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Error creating customer', { error });
    throw new AppError('Failed to create customer', 500, true, 'CREATE_ERROR');
  }
}));

/**
 * @swagger
 * /api/customers/{id}:
 *   put:
 *     summary: Update customer
 *     tags: [Customers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Customer updated successfully
 *       404:
 *         description: Customer not found
 */
router.put('/:id', requirePermission('customers:update'), asyncHandler(async (req, res) => {
  try {
    if (!req.user) {
      throw new AppError('User not authenticated', 401);
    }

    const { id } = req.params;
    const validatedData = updateCustomerSchema.parse(req.body);

    // Update customer (mock)
    const updatedCustomer = {
      id,
      ...validatedData,
      updatedAt: new Date().toISOString(),
    };

    logger.info('Customer updated', { userId: req.user.id, customerId: id });

    res.json({
      success: true,
      message: 'Customer updated successfully',
      data: updatedCustomer,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Error updating customer', { error });
    throw new AppError('Failed to update customer', 500, true, 'UPDATE_ERROR');
  }
}));

/**
 * @swagger
 * /api/customers/{id}:
 *   delete:
 *     summary: Delete customer
 *     tags: [Customers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Customer deleted successfully
 *       404:
 *         description: Customer not found
 */
router.delete('/:id', requirePermission('customers:delete'), asyncHandler(async (req, res) => {
  try {
    if (!req.user) {
      throw new AppError('User not authenticated', 401);
    }

    const { id } = req.params;

    logger.info('Customer deleted', { userId: req.user.id, customerId: id });

    res.json({
      success: true,
      message: 'Customer deleted successfully',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Error deleting customer', { error });
    throw new AppError('Failed to delete customer', 500, true, 'DELETE_ERROR');
  }
}));

export default router;
