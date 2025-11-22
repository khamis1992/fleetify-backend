/**
 * Contracts API endpoints
 * Replaces direct Supabase calls from frontend
 */

import { Router } from 'express';
import { z } from 'zod';
import { createClient } from '@supabase/supabase-js';
import { asyncHandler, AppError } from '../middleware/errorHandler';
import { requirePermission, requireCompanyAccess } from '../middleware/auth';
import { invalidateCache } from '../middleware/cache';
import { logger } from '../utils/logger';
import { cacheHelpers } from '../utils/redis';

const router = Router();
const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// Validation schemas
const createContractSchema = z.object({
  customerId: z.string().uuid('Invalid customer ID'),
  vehicleId: z.string().uuid('Invalid vehicle ID').optional(),
  startDate: z.string().datetime('Invalid start date'),
  endDate: z.string().datetime('Invalid end date'),
  monthlyRate: z.number().min(0, 'Monthly rate must be positive'),
  contractNumber: z.string().min(1, 'Contract number is required'),
  notes: z.string().optional(),
});

const updateContractSchema = z.object({
  customerId: z.string().uuid('Invalid customer ID').optional(),
  vehicleId: z.string().uuid('Invalid vehicle ID').optional(),
  startDate: z.string().datetime('Invalid start date').optional(),
  endDate: z.string().datetime('Invalid end date').optional(),
  monthlyRate: z.number().min(0, 'Monthly rate must be positive').optional(),
  status: z.enum(['active', 'expired', 'cancelled', 'pending']).optional(),
  notes: z.string().optional(),
});

const queryContractsSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  status: z.enum(['active', 'expired', 'cancelled', 'pending']).optional(),
  customerId: z.string().uuid().optional(),
  vehicleId: z.string().uuid().optional(),
  search: z.string().optional(),
  sortBy: z.enum(['created_at', 'start_date', 'end_date', 'monthly_rate']).default('created_at'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

/**
 * @swagger
 * /api/contracts:
 *   get:
 *     summary: Get contracts with filtering and pagination
 *     tags: [Contracts]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, expired, cancelled, pending]
 *       - in: query
 *         name: customerId
 *         schema:
 *           type: string
 *           format: uuid
 *       - in: query
 *         name: vehicleId
 *         schema:
 *           type: string
 *           format: uuid
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [created_at, start_date, end_date, monthly_rate]
 *           default: created_at
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *     responses:
 *       200:
 *         description: Contracts retrieved successfully
 */
router.get('/', requirePermission('contracts:view'), asyncHandler(async (req, res) => {
  const {
    page,
    limit,
    status,
    customerId,
    vehicleId,
    search,
    sortBy,
    sortOrder
  } = queryContractsSchema.parse(req.query);

  const offset = (page - 1) * limit;
  const cacheKey = `contracts:${req.user!.companyId}:${JSON.stringify(req.query)}`;

  // Try cache first
  const cached = await cacheHelpers.get(cacheKey);
  if (cached) {
    return res.json({
      success: true,
      data: JSON.parse(cached),
    });
  }

  // Build the query
  let query = supabase
    .from('contracts')
    .select(`
      *,
      customers:customer_id (
        id,
        first_name_ar,
        last_name_ar,
        first_name,
        last_name,
        phone,
        email
      ),
      vehicles:vehicle_id (
        id,
        plate_number,
        make,
        model,
        year,
        color
      )
    `)
    .eq('company_id', req.user!.companyId);

  // Apply filters
  if (status) {
    query = query.eq('status', status);
  }
  if (customerId) {
    query = query.eq('customer_id', customerId);
  }
  if (vehicleId) {
    query = query.eq('vehicle_id', vehicleId);
  }
  if (search) {
    query = query.or(`contract_number.ilike.%${search}%,customers.first_name_ar.ilike.%${search}%,customers.last_name_ar.ilike.%${search}%,vehicles.plate_number.ilike.%${search}%`);
  }

  // Apply sorting and pagination
  const { data: contracts, error, count } = await query
    .order(sortBy, { ascending: sortOrder === 'asc' })
    .range(offset, offset + limit - 1);

  if (error) {
    logger.error('Database error fetching contracts', { error, userId: req.user?.id });
    throw new AppError('Failed to fetch contracts', 500, 'DATABASE_ERROR');
  }

  const response = {
    contracts: contracts || [],
    pagination: {
      page,
      limit,
      total: count || 0,
      pages: Math.ceil((count || 0) / limit),
    },
  };

  // Cache for 5 minutes
  await cacheHelpers.set(cacheKey, JSON.stringify(response), 300);

  res.json({
    success: true,
    data: response,
  });
}));

/**
 * @swagger
 * /api/contracts/{id}:
 *   get:
 *     summary: Get contract by ID
 *     tags: [Contracts]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Contract retrieved successfully
 *       404:
 *         description: Contract not found
 */
router.get('/:id', requirePermission('contracts:view'), asyncHandler(async (req, res) => {
  const { id } = req.params;

  const { data: contract, error } = await supabase
    .from('contracts')
    .select(`
      *,
      customers:customer_id (
        id,
        first_name_ar,
        last_name_ar,
        first_name,
        last_name,
        phone,
        email,
        address,
        id_number
      ),
      vehicles:vehicle_id (
        id,
        plate_number,
        make,
        model,
        year,
        color,
        vin,
        engine_number
      ),
      invoices (
        id,
        invoice_number,
        total_amount,
        payment_status,
        due_date,
        created_at
      )
    `)
    .eq('id', id)
    .eq('company_id', req.user!.companyId)
    .single();

  if (error || !contract) {
    throw new AppError('Contract not found', 404, 'CONTRACT_NOT_FOUND');
  }

  res.json({
    success: true,
    data: contract,
  });
}));

/**
 * @swagger
 * /api/contracts:
 *   post:
 *     summary: Create new contract
 *     tags: [Contracts]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - customerId
 *               - startDate
 *               - endDate
 *               - monthlyRate
 *               - contractNumber
 *             properties:
 *               customerId:
 *                 type: string
 *                 format: uuid
 *               vehicleId:
 *                 type: string
 *                 format: uuid
 *               startDate:
 *                 type: string
 *                 format: date-time
 *               endDate:
 *                 type: string
 *                 format: date-time
 *               monthlyRate:
 *                 type: number
 *               contractNumber:
 *                 type: string
 *               notes:
 *                 type: string
 *     responses:
 *       201:
 *         description: Contract created successfully
 *       400:
 *         description: Bad request
 */
router.post('/', requirePermission('contracts:create'), invalidateCache(['contracts:*']), asyncHandler(async (req, res) => {
  const validatedData = createContractSchema.parse(req.body);

  // Check if contract number already exists
  const { data: existingContract } = await supabase
    .from('contracts')
    .select('id')
    .eq('contract_number', validatedData.contractNumber)
    .eq('company_id', req.user!.companyId)
    .single();

  if (existingContract) {
    throw new AppError('Contract number already exists', 409, 'CONTRACT_NUMBER_EXISTS');
  }

  const { data: contract, error } = await supabase
    .from('contracts')
    .insert({
      company_id: req.user!.companyId,
      customer_id: validatedData.customerId,
      vehicle_id: validatedData.vehicleId,
      start_date: validatedData.startDate,
      end_date: validatedData.endDate,
      monthly_rate: validatedData.monthlyRate,
      contract_number: validatedData.contractNumber,
      notes: validatedData.notes,
      status: 'active',
      created_by: req.user!.id,
    })
    .select(`
      *,
      customers:customer_id (
        id,
        first_name_ar,
        last_name_ar,
        first_name,
        last_name,
        phone
      ),
      vehicles:vehicle_id (
        id,
        plate_number,
        make,
        model
      )
    `)
    .single();

  if (error || !contract) {
    logger.error('Database error creating contract', { error, userId: req.user?.id });
    throw new AppError('Failed to create contract', 500, 'DATABASE_ERROR');
  }

  logger.info('Contract created', {
    contractId: contract.id,
    contractNumber: contract.contract_number,
    userId: req.user?.id,
    companyId: req.user?.companyId,
  });

  res.status(201).json({
    success: true,
    data: contract,
    message: 'Contract created successfully',
  });
}));

/**
 * @swagger
 * /api/contracts/{id}:
 *   put:
 *     summary: Update contract
 *     tags: [Contracts]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               customerId:
 *                 type: string
 *                 format: uuid
 *               vehicleId:
 *                 type: string
 *                 format: uuid
 *               startDate:
 *                 type: string
 *                 format: date-time
 *               endDate:
 *                 type: string
 *                 format: date-time
 *               monthlyRate:
 *                 type: number
 *               status:
 *                 type: string
 *                 enum: [active, expired, cancelled, pending]
 *               notes:
 *                 type: string
 *     responses:
 *       200:
 *         description: Contract updated successfully
 *       404:
 *         description: Contract not found
 */
router.put('/:id', requirePermission('contracts:edit'), invalidateCache(['contracts:*']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const validatedData = updateContractSchema.parse(req.body);

  // Check if contract exists and belongs to user's company
  const { data: existingContract } = await supabase
    .from('contracts')
    .select('id, company_id')
    .eq('id', id)
    .eq('company_id', req.user!.companyId)
    .single();

  if (!existingContract) {
    throw new AppError('Contract not found', 404, 'CONTRACT_NOT_FOUND');
  }

  const { data: contract, error } = await supabase
    .from('contracts')
    .update({
      ...validatedData,
      updated_at: new Date().toISOString(),
      updated_by: req.user!.id,
    })
    .eq('id', id)
    .select(`
      *,
      customers:customer_id (
        id,
        first_name_ar,
        last_name_ar,
        first_name,
        last_name,
        phone
      ),
      vehicles:vehicle_id (
        id,
        plate_number,
        make,
        model
      )
    `)
    .single();

  if (error || !contract) {
    logger.error('Database error updating contract', { error, userId: req.user?.id });
    throw new AppError('Failed to update contract', 500, 'DATABASE_ERROR');
  }

  logger.info('Contract updated', {
    contractId: contract.id,
    contractNumber: contract.contract_number,
    userId: req.user?.id,
    changes: validatedData,
  });

  res.json({
    success: true,
    data: contract,
    message: 'Contract updated successfully',
  });
}));

/**
 * @swagger
 * /api/contracts/{id}:
 *   delete:
 *     summary: Delete contract
 *     tags: [Contracts]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Contract deleted successfully
 *       404:
 *         description: Contract not found
 *       403:
 *         description: Cannot delete contract with active invoices
 */
router.delete('/:id', requirePermission('contracts:delete'), invalidateCache(['contracts:*']), asyncHandler(async (req, res) => {
  const { id } = req.params;

  // Check if contract exists and belongs to user's company
  const { data: existingContract } = await supabase
    .from('contracts')
    .select(`
      id,
      company_id,
      invoices (
        id,
        payment_status
      )
    `)
    .eq('id', id)
    .eq('company_id', req.user!.companyId)
    .single();

  if (!existingContract) {
    throw new AppError('Contract not found', 404, 'CONTRACT_NOT_FOUND');
  }

  // Check if contract has unpaid invoices
  const hasUnpaidInvoices = existingContract.invoices?.some(
    invoice => invoice.payment_status !== 'paid'
  );

  if (hasUnpaidInvoices) {
    throw new AppError('Cannot delete contract with unpaid invoices', 403, 'HAS_UNPAID_INVOICES');
  }

  const { error } = await supabase
    .from('contracts')
    .delete()
    .eq('id', id);

  if (error) {
    logger.error('Database error deleting contract', { error, userId: req.user?.id });
    throw new AppError('Failed to delete contract', 500, 'DATABASE_ERROR');
  }

  logger.info('Contract deleted', {
    contractId: id,
    userId: req.user?.id,
  });

  res.json({
    success: true,
    message: 'Contract deleted successfully',
  });
}));

/**
 * @swagger
 * /api/contracts/stats:
 *   get:
 *     summary: Get contract statistics for dashboard
 *     tags: [Contracts]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Contract statistics retrieved successfully
 */
router.get('/stats', requirePermission('contracts:view'), asyncHandler(async (req, res) => {
  const cacheKey = `contracts:stats:${req.user!.companyId}`;

  // Try cache first
  const cached = await cacheHelpers.get(cacheKey);
  if (cached) {
    return res.json({
      success: true,
      data: JSON.parse(cached),
    });
  }

  // Get contract statistics
  const { data: stats, error } = await supabase
    .from('contracts')
    .select('status')
    .eq('company_id', req.user!.companyId);

  if (error) {
    logger.error('Database error fetching contract stats', { error, userId: req.user?.id });
    throw new AppError('Failed to fetch contract statistics', 500, 'DATABASE_ERROR');
  }

  const statistics = {
    total: stats?.length || 0,
    active: stats?.filter(c => c.status === 'active').length || 0,
    expired: stats?.filter(c => c.status === 'expired').length || 0,
    cancelled: stats?.filter(c => c.status === 'cancelled').length || 0,
    pending: stats?.filter(c => c.status === 'pending').length || 0,
  };

  // Cache for 10 minutes
  await cacheHelpers.set(cacheKey, JSON.stringify(statistics), 600);

  res.json({
    success: true,
    data: statistics,
  });
}));

export default router;