/**
 * Dashboard API endpoints
 * Provides dashboard statistics and overview data
 */

import { Router } from 'express';
import { requirePermission } from '../middleware/auth';
import { asyncHandler, AppError } from '../middleware/errorHandler';
import { createClient } from '@supabase/supabase-js';
import { logger } from '../utils/logger';

const router = Router();

// Supabase client
let supabase: ReturnType<typeof createClient> | null = null;

if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
}

/**
 * @swagger
 * /api/dashboard:
 *   get:
 *     summary: Get dashboard overview and statistics
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard data retrieved successfully
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Insufficient permissions
 */
router.get('/', requirePermission('dashboard:view'), asyncHandler(async (req, res) => {
  try {
    if (!req.user) {
      throw new AppError('User not authenticated', 401);
    }

    // Mock data for dashboard - replace with real Supabase queries
    const dashboardData = {
      stats: {
        activeCompanies: 156,
        monthlyRevenue: '€524,300',
        totalTransactions: 1256,
        growthRate: '+18%',
        activeUsers: 847,
        uptime: '99.9%',
        monthlyTransactions: '€1.2M',
      },
      charts: {
        revenueByMonth: [
          { month: 'Jan', revenue: 45000 },
          { month: 'Feb', revenue: 52000 },
          { month: 'Mar', revenue: 48000 },
          { month: 'Apr', revenue: 61000 },
          { month: 'May', revenue: 55000 },
          { month: 'Jun', revenue: 67000 },
        ],
        transactionsByType: [
          { type: 'Rentals', count: 450 },
          { type: 'Sales', count: 320 },
          { type: 'Services', count: 280 },
          { type: 'Other', count: 206 },
        ],
      },
      recentActivity: [
        {
          id: '1',
          type: 'contract_created',
          description: 'New rental contract created',
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          user: 'John Doe',
        },
        {
          id: '2',
          type: 'payment_received',
          description: 'Payment received for contract #12345',
          timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
          user: 'Jane Smith',
        },
        {
          id: '3',
          type: 'vehicle_maintenance',
          description: 'Vehicle maintenance completed',
          timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
          user: 'Mike Johnson',
        },
      ],
      alerts: [
        {
          id: '1',
          severity: 'warning',
          message: 'Vehicle maintenance due in 3 days',
          timestamp: new Date().toISOString(),
        },
        {
          id: '2',
          severity: 'info',
          message: 'New contract pending approval',
          timestamp: new Date().toISOString(),
        },
      ],
    };

    // If Supabase is configured, fetch real data
    if (supabase && req.user.companyId) {
      try {
        // Fetch real contracts count
        const { count: contractsCount } = await supabase
          .from('contracts')
          .select('*', { count: 'exact', head: true })
          .eq('company_id', req.user.companyId);

        // Fetch real vehicles count
        const { count: vehiclesCount } = await supabase
          .from('vehicles')
          .select('*', { count: 'exact', head: true })
          .eq('company_id', req.user.companyId);

        // Fetch real customers count
        const { count: customersCount } = await supabase
          .from('customers')
          .select('*', { count: 'exact', head: true })
          .eq('company_id', req.user.companyId);

        // Update stats with real data
        dashboardData.stats = {
          ...dashboardData.stats,
          activeContracts: contractsCount || 0,
          totalVehicles: vehiclesCount || 0,
          totalCustomers: customersCount || 0,
        };

        logger.info('Dashboard data fetched from Supabase', {
          userId: req.user.id,
          companyId: req.user.companyId,
        });
      } catch (error) {
        logger.warn('Failed to fetch real dashboard data from Supabase', {
          error: (error as Error).message,
          userId: req.user.id,
        });
        // Continue with mock data if Supabase query fails
      }
    }

    res.json({
      success: true,
      data: dashboardData,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    logger.error('Dashboard error', { error });
    throw new AppError('Failed to fetch dashboard data', 500, true, 'DASHBOARD_ERROR');
  }
}));

/**
 * @swagger
 * /api/dashboard/metrics:
 *   get:
 *     summary: Get detailed metrics
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Metrics retrieved successfully
 */
router.get('/metrics', requirePermission('dashboard:view'), asyncHandler(async (req, res) => {
  const metrics = {
    activeCompanies: 156,
    monthlyRevenue: '€524,300',
    totalTransactions: 1256,
    growthRate: '+18%',
    activeUsers: 847,
    uptime: '99.9%',
    monthlyTransactions: '€1.2M',
    averageContractValue: '€3,200',
    customerSatisfaction: '98.5%',
  };

  res.json({
    success: true,
    data: metrics,
    timestamp: new Date().toISOString(),
  });
}));

export default router;
