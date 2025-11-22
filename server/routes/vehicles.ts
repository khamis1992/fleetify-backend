/**
 * Vehicles API endpoints
 * Placeholder implementation - to be fully implemented following contracts pattern
 */

import { Router } from 'express';
import { requirePermission } from '../middleware/auth';

const router = Router();

// Placeholder routes - implement following the contracts pattern
router.get('/', requirePermission('vehicles:view'), (req, res) => {
  res.json({
    success: true,
    message: 'Vehicles endpoint - to be implemented',
    data: [],
  });
});

export default router;