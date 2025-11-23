/**
 * Minimal auth routes for debugging
 */

import { Router } from 'express';

const router = Router();

// Test endpoint
router.get('/test', (req, res) => {
  res.json({
    message: 'Auth routes are working!',
    timestamp: new Date().toISOString()
  });
});

// Default endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'Auth routes endpoint',
    availableRoutes: ['/test', '/login', '/register']
  });
});

export default router;