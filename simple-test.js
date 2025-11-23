/**
 * Simple test server to verify Railway deployment works
 */

import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';

// Load environment variables
config();

const app = express();
const PORT = process.env.PORT || 3001;

// Basic middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    message: 'Simple test server is working!',
  });
});

// Test auth route
app.get('/api/auth', (req, res) => {
  res.json({
    message: 'Auth route is working!',
    timestamp: new Date().toISOString(),
    supabaseConfigured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
  });
});

// Test login route
app.post('/api/auth/login', (req, res) => {
  res.json({
    message: 'Login endpoint is working!',
    timestamp: new Date().toISOString(),
    received: req.body,
    supabaseConfigured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
  });
});

// Test vehicles route
app.get('/api/vehicles', (req, res) => {
  res.json({
    message: 'Vehicles route is working!',
    timestamp: new Date().toISOString(),
    vehicles: [],
  });
});

// Main API info
app.get('/api', (req, res) => {
  res.json({
    message: 'Fleetify Backend API',
    status: 'running',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    endpoints: {
      health: '/health',
      auth: '/api/auth',
      login: '/api/auth/login',
      vehicles: '/api/vehicles',
    },
    supabaseConfigured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Simple test server running on port ${PORT}`);
  console.log(`🏥 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔑 Test Auth: http://localhost:${PORT}/api/auth`);
  console.log(`🚗 Test Vehicles: http://localhost:${PORT}/api/vehicles`);
  console.log(`⚙️ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Supabase Configured: ${!!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)}`);
});