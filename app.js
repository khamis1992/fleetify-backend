/**
 * Simple Railway-compatible server with static imports
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { config } from 'dotenv';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import routes using static imports (avoiding dynamic import issues)
import authRoutes from './src/server/routes/auth.js';
import contractsRoutes from './src/server/routes/contracts.js';
import customersRoutes from './src/server/routes/customers.js';
import vehiclesRoutes from './src/server/routes/vehicles.js';
import employeesRoutes from './src/server/routes/employees.js';
import violationsRoutes from './src/server/routes/violations.js';
import invoicesRoutes from './src/server/routes/invoices.js';
import dashboardRoutes from './src/server/routes/dashboard.js';

// Import middleware
import { errorHandler } from './src/server/middleware/errorHandler.js';
import { requestLogger } from './src/server/middleware/requestLogger.js';
import { validateAuth } from './src/server/middleware/auth.js';
import { cacheMiddleware } from './src/server/middleware/cache.js';
import { rateLimitConfig } from './src/server/config/rateLimit.js';

// Load environment variables
config();

const app = express();
const server = createServer(app);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Compression middleware
app.use(compression());

// Request logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
  app.use(requestLogger);
}

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit(rateLimitConfig);
app.use('/api/', limiter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
  });
});

// API documentation
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'FleetifyApp API',
      version: '1.0.0',
      description: 'Secure backend API for FleetifyApp fleet management system',
    },
    servers: [
      {
        url: process.env.API_BASE_URL || 'http://localhost:3001',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        cookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'auth_token',
        },
      },
    },
  },
  apis: ['./src/server/routes/*.ts'],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// API routes
console.log('🔧 Loading API routes...');
app.use('/api/auth', authRoutes);
app.use('/api/contracts', validateAuth, cacheMiddleware(300), contractsRoutes);
app.use('/api/customers', validateAuth, cacheMiddleware(600), customersRoutes);
app.use('/api/vehicles', validateAuth, cacheMiddleware(300), vehiclesRoutes);
app.use('/api/employees', validateAuth, cacheMiddleware(600), employeesRoutes);
app.use('/api/violations', validateAuth, cacheMiddleware(300), violationsRoutes);
app.use('/api/invoices', validateAuth, cacheMiddleware(300), invoicesRoutes);
app.use('/api/dashboard', validateAuth, cacheMiddleware(180), dashboardRoutes);
console.log('✅ API routes loaded successfully');

// Basic API info endpoint
app.get('/api', (req, res) => {
  res.json({
    message: 'Fleetify Backend API',
    status: 'running',
    endpoints: {
      health: '/health',
      apiDocs: '/api-docs',
      info: '/api',
      auth: '/api/auth',
      vehicles: '/api/vehicles',
      contracts: '/api/contracts',
      dashboard: '/api/dashboard',
    },
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    supabaseConfigured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'API is working',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    supabaseConfigured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      '/health',
      '/api',
      '/api-docs',
      '/api/test',
      '/api/auth',
      '/api/vehicles',
      '/api/contracts',
      '/api/dashboard',
    ],
  });
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log(`🚀 Fleetify Backend API server running on port ${PORT}`);
  console.log(`📚 API Documentation: http://localhost:${PORT}/api-docs`);
  console.log(`🏥 Health Check: http://localhost:${PORT}/health`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✅ API Routes: Auth, Vehicles, Contracts, Dashboard loaded`);
});

export default app;