/**
 * Direct Railway-compatible backend server entry point
 * This ensures Railway finds and loads the correct server with all routes
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
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Change to server directory for proper module resolution
process.chdir(join(__dirname, 'src/server'));

// Import routes from server directory
try {
  var authRoutes = await import('./routes/auth.js');
  var contractsRoutes = await import('./routes/contracts.js');
  var customersRoutes = await import('./routes/customers.js');
  var vehiclesRoutes = await import('./routes/vehicles.js');
  var employeesRoutes = await import('./routes/employees.js');
  var violationsRoutes = await import('./routes/violations.js');
  var invoicesRoutes = await import('./routes/invoices.js');
  var dashboardRoutes = await import('./routes/dashboard.js');

  // Import middleware
  var { errorHandler } = await import('./middleware/errorHandler.js');
  var { requestLogger } = await import('./middleware/requestLogger.js');
  var { validateAuth } = await import('./middleware/auth.js');
  var { cacheMiddleware } = await import('./middleware/cache.js');
  var { rateLimitConfig } = await import('./config/rateLimit.js');

  console.log('✅ Successfully imported all routes and middleware');
} catch (error) {
  console.error('❌ Failed to import routes/middleware:', error.message);
  console.log('🔄 Falling back to basic server mode...');
}

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
  if (requestLogger) {
    app.use(requestLogger);
  }
}

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit(rateLimitConfig || {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
  });
});

// Basic API info endpoint (fallback)
app.get('/api', (req, res) => {
  res.status(200).json({
    message: 'Fleetify Backend API',
    status: 'running',
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'production',
    routes: authRoutes ? ['Auth', 'Contracts', 'Customers', 'Vehicles', 'Employees', 'Violations', 'Invoices', 'Dashboard'] : ['Basic mode - routes failed to load']
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
        description: 'Production server',
      },
    ],
  },
  apis: ['./src/server/routes/*.ts'],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// API routes (only if successfully imported)
if (authRoutes && authRoutes.default) {
  app.use('/api/auth', authRoutes.default);
  console.log('✅ Auth routes loaded');
} else {
  console.log('⚠️ Auth routes not loaded - using fallback');
  app.get('/api/auth', (req, res) => {
    res.status(503).json({ error: 'Auth routes not available', message: 'Server running in degraded mode' });
  });
}

if (contractsRoutes && contractsRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/contracts', validateAuth, cacheMiddleware(300), contractsRoutes.default);
  console.log('✅ Contracts routes loaded');
}

if (customersRoutes && customersRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/customers', validateAuth, cacheMiddleware(600), customersRoutes.default);
  console.log('✅ Customers routes loaded');
}

if (vehiclesRoutes && vehiclesRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/vehicles', validateAuth, cacheMiddleware(300), vehiclesRoutes.default);
  console.log('✅ Vehicles routes loaded');
}

if (employeesRoutes && employeesRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/employees', validateAuth, cacheMiddleware(600), employeesRoutes.default);
  console.log('✅ Employees routes loaded');
}

if (violationsRoutes && violationsRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/violations', validateAuth, cacheMiddleware(300), violationsRoutes.default);
  console.log('✅ Violations routes loaded');
}

if (invoicesRoutes && invoicesRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/invoices', validateAuth, cacheMiddleware(300), invoicesRoutes.default);
  console.log('✅ Invoices routes loaded');
}

if (dashboardRoutes && dashboardRoutes.default && validateAuth && cacheMiddleware) {
  app.use('/api/dashboard', validateAuth, cacheMiddleware(180), dashboardRoutes.default);
  console.log('✅ Dashboard routes loaded');
}

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'API is working!',
    timestamp: new Date().toISOString(),
    routes: {
      auth: !!authRoutes?.default,
      contracts: !!contractsRoutes?.default,
      customers: !!customersRoutes?.default,
      vehicles: !!vehiclesRoutes?.default,
      employees: !!employeesRoutes?.default,
      violations: !!violationsRoutes?.default,
      invoices: !!invoicesRoutes?.default,
      dashboard: !!dashboardRoutes?.default
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    timestamp: new Date().toISOString(),
    availableEndpoints: ['/health', '/api', '/api-docs', '/api/test']
  });
});

// Error handling middleware (must be last)
if (errorHandler) {
  app.use(errorHandler);
} else {
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
    });
  });
}

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
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'production'}`);
  console.log(`✅ Routes status: ${authRoutes?.default ? 'Loaded' : 'Failed to load'}`);
});

export default app;