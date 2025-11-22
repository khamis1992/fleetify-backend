/**
 * Backend API Server for FleetifyApp
 * Provides secure API endpoints replacing direct Supabase calls from frontend
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

// Import routes
import authRoutes from './routes/auth';
import contractsRoutes from './routes/contracts';
import customersRoutes from './routes/customers';
import vehiclesRoutes from './routes/vehicles';
import employeesRoutes from './routes/employees';
import violationsRoutes from './routes/violations';
import invoicesRoutes from './routes/invoices';
import dashboardRoutes from './routes/dashboard';

// Import middleware
import { errorHandler } from './middleware/errorHandler';
import { requestLogger } from './middleware/requestLogger';
import { validateAuth } from './middleware/auth';
import { cacheMiddleware } from './middleware/cache';
import { rateLimitConfig } from './config/rateLimit';

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
app.use('/api/auth', authRoutes);
app.use('/api/contracts', validateAuth, cacheMiddleware(300), contractsRoutes);
app.use('/api/customers', validateAuth, cacheMiddleware(600), customersRoutes);
app.use('/api/vehicles', validateAuth, cacheMiddleware(300), vehiclesRoutes);
app.use('/api/employees', validateAuth, cacheMiddleware(600), employeesRoutes);
app.use('/api/violations', validateAuth, cacheMiddleware(300), violationsRoutes);
app.use('/api/invoices', validateAuth, cacheMiddleware(300), invoicesRoutes);
app.use('/api/dashboard', validateAuth, cacheMiddleware(180), dashboardRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    timestamp: new Date().toISOString(),
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
  console.log(`🚀 Backend API server running on port ${PORT}`);
  console.log(`📚 API Documentation: http://localhost:${PORT}/api-docs`);
  console.log(`🏥 Health Check: http://localhost:${PORT}/health`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

export default app;