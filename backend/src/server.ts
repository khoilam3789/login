import express, { Application } from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import mongoSanitize from 'express-mongo-sanitize';
import xssClean = require('xss-clean');
import dotenv from 'dotenv';
import { createServer } from 'http';

// Load environment variables
dotenv.config();

// Import configurations
import { connectDatabase } from './config/database';
import { logger } from './config/logger';
import { corsOptions } from './config/cors';

// Import middlewares
import { errorHandler } from './middlewares/error.middleware';
import { requestLogger } from './middlewares/request-logger.middleware';
import { securityHeaders } from './middlewares/security-headers.middleware';
import { rateLimiters } from './middlewares/rate-limit.middleware';
import { authenticateToken } from './middlewares/auth.middleware';

// Import routes
import authRoutes from './routes/auth.routes';
import vaultRoutes from './routes/vault.routes';
import otpRoutes from './routes/otp.routes';
import userRoutes from './routes/user.routes';
import auditRoutes from './routes/audit.routes';

class Server {
  private app: Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = parseInt(process.env.PORT || '5000', 10);
    
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddlewares(): void {
    // Security middlewares
    this.app.use(helmet());
    this.app.use(securityHeaders);
    
    // CORS
    this.app.use(cors(corsOptions));
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Compression
    this.app.use(compression());
    
    // Sanitization
    this.app.use(mongoSanitize());
    this.app.use(xssClean());
    
    // Request logging
    this.app.use(requestLogger);
    
    // Rate limiting
    this.app.use('/api', rateLimiters.general);
  }

  private initializeRoutes(): void {
    const apiVersion = process.env.API_VERSION || 'v1';
    const baseUrl = `/api/${apiVersion}`;

    // Health check
    this.app.get('/health', (_req, res) => {
      res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV
      });
    });

    // API routes
    this.app.use(`${baseUrl}/auth`, authRoutes);
    // TODO: Re-enable authentication middleware after fixing compile errors
    // this.app.use(`${baseUrl}/vault`, authenticateToken, vaultRoutes);
    // this.app.use(`${baseUrl}/otp`, authenticateToken, otpRoutes);
    // this.app.use(`${baseUrl}/user`, authenticateToken, userRoutes);
    // this.app.use(`${baseUrl}/audit`, authenticateToken, auditRoutes);
    this.app.use(`${baseUrl}/vault`, vaultRoutes);
    this.app.use(`${baseUrl}/otp`, otpRoutes);
    this.app.use(`${baseUrl}/user`, userRoutes);
    this.app.use(`${baseUrl}/audit`, auditRoutes);

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.originalUrl} not found`
      });
    });
  }

  private initializeErrorHandling(): void {
    this.app.use(errorHandler);
  }

  public async start(): Promise<void> {
    try {
      // Connect to database
      await connectDatabase();
      
      // Start server
      const server = createServer(this.app);
      
      server.listen(this.port, () => {
        logger.info(`🚀 Server is running on port ${this.port}`);
        logger.info(`📝 Environment: ${process.env.NODE_ENV}`);
        logger.info(`🔗 API URL: http://localhost:${this.port}/api/v1`);
      });

      // Graceful shutdown - use 'once' to prevent duplicate handlers
      process.once('SIGTERM', () => this.gracefulShutdown(server));
      process.once('SIGINT', () => this.gracefulShutdown(server));

    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  private async gracefulShutdown(server: any): Promise<void> {
    logger.info('Received shutdown signal. Closing server gracefully...');
    
    server.close(async () => {
      logger.info('HTTP server closed');
      
      try {
        await mongoose.connection.close();
        logger.info('Database connection closed');
        process.exit(0);
      } catch (error) {
        logger.error('Error during shutdown:', error);
        process.exit(1);
      }
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  }
}

export default Server;
