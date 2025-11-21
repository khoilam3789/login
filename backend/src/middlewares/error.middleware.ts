import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';

export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction
) => {
  if (err instanceof AppError) {
    logger.error({
      message: err.message,
      statusCode: err.statusCode,
      stack: err.stack,
      path: req.path,
      method: req.method
    });

    return res.status(err.statusCode).json({
      success: false,
      message: err.message
    });
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    logger.error('Validation error:', err);
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: err.message
    });
  }

  // Mongoose duplicate key error
  if (err.name === 'MongoError' && (err as any).code === 11000) {
    logger.error('Duplicate key error:', err);
    return res.status(409).json({
      success: false,
      message: 'Duplicate entry'
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    });
  }

  // Default error
  logger.error('Unhandled error:', err);
  return res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
};
