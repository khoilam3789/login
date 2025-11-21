import { Router } from 'express';
import { authLimiter } from '../middlewares/rate-limit.middleware';
import { AuthController } from '../controllers/auth.controller';

const router = Router();

// POST /api/v1/auth/register
router.post('/register', authLimiter, AuthController.register);

// POST /api/v1/auth/verify-email
router.post('/verify-email', AuthController.verifyEmail);

// POST /api/v1/auth/resend-verification
router.post('/resend-verification', authLimiter, AuthController.resendVerification);

// POST /api/v1/auth/login
router.post('/login', authLimiter, AuthController.login);

// POST /api/v1/auth/logout
router.post('/logout', AuthController.logout);

// POST /api/v1/auth/refresh
router.post('/refresh', AuthController.refresh);

// POST /api/v1/auth/get-salt
router.post('/get-salt', AuthController.getSalt);

export default router;
