import { Router } from 'express';
import { authLimiter } from '../middlewares/rate-limit.middleware';
import { AuthController } from '../controllers/auth.controller';

const router = Router();

// POST /api/v1/auth/register
router.post('/register', AuthController.register);

// POST /api/v1/auth/verify-email
router.post('/verify-email', AuthController.verifyEmail);

// POST /api/v1/auth/resend-verification
router.post('/resend-verification', AuthController.resendVerification);

// POST /api/v1/auth/login
router.post('/login', AuthController.login);

// POST /api/v1/auth/verify-2fa-login - Verify OTP for 2FA login
router.post('/verify-2fa-login', AuthController.verify2FALogin);

// POST /api/v1/auth/logout
router.post('/logout', AuthController.logout);

// POST /api/v1/auth/refresh
router.post('/refresh', AuthController.refresh);

// POST /api/v1/auth/get-salt
router.post('/get-salt', AuthController.getSalt);

// POST /api/v1/auth/toggle-2fa - Toggle 2FA for user (requires auth)
router.post('/toggle-2fa', AuthController.toggle2FA);

export default router;
