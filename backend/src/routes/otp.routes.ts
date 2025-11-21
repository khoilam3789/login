import { Router } from 'express';
import { otpLimiter } from '../middlewares/rate-limit.middleware';
import { OTPController } from '../controllers/otp.controller';

const router = Router();

// 2FA Management
// POST /api/v1/otp/2fa/setup - Setup 2FA for user account
router.post('/2fa/setup', OTPController.setup2FA);

// POST /api/v1/otp/2fa/verify - Verify and enable 2FA
router.post('/2fa/verify', OTPController.verify2FA);

// POST /api/v1/otp/2fa/disable - Disable 2FA
router.post('/2fa/disable', OTPController.disable2FA);

// External TOTP Secrets Management
// GET /api/v1/otp/external-secrets - Get all external TOTP secrets
router.get('/external-secrets', OTPController.getExternalSecrets);

// GET /api/v1/otp/external-secrets/:id - Get single external secret
router.get('/external-secrets/:id', OTPController.getExternalSecret);

// POST /api/v1/otp/external-secrets - Add new external TOTP secret
router.post('/external-secrets', OTPController.addExternalSecret);

// PUT /api/v1/otp/external-secrets/:id - Update external TOTP secret
router.put('/external-secrets/:id', OTPController.updateExternalSecret);

// DELETE /api/v1/otp/external-secrets/:id - Delete external TOTP secret
router.delete('/external-secrets/:id', OTPController.deleteExternalSecret);

// POST /api/v1/otp/external-secrets/:id/generate - Generate OTP code
router.post('/external-secrets/:id/generate', otpLimiter, OTPController.generateOTP);

export default router;
