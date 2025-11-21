import { Request, Response } from 'express';
import { User } from '../models/user.model';
import { ExternalSecret } from '../models/external-secret.model';
import { OTPService } from '../services/otp.service';
import { logger } from '../config/logger';

export class OTPController {
  /**
   * Setup 2FA for user account
   */
  static async setup2FA(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId; // From auth middleware
      const user = await User.findById(userId);

      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
        });
        return;
      }

      if (user.twoFactorEnabled) {
        res.status(400).json({
          success: false,
          message: '2FA is already enabled',
        });
        return;
      }

      // Generate new TOTP secret
      const secret = OTPService.generateTOTPSecret();
      const setupData = await OTPService.setupTOTP(user.email, secret);

      // Generate backup codes
      const backupCodes = OTPService.generateBackupCodes(10);

      // Save secret (temporarily, until verified)
      user.twoFactorSecret = secret;
      await user.save();

      logger.info(`2FA setup initiated for user: ${user.email}`);

      res.status(200).json({
        success: true,
        data: {
          qrCode: setupData.qrCodeUrl,
          manualCode: setupData.manualEntryCode,
          backupCodes: backupCodes,
        },
      });
    } catch (error) {
      logger.error('2FA setup error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to setup 2FA',
      });
    }
  }

  /**
   * Verify and enable 2FA
   */
  static async verify2FA(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { token, backupCodes } = req.body;

      if (!token) {
        res.status(400).json({
          success: false,
          message: 'OTP token is required',
        });
        return;
      }

      const user = await User.findById(userId).select('+twoFactorSecret');

      if (!user || !user.twoFactorSecret) {
        res.status(400).json({
          success: false,
          message: '2FA setup not initiated',
        });
        return;
      }

      // Verify token
      const verification = OTPService.verifyTOTP(token, user.twoFactorSecret);

      if (!verification.isValid) {
        res.status(400).json({
          success: false,
          message: 'Invalid OTP code',
        });
        return;
      }

      // Enable 2FA
      user.twoFactorEnabled = true;
      if (backupCodes && Array.isArray(backupCodes)) {
        user.backupCodes = backupCodes;
      }
      await user.save();

      logger.info(`2FA enabled for user: ${user.email}`);

      res.status(200).json({
        success: true,
        message: '2FA enabled successfully',
      });
    } catch (error) {
      logger.error('2FA verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to verify 2FA',
      });
    }
  }

  /**
   * Disable 2FA
   */
  static async disable2FA(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { password, token } = req.body;

      if (!password || !token) {
        res.status(400).json({
          success: false,
          message: 'Password and OTP token are required',
        });
        return;
      }

      const user = await User.findById(userId).select('+twoFactorSecret +passwordHash');

      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
        });
        return;
      }

      // Verify password (you should implement proper password verification)
      // For now, assuming password is already hashed
      if (user.passwordHash !== password) {
        res.status(401).json({
          success: false,
          message: 'Invalid password',
        });
        return;
      }

      // Verify OTP
      if (user.twoFactorSecret) {
        const verification = OTPService.verifyTOTP(token, user.twoFactorSecret);
        if (!verification.isValid) {
          res.status(400).json({
            success: false,
            message: 'Invalid OTP code',
          });
          return;
        }
      }

      // Disable 2FA
      user.twoFactorEnabled = false;
      user.twoFactorSecret = undefined;
      user.backupCodes = undefined;
      await user.save();

      logger.info(`2FA disabled for user: ${user.email}`);

      res.status(200).json({
        success: true,
        message: '2FA disabled successfully',
      });
    } catch (error) {
      logger.error('2FA disable error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to disable 2FA',
      });
    }
  }

  /**
   * Get all external secrets
   */
  static async getExternalSecrets(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { category } = req.query;

      const query: any = { userId };
      if (category) {
        query.category = category;
      }

      const secrets = await ExternalSecret.find(query)
        .select('-encryptedSecret') // Don't send encrypted secret in list
        .sort({ lastUsed: -1, createdAt: -1 });

      res.status(200).json({
        success: true,
        data: secrets,
      });
    } catch (error) {
      logger.error('Get external secrets error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve secrets',
      });
    }
  }

  /**
   * Get single external secret (with decryption on client side)
   */
  static async getExternalSecret(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { id } = req.params;

      const secret = await ExternalSecret.findOne({ _id: id, userId });

      if (!secret) {
        res.status(404).json({
          success: false,
          message: 'Secret not found',
        });
        return;
      }

      // Update last used
      secret.lastUsed = new Date();
      await secret.save();

      res.status(200).json({
        success: true,
        data: secret,
      });
    } catch (error) {
      logger.error('Get external secret error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve secret',
      });
    }
  }

  /**
   * Add new external secret
   */
  static async addExternalSecret(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { name, issuer, encryptedSecret, accountName, icon, category, notes } = req.body;

      if (!name || !issuer || !encryptedSecret) {
        res.status(400).json({
          success: false,
          message: 'Name, issuer, and encrypted secret are required',
        });
        return;
      }

      const secret = await ExternalSecret.create({
        userId,
        name,
        issuer,
        encryptedSecret,
        accountName,
        icon,
        category,
        notes,
      });

      logger.info(`External secret added for user: ${userId}`);

      res.status(201).json({
        success: true,
        data: secret,
      });
    } catch (error) {
      logger.error('Add external secret error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to add secret',
      });
    }
  }

  /**
   * Update external secret
   */
  static async updateExternalSecret(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { id } = req.params;
      const { name, issuer, encryptedSecret, accountName, icon, category, notes } = req.body;

      const secret = await ExternalSecret.findOne({ _id: id, userId });

      if (!secret) {
        res.status(404).json({
          success: false,
          message: 'Secret not found',
        });
        return;
      }

      // Update fields
      if (name) secret.name = name;
      if (issuer) secret.issuer = issuer;
      if (encryptedSecret) secret.encryptedSecret = encryptedSecret;
      if (accountName !== undefined) secret.accountName = accountName;
      if (icon !== undefined) secret.icon = icon;
      if (category) secret.category = category;
      if (notes !== undefined) secret.notes = notes;

      await secret.save();

      logger.info(`External secret updated: ${id}`);

      res.status(200).json({
        success: true,
        data: secret,
      });
    } catch (error) {
      logger.error('Update external secret error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update secret',
      });
    }
  }

  /**
   * Delete external secret
   */
  static async deleteExternalSecret(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { id } = req.params;

      const result = await ExternalSecret.deleteOne({ _id: id, userId });

      if (result.deletedCount === 0) {
        res.status(404).json({
          success: false,
          message: 'Secret not found',
        });
        return;
      }

      logger.info(`External secret deleted: ${id}`);

      res.status(200).json({
        success: true,
        message: 'Secret deleted successfully',
      });
    } catch (error) {
      logger.error('Delete external secret error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to delete secret',
      });
    }
  }

  /**
   * Generate current OTP code for external secret
   */
  static async generateOTP(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.userId;
      const { id } = req.params;
      const { userKey } = req.body; // Client sends their key for decryption

      if (!userKey) {
        res.status(400).json({
          success: false,
          message: 'User key is required for decryption',
        });
        return;
      }

      const secret = await ExternalSecret.findOne({ _id: id, userId });

      if (!secret) {
        res.status(404).json({
          success: false,
          message: 'Secret not found',
        });
        return;
      }

      // Note: In production, decryption should happen on client side
      // This is just for demonstration
      try {
        const decryptedSecret = OTPService.decryptSecret(secret.encryptedSecret, userKey);
        const otpCode = OTPService.generateCurrentTOTP(decryptedSecret);
        const timeRemaining = OTPService.getTimeRemaining();

        // Update last used
        secret.lastUsed = new Date();
        await secret.save();

        res.status(200).json({
          success: true,
          data: {
            code: otpCode,
            expiresIn: timeRemaining,
          },
        });
      } catch (error) {
        res.status(400).json({
          success: false,
          message: 'Failed to decrypt secret or generate OTP',
        });
      }
    } catch (error) {
      logger.error('Generate OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to generate OTP',
      });
    }
  }
}

export default OTPController;
