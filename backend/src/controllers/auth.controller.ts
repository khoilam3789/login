import { Request, Response } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.model';
import { RefreshToken } from '../models/refresh-token.model';
import { EmailService } from '../services/email.service';
import { logger } from '../config/logger';

const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-change-in-production';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-change-in-production';
const JWT_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN = '7d';

interface RegisterRequest {
  email: string;
  authKeyHash: string;
  salt: string;
  encryptedDEK: string;
  dekIV: string;
}

interface LoginRequest {
  email: string;
  authKeyHash: string;
}

export class AuthController {
  /**
   * Register a new user
   */
  static async register(req: Request, res: Response): Promise<void> {
    try {
      const {
        email,
        authKeyHash,
        salt,
        encryptedDEK,
        dekIV,
      } = req.body as RegisterRequest;

      // Validate required fields
      if (!email || !authKeyHash || !salt || !encryptedDEK || !dekIV) {
        res.status(400).json({
          success: false,
          message: 'All fields are required',
        });
        return;
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email });

      if (existingUser) {
        res.status(409).json({
          success: false,
          message: 'Email already registered',
        });
        return;
      }

      // Generate username from email
      const username = email.split('@')[0];

      // Generate email verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpires = new Date();
      verificationExpires.setHours(verificationExpires.getHours() + 24); // 24 hours

      // Create new user
      const user = new User({
        email,
        username,
        passwordHash: authKeyHash,
        salt,
        masterKeyHash: '', // Not needed with simplified architecture
        protectedSymmetricKey: encryptedDEK,
        dekIV: dekIV,
        publicKey: '', // Not needed with simplified architecture
        privateKeyEncrypted: '', // Not needed with simplified architecture
        isEmailVerified: false,
        emailVerificationToken: verificationToken,
        emailVerificationExpires: verificationExpires,
      });

      await user.save();

      logger.info(`New user registered: ${email}`);

      // Send verification email
      try {
        await EmailService.sendEmailVerification(email, verificationToken);
        logger.info(`✅ Verification email sent to: ${email}`);
      } catch (emailError: any) {
        logger.error(`❌ Failed to send verification email to ${email}:`, emailError.message);
        // Don't fail registration if email fails
      }

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please check your email to verify your account.',
        data: {
          email: user.email,
          username: user.username,
          requiresVerification: true,
        },
      });
    } catch (error) {
      logger.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Registration failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Verify email
   */
  static async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.body;

      if (!token) {
        res.status(400).json({
          success: false,
          message: 'Verification token is required',
        });
        return;
      }

      // Find user with this token
      const user = await User.findOne({
        emailVerificationToken: token,
        emailVerificationExpires: { $gt: new Date() },
      });

      if (!user) {
        res.status(400).json({
          success: false,
          message: 'Invalid or expired verification token',
        });
        return;
      }

      // Verify email
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      logger.info(`Email verified for user: ${user.email}`);

      res.status(200).json({
        success: true,
        message: 'Email verified successfully. You can now login.',
      });
    } catch (error) {
      logger.error('Email verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Email verification failed',
      });
    }
  }

  /**
   * Login user
   */
  static async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, authKeyHash } = req.body as LoginRequest;

      if (!email || !authKeyHash) {
        res.status(400).json({
          success: false,
          message: 'Email and auth key hash are required',
        });
        return;
      }

      // Find user
      const user = await User.findOne({ email });

      if (!user) {
        res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
        return;
      }

      // Check if email is verified
      // TEMPORARY: Disabled for testing
      /* if (!user.isEmailVerified) {
        res.status(403).json({
          success: false,
          message: 'Please verify your email before logging in',
          code: 'EMAIL_NOT_VERIFIED',
        });
        return;
      } */


      // Verify password hash
      if (user.passwordHash !== authKeyHash) {
        // Increment failed login attempts
        user.failedLoginAttempts += 1;
        
        if (user.failedLoginAttempts >= 5) {
          user.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
          logger.warn(`Account locked for user: ${email}`);
        }
        
        await user.save();

        res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
        return;
      }

      // Reset failed login attempts
      user.failedLoginAttempts = 0;
      user.accountLockedUntil = undefined;
      user.lastLoginAt = new Date();
      await user.save();
        // Update last login time
        user.lastLoginAt = new Date();
        await user.save();

      // Check if 2FA is enabled
      if (user.twoFactorEnabled) {
        // Generate OTP and send via email
        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
        const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        
        // Save OTP to user temporarily (you might want a separate OTP table)
        user.emailVerificationToken = otp; // Reuse this field temporarily
        user.emailVerificationExpires = otpExpiry;
        await user.save();

        // Send OTP email
        try {
          await EmailService.sendOTP(user.email, otp);
          logger.info(`2FA OTP sent to: ${email}`);
        } catch (emailError: any) {
          logger.error(`Failed to send 2FA OTP to ${email}:`, emailError.message);
        }

        // Return temp token for OTP verification
        const tempToken = jwt.sign(
          { userId: user._id, email: user.email, purpose: '2fa' },
          JWT_SECRET,
          { expiresIn: '10m' }
        );

        res.status(200).json({
          success: true,
          requires2FA: true,
          tempToken: tempToken,
          message: 'OTP sent to your email'
        });
        return;
      }

      // Generate tokens (no 2FA required)
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      const refreshToken = crypto.randomBytes(64).toString('hex');
      const refreshTokenExpiry = new Date();
      refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

      // Save refresh token
      await RefreshToken.create({
        userId: user._id,
        token: refreshToken,
        expiresAt: refreshTokenExpiry,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      logger.info(`User logged in: ${email}`);

      res.status(200).json({
        success: true,
        token: accessToken,
        refreshToken: refreshToken,
        user: {
          id: user._id,
          email: user.email,
        },
        encryptedDEK: user.protectedSymmetricKey,
        dekIV: user.dekIV,
      });
    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Login failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Verify 2FA OTP after login
   */
  static async verify2FALogin(req: Request, res: Response): Promise<void> {
    try {
      const { tempToken, otp } = req.body;

      if (!tempToken || !otp) {
        res.status(400).json({
          success: false,
          message: 'Temp token and OTP are required',
        });
        return;
      }

      // Verify temp token
      let decoded;
      try {
        decoded = jwt.verify(tempToken, JWT_SECRET) as any;
        if (decoded.purpose !== '2fa') {
          throw new Error('Invalid token purpose');
        }
      } catch (error) {
        res.status(401).json({
          success: false,
          message: 'Invalid or expired token',
        });
        return;
      }

      // Find user and verify OTP
      const user = await User.findById(decoded.userId).select('+emailVerificationToken +emailVerificationExpires');
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
        });
        return;
      }

      // Check OTP
      logger.info(`Verifying OTP for user ${user.email}: received=${otp}, stored=${user.emailVerificationToken}`);
      
      if (user.emailVerificationToken !== otp) {
        logger.warn(`Invalid OTP for user ${user.email}`);
        res.status(401).json({
          success: false,
          message: 'Invalid OTP code',
        });
        return;
      }

      // Check OTP expiry
      if (!user.emailVerificationExpires || user.emailVerificationExpires < new Date()) {
        res.status(401).json({
          success: false,
          message: 'OTP has expired',
        });
        return;
      }

      // Clear OTP
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      // Generate real tokens
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      const refreshToken = crypto.randomBytes(64).toString('hex');
      const refreshTokenExpiry = new Date();
      refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

      // Save refresh token
      await RefreshToken.create({
        userId: user._id,
        token: refreshToken,
        expiresAt: refreshTokenExpiry,
      });

      logger.info(`2FA verified for user: ${user.email}`);

      res.status(200).json({
        success: true,
        token: accessToken,
        refreshToken: refreshToken,
        user: {
          id: user._id,
          email: user.email,
        },
        encryptedDEK: user.protectedSymmetricKey,
        dekIV: user.dekIV,
      });
    } catch (error) {
      logger.error('2FA verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Verification failed',
      });
    }
  }

  /**
   * Resend verification email
   */
  static async resendVerification(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      if (!email) {
        res.status(400).json({
          success: false,
          message: 'Email is required',
        });
        return;
      }

      const user = await User.findOne({ email }).select('+emailVerificationToken +emailVerificationExpires');

      if (!user) {
        // Don't reveal if user exists
        res.status(200).json({
          success: true,
          message: 'If the email exists, a verification link has been sent.',
        });
        return;
      }

      if (user.isEmailVerified) {
        res.status(400).json({
          success: false,
          message: 'Email is already verified',
        });
        return;
      }

      // Generate new verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpires = new Date();
      verificationExpires.setHours(verificationExpires.getHours() + 24);

      user.emailVerificationToken = verificationToken;
      user.emailVerificationExpires = verificationExpires;
      await user.save();

      // Send verification email
      await EmailService.sendEmailVerification(email, verificationToken);

      logger.info(`Verification email resent to: ${email}`);

      res.status(200).json({
        success: true,
        message: 'Verification email sent',
      });
    } catch (error) {
      logger.error('Resend verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to resend verification email',
      });
    }
  }

  /**
   * Logout user
   */
  static async logout(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (refreshToken) {
        await RefreshToken.deleteOne({ token: refreshToken });
      }

      res.status(200).json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed',
      });
    }
  }

  /**
   * Refresh access token
   */
  static async refresh(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          message: 'Refresh token is required',
        });
        return;
      }

      const tokenDoc = await RefreshToken.findOne({ token: refreshToken });

      if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
        res.status(401).json({
          success: false,
          message: 'Invalid or expired refresh token',
        });
        return;
      }

      const user = await User.findById(tokenDoc.userId);

      if (!user) {
        res.status(401).json({
          success: false,
          message: 'User not found',
        });
        return;
      }

      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      res.status(200).json({
        success: true,
        message: 'Token refreshed',
        data: {
          accessToken,
        },
      });
    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        message: 'Token refresh failed',
      });
    }
  }

  /**
   * Get salt for user
   */
  static async getSalt(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      if (!email) {
        res.status(400).json({
          success: false,
          message: 'Email is required',
        });
        return;
      }

      const user = await User.findOne({ email }).select('salt');

      if (!user) {
        const fakeSalt = crypto.randomBytes(32).toString('hex');
        res.status(200).json({
          success: true,
          data: {
            salt: fakeSalt,
          },
        });
        return;
      }

      res.status(200).json({
        success: true,
        data: {
          salt: user.salt,
        },
      });
    } catch (error) {
      logger.error('Get salt error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve salt',
      });
    }
  }

  /**
   * Toggle 2FA for user
   */
  static async toggle2FA(req: Request, res: Response): Promise<void> {
    try {
      const { email, enabled } = req.body;

      if (!email || typeof enabled !== 'boolean') {
        res.status(400).json({
          success: false,
          message: 'Email and enabled status are required',
        });
        return;
      }

      const user = await User.findOne({ email });
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
        });
        return;
      }

      user.twoFactorEnabled = enabled;
      await user.save();

      logger.info(`2FA ${enabled ? 'enabled' : 'disabled'} for user: ${email}`);

      res.status(200).json({
        success: true,
        message: `2FA ${enabled ? 'enabled' : 'disabled'} successfully`,
        data: {
          twoFactorEnabled: user.twoFactorEnabled
        }
      });
    } catch (error) {
      logger.error('Toggle 2FA error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to toggle 2FA',
      });
    }
  }
}
