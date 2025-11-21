import nodemailer from 'nodemailer';
import { logger } from '../config/logger';

export class EmailService {
  private static transporter: nodemailer.Transporter | null = null;

  /**
   * Initialize email transporter
   */
  private static async getTransporter() {
    if (this.transporter) {
      return this.transporter;
    }

    try {
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
      });

      // Verify connection
      await this.transporter.verify();
      logger.info('✅ Email service connected successfully');
      
      return this.transporter;
    } catch (error: any) {
      this.transporter = null;
      
      // Detailed error logging
      if (error.code === 'EAUTH') {
        logger.error('❌ SMTP Authentication Failed:', {
          error: 'Invalid email credentials',
          code: error.code,
          response: error.response,
          suggestion: 'Check EMAIL_USER and EMAIL_PASSWORD in .env file. Make sure to use App Password for Gmail.'
        });
      } else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNECTION') {
        logger.error('❌ SMTP Connection Failed:', {
          error: 'Cannot connect to SMTP server',
          code: error.code,
          suggestion: 'Check your internet connection or firewall settings.'
        });
      } else if (error.response?.includes('454')) {
        logger.error('❌ Google Security Block:', {
          error: 'Gmail blocked the connection',
          code: error.code,
          response: error.response,
          suggestion: 'Enable "Less secure app access" or use App Password. Visit: https://myaccount.google.com/apppasswords'
        });
      } else {
        logger.error('❌ Email Service Error:', {
          error: error.message,
          code: error.code,
          response: error.response,
          stack: error.stack
        });
      }
      
      throw error;
    }
  }

  /**
   * Send email verification
   */
  static async sendEmailVerification(email: string, verificationToken: string): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

      const mailOptions = {
        from: `"Password Manager" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Xác Thực Email - Password Manager',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
              <tr>
                <td align="center">
                  <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                      <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">
                          🔐 Password Manager
                        </h1>
                        <p style="color: #ffffff; margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">
                          Xác Thực Tài Khoản
                        </p>
                      </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                      <td style="padding: 40px 30px;">
                        <h2 style="color: #333333; margin: 0 0 20px 0; font-size: 24px;">
                          Chào mừng bạn! 👋
                        </h2>
                        
                        <p style="color: #666666; font-size: 16px; line-height: 1.6; margin: 0 0 20px 0;">
                          Cảm ơn bạn đã đăng ký tài khoản <strong>Password Manager</strong>. Để bắt đầu sử dụng dịch vụ, vui lòng xác thực địa chỉ email của bạn.
                        </p>
                        
                        <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px;">
                          <p style="color: #856404; margin: 0; font-size: 14px;">
                            ⚠️ <strong>Quan trọng:</strong> Bạn cần xác thực email để có thể đăng nhập vào tài khoản.
                          </p>
                        </div>
                        
                        <!-- Verification Button -->
                        <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                          <tr>
                            <td align="center">
                              <a href="${verificationUrl}" 
                                 style="display: inline-block; 
                                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                        color: #ffffff; 
                                        text-decoration: none; 
                                        padding: 16px 40px; 
                                        border-radius: 6px; 
                                        font-size: 18px; 
                                        font-weight: bold;
                                        box-shadow: 0 4px 6px rgba(102, 126, 234, 0.3);">
                                ✓ Xác Thực Email
                              </a>
                            </td>
                          </tr>
                        </table>
                        
                        <p style="color: #666666; font-size: 14px; line-height: 1.6; margin: 20px 0;">
                          Hoặc copy link sau vào trình duyệt:
                        </p>
                        
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; word-break: break-all;">
                          <code style="color: #667eea; font-size: 12px;">${verificationUrl}</code>
                        </div>
                        
                        <div style="margin: 30px 0; padding: 20px; background-color: #e8f5e9; border-radius: 6px;">
                          <h3 style="color: #2e7d32; margin: 0 0 10px 0; font-size: 16px;">
                            🔒 Bảo Mật & An Toàn
                          </h3>
                          <ul style="color: #4caf50; margin: 0; padding-left: 20px; font-size: 14px; line-height: 1.8;">
                            <li>Mật khẩu của bạn được mã hóa hoàn toàn</li>
                            <li>Chúng tôi không thể truy cập dữ liệu của bạn</li>
                            <li>Zero-Knowledge Architecture</li>
                          </ul>
                        </div>
                        
                        <p style="color: #999999; font-size: 13px; line-height: 1.6; margin: 20px 0 0 0;">
                          Link xác thực sẽ hết hạn sau <strong>24 giờ</strong>.
                        </p>
                        
                        <p style="color: #999999; font-size: 13px; line-height: 1.6; margin: 10px 0 0 0;">
                          Nếu bạn không đăng ký tài khoản này, vui lòng bỏ qua email này.
                        </p>
                      </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                      <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e0e0e0;">
                        <p style="color: #999999; font-size: 12px; margin: 0 0 10px 0;">
                          © 2025 Password Manager. All rights reserved.
                        </p>
                        <p style="color: #999999; font-size: 12px; margin: 0;">
                          Secure Your Digital Life 🔐
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `,
      };

      const info = await transporter.sendMail(mailOptions);
      
      logger.info('✅ Verification email sent successfully:', {
        to: email,
        messageId: info.messageId,
        response: info.response
      });
      
    } catch (error: any) {
      // Detailed error logging for send failures
      if (error.code === 'EAUTH') {
        logger.error('❌ Email Send Failed - Authentication Error:', {
          type: 'SMTP_AUTH_ERROR',
          email: email,
          error: error.message,
          code: error.code,
          response: error.response,
          suggestion: 'SMTP credentials are invalid. Update EMAIL_USER and EMAIL_PASSWORD.'
        });
        throw new Error('Email authentication failed. Please contact administrator.');
      } else if (error.responseCode === 454 || error.response?.includes('454')) {
        logger.error('❌ Email Send Failed - Google Security Block:', {
          type: 'GOOGLE_SECURITY_BLOCK',
          email: email,
          error: error.message,
          code: error.responseCode,
          response: error.response,
          suggestion: 'Google blocked the email. Enable 2FA and use App Password.'
        });
        throw new Error('Email service temporarily unavailable. Please try again later.');
      } else if (error.responseCode === 550) {
        logger.error('❌ Email Send Failed - Invalid Recipient:', {
          type: 'INVALID_RECIPIENT',
          email: email,
          error: error.message,
          code: error.responseCode,
          response: error.response
        });
        throw new Error('Invalid email address.');
      } else {
        logger.error('❌ Email Send Failed - Unknown Error:', {
          type: 'UNKNOWN_ERROR',
          email: email,
          error: error.message,
          code: error.code,
          response: error.response,
          stack: error.stack
        });
        throw new Error('Failed to send verification email. Please try again later.');
      }
    }
  }

  /**
   * Send OTP via email
   */
  static async sendOTP(email: string, otp: string): Promise<void> {
    try {
      const transporter = await this.getTransporter();

      const mailOptions = {
        from: `"Password Manager" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Your OTP Code - Password Manager',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">OTP Verification Code</h2>
            <p>Your OTP code is:</p>
            <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
              ${otp}
            </div>
            <p style="color: #666;">This code will expire in 5 minutes.</p>
            <p style="color: #666;">If you didn't request this code, please ignore this email.</p>
          </div>
        `,
      };

      const info = await transporter.sendMail(mailOptions);
      logger.info('✅ OTP Email sent successfully:', { to: email, messageId: info.messageId });
      
    } catch (error: any) {
      logger.error('❌ OTP Send Failed:', { email, error: error.message });
      throw error;
    }
  }
}
