// Minimal test server for vault testing
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// MongoDB connection
mongoose.connect('mongodb+srv://khoilam3789_db_user:d6jBtNrJUb4IHcMs@data.jqzpt6k.mongodb.net/password_manager?retryWrites=true&w=majority&appName=data')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// Email transporter configuration
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: 'khoilam3789@gmail.com',
    pass: 'gzocqwkugsvnlbuy'
  }
});

// Verify email configuration
emailTransporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email configuration error:', error);
  } else {
    console.log('✅ Email server ready to send messages');
  }
});

// Vault Item Schema
const vaultItemSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  type: { type: String, enum: ['password', 'note', 'card', 'identity'], default: 'password' },
  name: { type: String, required: true },
  encryptedData: { type: String, required: true },
  iv: { type: String, required: true },
  category: String,
  favorite: { type: Boolean, default: false },
  tags: [String],
  notes: { type: String, maxlength: 1000 },
  lastAccessed: Date
}, { timestamps: true });

const VaultItem = mongoose.model('VaultItem', vaultItemSchema);

// User Schema (for 2FA)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  is2FAEnabled: { type: Boolean, default: false },
  authKeyHash: String,
  encryptedDEK: String,
  dekIV: String,
  salt: String
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// OTP Schema
const otpSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  email: { type: String, required: true },
  otp: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  verified: { type: Boolean, default: false }
}, { timestamps: true });

const OTP = mongoose.model('OTP', otpSchema);

// External OTP Secret Schema (for Google Authenticator, etc.)
const externalSecretSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  issuer: { type: String, required: true },
  encryptedSecret: { type: String, required: true }, // TOTP secret encrypted
  iv: { type: String, required: true },
  algorithm: { type: String, default: 'SHA1' },
  digits: { type: Number, default: 6 },
  period: { type: Number, default: 30 }
}, { timestamps: true });

const ExternalSecret = mongoose.model('ExternalSecret', externalSecretSchema);

// Session Schema
const sessionSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  sessionToken: { type: String, required: true, unique: true },
  deviceInfo: {
    deviceType: String, // 'Windows', 'iPhone', 'Android', 'Mac', 'Linux'
    browser: String,    // 'Chrome', 'Safari', 'Firefox', 'Edge'
    os: String
  },
  ipAddress: String,
  userAgent: String,
  lastActivity: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

const Session = mongoose.model('Session', sessionSchema);

// Helper: Parse user agent to get device info
function parseUserAgent(userAgent) {
  const ua = userAgent || '';
  
  // Detect OS/Device
  let deviceType = 'Desktop';
  let os = 'Unknown';
  
  if (/iPhone/.test(ua)) {
    deviceType = 'iPhone';
    os = 'iOS';
  } else if (/iPad/.test(ua)) {
    deviceType = 'iPad';
    os = 'iOS';
  } else if (/Android/.test(ua)) {
    deviceType = 'Android';
    os = 'Android';
  } else if (/Windows/.test(ua)) {
    deviceType = 'Windows';
    os = 'Windows';
  } else if (/Macintosh/.test(ua)) {
    deviceType = 'Mac';
    os = 'macOS';
  } else if (/Linux/.test(ua)) {
    deviceType = 'Linux';
    os = 'Linux';
  }
  
  // Detect Browser
  let browser = 'Unknown';
  if (/Edg/.test(ua)) {
    browser = 'Edge';
  } else if (/Chrome/.test(ua) && !/Edg/.test(ua)) {
    browser = 'Chrome';
  } else if (/Safari/.test(ua) && !/Chrome/.test(ua)) {
    browser = 'Safari';
  } else if (/Firefox/.test(ua)) {
    browser = 'Firefox';
  }
  
  return { deviceType, browser, os };
}

// Routes
app.post('/api/v1/vault', async (req, res) => {
  try {
    console.log('Received vault creation request:', req.body);
    
    const { type, name, encryptedData, iv, category, favorite, tags, notes } = req.body;
    
    if (!name || !encryptedData || !iv) {
      return res.status(400).json({
        success: false,
        message: 'Name, encrypted data, and IV are required',
      });
    }

    const userId = await getUserIdFromRequest(req);
    console.log('Creating vault item for userId:', userId);

    const item = await VaultItem.create({
      userId: userId,
      type: type || 'password',
      name,
      encryptedData,
      iv,
      category,
      favorite: favorite || false,
      tags: tags || [],
      notes,
    });

    console.log('Vault item created:', item._id);

    res.status(201).json({
      success: true,
      data: item,
    });
  } catch (error) {
    console.error('Create vault item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create vault item',
      error: error.message
    });
  }
});

app.get('/api/v1/vault', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    console.log('Fetching vault items for userId:', userId);
    const items = await VaultItem.find({ userId: userId })
      .sort({ favorite: -1, updatedAt: -1 });

    res.status(200).json({
      success: true,
      data: items,
    });
  } catch (error) {
    console.error('Get vault items error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve vault items',
    });
  }
});

// Clear all vault items (for testing)
app.delete('/api/v1/vault/clear-all', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    console.log('Clearing all vault items for userId:', userId);
    const result = await VaultItem.deleteMany({ userId: userId });
    console.log('Cleared all vault items:', result.deletedCount);
    res.status(200).json({
      success: true,
      message: `Deleted ${result.deletedCount} items`
    });
  } catch (error) {
    console.error('Clear vault error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to clear vault'
    });
  }
});

app.get('/api/v1/vault/:id', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const item = await VaultItem.findOne({ 
      _id: req.params.id, 
      userId: userId 
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Vault item not found',
      });
    }

    // Update last accessed
    item.lastAccessed = new Date();
    await item.save();

    res.status(200).json({
      success: true,
      data: item,
    });
  } catch (error) {
    console.error('Get vault item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve vault item',
    });
  }
});

app.put('/api/v1/vault/:id', async (req, res) => {
  try {
    const { name, encryptedData, iv, category, favorite, tags } = req.body;
    const userId = await getUserIdFromRequest(req);

    const item = await VaultItem.findOne({ 
      _id: req.params.id, 
      userId: userId 
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Vault item not found',
      });
    }

    // Update fields
    if (name !== undefined) item.name = name;
    if (encryptedData !== undefined) item.encryptedData = encryptedData;
    if (iv !== undefined) item.iv = iv;
    if (category !== undefined) item.category = category;
    if (favorite !== undefined) item.favorite = favorite;
    if (tags !== undefined) item.tags = tags;

    await item.save();

    res.status(200).json({
      success: true,
      data: item,
    });
  } catch (error) {
    console.error('Update vault item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update vault item',
    });
  }
});

app.delete('/api/v1/vault/:id', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const item = await VaultItem.findOneAndDelete({
      _id: req.params.id,
      userId: userId
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Vault item not found',
      });
    }

    res.status(200).json({
      success: true,
      message: 'Vault item deleted successfully',
    });
  } catch (error) {
    console.error('Delete vault item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete vault item',
    });
  }
});

// Also add auth routes that frontend needs
// For testing: Use a fixed salt and pre-encrypted DEK that matches test credentials
// Test credentials: email='test@test.com', password='Test123!'
const FIXED_SALT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; // Base64 of 32 zero bytes
const FIXED_DEK = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB8='; // Pre-generated encrypted DEK
const FIXED_IV = 'CCCCCCCCCCCCCCCCCCCCCA=='; // Pre-generated IV

// Helper: Get userId from request (email or Authorization header)
async function getUserIdFromRequest(req) {
  // Try to get from Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    // In test mode, token format is: userId or email
    // Try to find user by ID first
    let user = await User.findById(token).catch(() => null);
    if (user) return user._id.toString();
  }
  
  // Try to get from x-user-email header
  const userEmail = req.headers['x-user-email'];
  if (userEmail) {
    const user = await User.findOne({ email: userEmail });
    if (user) return user._id.toString();
  }
  
  // Fallback: use test user
  return 'test-user-123';
}

// Helper: Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: Send OTP email (real email)
async function sendOTPEmail(email, otp) {
  console.log('\n=================================================');
  console.log('📧 ĐANG GỬI EMAIL OTP');
  console.log('=================================================');
  console.log(`Gửi đến: ${email}`);
  console.log(`Mã OTP: ${otp}`);
  console.log(`Thời gian hết hạn: 10 phút`);
  console.log('=================================================\n');
  
  try {
    const mailOptions = {
      from: 'Password Manager <khoilam3789@gmail.com>',
      to: email,
      subject: 'Mã xác thực OTP - Password Manager',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .otp-code { font-size: 32px; font-weight: bold; color: #667eea; text-align: center; letter-spacing: 8px; margin: 20px 0; padding: 15px; background: white; border-radius: 8px; border: 2px dashed #667eea; }
            .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔐 Xác thực đăng nhập</h1>
            </div>
            <div class="content">
              <p>Xin chào,</p>
              <p>Bạn đã yêu cầu mã OTP để đăng nhập vào Password Manager. Mã xác thực của bạn là:</p>
              <div class="otp-code">${otp}</div>
              <div class="warning">
                <strong>⚠️ Lưu ý quan trọng:</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">
                  <li>Mã OTP này chỉ có hiệu lực trong <strong>10 phút</strong></li>
                  <li>Không chia sẻ mã này với bất kỳ ai</li>
                  <li>Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email</li>
                </ul>
              </div>
              <p>Trân trọng,<br><strong>Password Manager Team</strong></p>
            </div>
            <div class="footer">
              <p>Email này được gửi tự động, vui lòng không trả lời.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };
    
    const info = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Email sent successfully! Message ID:', info.messageId);
    return true;
  } catch (error) {
    console.error('❌ Error sending email:', error);
    console.log('⚠️  Fallback: OTP code is:', otp);
    return false;
  }
}

// Helper: Send welcome email
async function sendWelcomeEmail(email) {
  console.log('📧 Sending welcome email to:', email);
  
  try {
    const mailOptions = {
      from: 'Password Manager <khoilam3789@gmail.com>',
      to: email,
      subject: 'Chào mừng đến với Password Manager! 🎉',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .feature { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #667eea; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🎉 Chào mừng bạn!</h1>
            </div>
            <div class="content">
              <p>Xin chào,</p>
              <p>Cảm ơn bạn đã đăng ký Password Manager! Tài khoản của bạn đã được tạo thành công.</p>
              
              <h3>🔐 Tính năng chính:</h3>
              <div class="feature">
                <strong>✓ Mã hóa Zero-Knowledge</strong><br>
                Mật khẩu của bạn được mã hóa end-to-end, chúng tôi không thể truy cập.
              </div>
              <div class="feature">
                <strong>✓ Xác thực 2 yếu tố (2FA)</strong><br>
                Bảo vệ tài khoản với lớp bảo mật bổ sung qua OTP email.
              </div>
              <div class="feature">
                <strong>✓ Quản lý Vault</strong><br>
                Lưu trữ mật khẩu, thẻ, ghi chú một cách an toàn.
              </div>
              
              <p style="text-align: center;">
                <a href="http://localhost:3000/login" class="button">Đăng nhập ngay</a>
              </p>
              
              <p>Nếu bạn có bất kỳ câu hỏi nào, đừng ngần ngại liên hệ với chúng tôi.</p>
              <p>Trân trọng,<br><strong>Password Manager Team</strong></p>
            </div>
            <div class="footer">
              <p>Email này được gửi tự động, vui lòng không trả lời.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };
    
    const info = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Welcome email sent! Message ID:', info.messageId);
    return true;
  } catch (error) {
    console.error('❌ Error sending welcome email:', error);
    return false;
  }
}

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    console.log('Login attempt for:', req.body.email);
    
    const email = req.body.email || 'test@test.com';
    
    // Find or create user
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        email,
        is2FAEnabled: false,
        salt: FIXED_SALT,
        encryptedDEK: FIXED_DEK,
        dekIV: FIXED_IV
      });
    }

    // Check if 2FA is enabled
    if (user.is2FAEnabled) {
      // Generate OTP
      const otp = generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      // Save OTP to database
      await OTP.create({
        userId: user._id.toString(),
        email: user.email,
        otp,
        expiresAt,
        verified: false
      });

      // Send OTP email
      await sendOTPEmail(email, otp);

      // Return response indicating 2FA required
      return res.json({
        success: true,
        requires2FA: true,
        tempToken: 'temp-token-' + user._id,
        message: 'OTP đã được gửi đến email của bạn'
      });
    }

    // No 2FA - return full auth response
    const sessionToken = 'session-' + user._id + '-' + Date.now();
    const deviceInfo = parseUserAgent(req.headers['user-agent']);
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown';
    
    // Create session
    await Session.create({
      userId: user._id.toString(),
      sessionToken,
      deviceInfo,
      ipAddress,
      userAgent: req.headers['user-agent'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      isActive: true
    });
    
    res.json({
      success: true,
      requires2FA: false,
      token: sessionToken,
      refreshToken: 'test-refresh-token',
      user: { 
        _id: user._id.toString(),
        email: user.email,
        isEmailVerified: true,
        is2FAEnabled: user.is2FAEnabled
      },
      encryptedDEK: FIXED_DEK,
      dekIV: FIXED_IV
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

// Verify OTP
app.post('/api/v1/auth/verify-otp', async (req, res) => {
  try {
    const { tempToken, otp } = req.body;
    
    if (!tempToken || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Temp token and OTP are required'
      });
    }

    // Extract userId from tempToken
    const userId = tempToken.replace('temp-token-', '');

    // Find OTP record
    const otpRecord = await OTP.findOne({
      userId,
      otp,
      verified: false,
      expiresAt: { $gt: new Date() }
    }).sort({ createdAt: -1 });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: 'OTP không hợp lệ hoặc đã hết hạn'
      });
    }

    // Mark OTP as verified
    otpRecord.verified = true;
    await otpRecord.save();

    // Get user
    const user = await User.findById(userId);

    // Create session
    const sessionToken = 'session-' + user._id + '-' + Date.now();
    const deviceInfo = parseUserAgent(req.headers['user-agent']);
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown';
    
    await Session.create({
      userId: user._id.toString(),
      sessionToken,
      deviceInfo,
      ipAddress,
      userAgent: req.headers['user-agent'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      isActive: true
    });

    // Return full auth response
    res.json({
      success: true,
      token: sessionToken,
      refreshToken: 'test-refresh-token',
      user: { 
        _id: user._id.toString(),
        email: user.email,
        isEmailVerified: true,
        is2FAEnabled: user.is2FAEnabled
      },
      encryptedDEK: FIXED_DEK,
      dekIV: FIXED_IV
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'OTP verification failed'
    });
  }
});

// Resend OTP
app.post('/api/v1/auth/resend-otp', async (req, res) => {
  try {
    const { tempToken } = req.body;
    
    if (!tempToken) {
      return res.status(400).json({
        success: false,
        message: 'Temp token is required'
      });
    }

    const userId = tempToken.replace('temp-token-', '');
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Generate new OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await OTP.create({
      userId: user._id.toString(),
      email: user.email,
      otp,
      expiresAt,
      verified: false
    });

    await sendOTPEmail(user.email, otp);

    res.json({
      success: true,
      message: 'OTP mới đã được gửi'
    });
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to resend OTP'
    });
  }
});

// Toggle 2FA
app.post('/api/v1/auth/toggle-2fa', async (req, res) => {
  try {
    const { email, enabled } = req.body;
    
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        email,
        is2FAEnabled: enabled,
        salt: FIXED_SALT,
        encryptedDEK: FIXED_DEK,
        dekIV: FIXED_IV
      });
    } else {
      user.is2FAEnabled = enabled;
      await user.save();
    }

    res.json({
      success: true,
      is2FAEnabled: user.is2FAEnabled,
      message: enabled ? '2FA đã được bật' : '2FA đã được tắt'
    });
  } catch (error) {
    console.error('Toggle 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to toggle 2FA'
    });
  }
});

// Get user keys (for key rotation)
app.get('/api/v1/auth/user-keys', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User không tồn tại'
      });
    }
    
    res.json({
      success: true,
      data: {
        encryptedDEK: user.encryptedDEK,
        dekIV: user.dekIV,
        salt: user.salt
      }
    });
  } catch (error) {
    console.error('Get user keys error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể lấy keys'
    });
  }
});

// Rotate keys (change master password)
app.post('/api/v1/auth/rotate-keys', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const {
      currentAuthKeyHash,
      newAuthKeyHash,
      newSalt,
      newEncryptedDEK,
      newDekIV,
      reEncryptedItems
    } = req.body;
    
    console.log('🔄 [KeyRotation] Starting key rotation for user:', userId);
    
    // Step 1: Verify current password
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User không tồn tại'
      });
    }
    
    if (user.authKeyHash !== currentAuthKeyHash) {
      return res.status(401).json({
        success: false,
        message: 'Mật khẩu hiện tại không đúng'
      });
    }
    
    console.log('✅ [KeyRotation] Current password verified');
    
    // Step 2: Update user keys in transaction
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update user
      user.authKeyHash = newAuthKeyHash;
      user.salt = newSalt;
      user.encryptedDEK = newEncryptedDEK;
      user.dekIV = newDekIV;
      await user.save({ session });
      
      console.log(`✅ [KeyRotation] User keys updated`);
      
      // Update all vault items
      for (const item of reEncryptedItems) {
        await VaultItem.updateOne(
          { _id: item.id, userId },
          {
            name: item.name,
            encryptedData: item.encryptedData,
            iv: item.iv,
            category: item.category,
            favorite: item.favorite,
            tags: item.tags
          },
          { session }
        );
      }
      
      console.log(`✅ [KeyRotation] ${reEncryptedItems.length} vault items re-encrypted`);
      
      // Commit transaction
      await session.commitTransaction();
      console.log('✅ [KeyRotation] Key rotation completed successfully');
      
      res.json({
        success: true,
        message: 'Master password đã được thay đổi thành công'
      });
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } catch (error) {
    console.error('❌ [KeyRotation] Error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể thay đổi master password'
    });
  }
});

app.post('/api/v1/auth/get-salt', (req, res) => {
  // Return fixed salt for testing so encryption keys are consistent
  console.log('Salt request for:', req.body.email);
  
  res.json({
    success: true,
    data: {
      salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' // Fixed salt for testing
    }
  });
});

// Register endpoint
app.post('/api/v1/auth/register', async (req, res) => {
  try {
    console.log('📝 Register attempt for:', req.body.email);
    const { email, authKeyHash, salt, encryptedDEK, dekIV } = req.body;
    
    // Validate input
    if (!email || !email.includes('@')) {
      return res.status(400).json({
        success: false,
        message: 'Email không hợp lệ'
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('⚠️  User already exists:', email);
      return res.status(400).json({
        success: false,
        message: 'Email đã được đăng ký. Vui lòng sử dụng email khác hoặc đăng nhập.',
        exists: true
      });
    }

    // Create new user (use provided values or test values)
    const user = await User.create({
      email,
      is2FAEnabled: false,
      authKeyHash: authKeyHash || 'test-hash',
      salt: salt || FIXED_SALT,
      encryptedDEK: encryptedDEK || FIXED_DEK,
      dekIV: dekIV || FIXED_IV
    });

    console.log('✅ User registered successfully:', email);
    
    // Send welcome email
    try {
      await sendWelcomeEmail(email);
    } catch (emailError) {
      console.log('⚠️  Welcome email failed, but registration succeeded');
    }
    
    res.json({
      success: true,
      message: 'Đăng ký thành công! Vui lòng đăng nhập.',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
      refreshToken: 'test-refresh-token',
      user: {
        _id: user._id.toString(),
        email: user.email,
        isEmailVerified: true,
        is2FAEnabled: false
      }
    });
  } catch (error) {
    console.error('❌ Register error:', error);
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Email đã tồn tại trong hệ thống'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Đăng ký thất bại. Vui lòng thử lại.'
    });
  }
});

// Resend verification email endpoint
app.post('/api/v1/auth/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email là bắt buộc'
      });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy tài khoản với email này'
      });
    }

    console.log('📧 Resending verification email to:', email);
    await sendWelcomeEmail(email);

    res.json({
      success: true,
      message: 'Email xác thực đã được gửi lại'
    });
  } catch (error) {
    console.error('❌ Resend verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể gửi email. Vui lòng thử lại sau.'
    });
  }
});

// ===== EXTERNAL OTP SECRET ENDPOINTS =====

// Get all external OTP secrets for current user
app.get('/api/v1/otp/external-secrets', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    
    const secrets = await ExternalSecret.find({ userId })
      .sort({ createdAt: -1 })
      .select('-__v');
    
    // Decrypt secrets before sending to client
    const serverKey = Buffer.from(process.env.SERVER_ENCRYPTION_KEY || '3zZ3T3rQCYdTIR5HhOaGkUpvSViC8Zx6rW7mU9k2p2E=', 'base64');
    const decryptedSecrets = secrets.map(s => {
      try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', serverKey, Buffer.from(s.iv, 'hex'));
        let decrypted = decipher.update(s.encryptedSecret, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return {
          id: s._id,
          label: s.name,
          secret: decrypted,
          issuer: s.issuer,
          algorithm: s.algorithm,
          digits: s.digits,
          period: s.period,
          createdAt: s.createdAt
        };
      } catch (err) {
        console.error('Decrypt error for secret:', s._id, err);
        return null;
      }
    }).filter(s => s !== null);
    
    res.json({
      success: true,
      secrets: decryptedSecrets
    });
  } catch (error) {
    console.error('Get external secrets error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể tải danh sách OTP bên ngoài'
    });
  }
});

// Add new external OTP secret
app.post('/api/v1/otp/external-secrets', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const { label, secret, issuer, algorithm, digits, period } = req.body;
    
    if (!label || !secret) {
      return res.status(400).json({
        success: false,
        message: 'Thiếu thông tin bắt buộc (label và secret)'
      });
    }
    
    // Generate IV for encryption
    const iv = crypto.randomBytes(16).toString('hex');
    
    // Encrypt the secret using AES-256-CBC
    const serverKey = Buffer.from(process.env.SERVER_ENCRYPTION_KEY || '3zZ3T3rQCYdTIR5HhOaGkUpvSViC8Zx6rW7mU9k2p2E=', 'base64');
    const cipher = crypto.createCipheriv('aes-256-cbc', serverKey, Buffer.from(iv, 'hex'));
    let encryptedSecret = cipher.update(secret, 'utf8', 'hex');
    encryptedSecret += cipher.final('hex');
    
    const newSecret = new ExternalSecret({
      userId,
      name: label,
      issuer: issuer || label,
      encryptedSecret,
      iv,
      algorithm: algorithm || 'SHA1',
      digits: digits || 6,
      period: period || 30
    });
    
    await newSecret.save();
    console.log('External OTP secret added for user:', userId);
    
    res.json({
      success: true,
      secret: {
        id: newSecret._id,
        label: newSecret.name,
        secret: secret, // Return plain secret for client to use
        issuer: newSecret.issuer,
        algorithm: newSecret.algorithm,
        digits: newSecret.digits,
        period: newSecret.period,
        createdAt: newSecret.createdAt
      }
    });
  } catch (error) {
    console.error('Add external secret error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể thêm OTP bên ngoài'
    });
  }
});

// Update external OTP secret
app.put('/api/v1/otp/external-secrets/:id', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const { id } = req.params;
    const { label, secret, issuer, algorithm, digits, period } = req.body;
    
    const existingSecret = await ExternalSecret.findOne({ _id: id, userId });
    
    if (!existingSecret) {
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy OTP này'
      });
    }
    
    // Update fields if provided
    if (label !== undefined) existingSecret.name = label;
    if (issuer !== undefined) existingSecret.issuer = issuer;
    if (algorithm !== undefined) existingSecret.algorithm = algorithm;
    if (digits !== undefined) existingSecret.digits = digits;
    if (period !== undefined) existingSecret.period = period;
    
    // Re-encrypt secret if provided
    if (secret !== undefined) {
      const iv = crypto.randomBytes(16).toString('hex');
      const serverKey = Buffer.from(process.env.SERVER_ENCRYPTION_KEY || '3zZ3T3rQCYdTIR5HhOaGkUpvSViC8Zx6rW7mU9k2p2E=', 'base64');
      const cipher = crypto.createCipheriv('aes-256-cbc', serverKey, Buffer.from(iv, 'hex'));
      let encryptedSecret = cipher.update(secret, 'utf8', 'hex');
      encryptedSecret += cipher.final('hex');
      
      existingSecret.encryptedSecret = encryptedSecret;
      existingSecret.iv = iv;
    }
    
    await existingSecret.save();
    console.log('External OTP secret updated:', id);
    
    // Decrypt for response
    const serverKey = Buffer.from(process.env.SERVER_ENCRYPTION_KEY || '3zZ3T3rQCYdTIR5HhOaGkUpvSViC8Zx6rW7mU9k2p2E=', 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', serverKey, Buffer.from(existingSecret.iv, 'hex'));
    let decrypted = decipher.update(existingSecret.encryptedSecret, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    res.json({
      success: true,
      secret: {
        id: existingSecret._id,
        label: existingSecret.name,
        secret: decrypted,
        issuer: existingSecret.issuer,
        algorithm: existingSecret.algorithm,
        digits: existingSecret.digits,
        period: existingSecret.period,
        createdAt: existingSecret.createdAt
      }
    });
  } catch (error) {
    console.error('Update external secret error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể cập nhật OTP bên ngoài'
    });
  }
});

// Delete external OTP secret
app.delete('/api/v1/otp/external-secrets/:id', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const { id } = req.params;
    
    const result = await ExternalSecret.deleteOne({ _id: id, userId });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy OTP này'
      });
    }
    
    console.log('External OTP secret deleted:', id);
    
    res.json({
      success: true,
      message: 'Đã xóa OTP bên ngoài'
    });
  } catch (error) {
    console.error('Delete external secret error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể xóa OTP bên ngoài'
    });
  }
});

// ===== END EXTERNAL OTP SECRET ENDPOINTS =====

app.post('/api/v1/auth/logout', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const sessionToken = req.headers.authorization?.replace('Bearer ', '');
    
    if (sessionToken) {
      // Deactivate the current session
      await Session.updateOne(
        { sessionToken, userId },
        { isActive: false }
      );
      console.log('Session deactivated for user:', userId);
    }
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  }
});

// Get all active sessions for current user
app.get('/api/v1/auth/sessions', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const currentToken = req.headers.authorization?.replace('Bearer ', '');
    
    // Get all active sessions
    const sessions = await Session.find({
      userId,
      isActive: true,
      expiresAt: { $gt: new Date() }
    }).sort({ lastActivity: -1 });
    
    const formattedSessions = sessions.map(session => ({
      id: session._id.toString(),
      sessionToken: session.sessionToken,
      deviceType: session.deviceInfo.deviceType,
      browser: session.deviceInfo.browser,
      os: session.deviceInfo.os,
      ipAddress: session.ipAddress,
      lastActivity: session.lastActivity,
      createdAt: session.createdAt,
      isCurrent: session.sessionToken === currentToken
    }));
    
    res.json({
      success: true,
      sessions: formattedSessions
    });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get sessions'
    });
  }
});

// Logout specific session
app.delete('/api/v1/auth/sessions/:sessionId', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const { sessionId } = req.params;
    
    // Deactivate the session
    const result = await Session.updateOne(
      { _id: sessionId, userId },
      { isActive: false }
    );
    
    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Session logged out successfully'
    });
  } catch (error) {
    console.error('Logout session error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to logout session'
    });
  }
});

// Logout all other sessions (keep current)
app.post('/api/v1/auth/sessions/logout-all', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const currentToken = req.headers.authorization?.replace('Bearer ', '');
    
    // Deactivate all sessions except current
    const result = await Session.updateMany(
      { 
        userId, 
        sessionToken: { $ne: currentToken },
        isActive: true 
      },
      { isActive: false }
    );
    
    res.json({
      success: true,
      message: `Đã đăng xuất ${result.modifiedCount} phiên khác`,
      loggedOutCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Logout all sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to logout all sessions'
    });
  }
});

// Delete account - remove all user data
app.delete('/api/v1/auth/delete-account', async (req, res) => {
  try {
    const userId = await getUserIdFromRequest(req);
    const userEmail = req.headers['x-user-email'];
    
    if (!userId || userId === 'test-user-123') {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID'
      });
    }
    
    console.log('🗑️  Deleting account for userId:', userId, 'email:', userEmail);
    
    // Delete all vault items
    const vaultResult = await VaultItem.deleteMany({ userId });
    console.log(`  - Deleted ${vaultResult.deletedCount} vault items`);
    
    // Delete all sessions
    const sessionResult = await Session.deleteMany({ userId });
    console.log(`  - Deleted ${sessionResult.deletedCount} sessions`);
    
    // Delete all OTPs
    const otpResult = await OTP.deleteMany({ userId });
    console.log(`  - Deleted ${otpResult.deletedCount} OTPs`);
    
    // Delete user account
    const user = await User.findByIdAndDelete(userId);
    if (user) {
      console.log(`  - Deleted user account: ${user.email}`);
    }
    
    console.log('✅ Account deletion completed successfully');
    
    res.json({
      success: true,
      message: 'Tài khoản đã được xóa thành công',
      deletedData: {
        vaultItems: vaultResult.deletedCount,
        sessions: sessionResult.deletedCount,
        otps: otpResult.deletedCount
      }
    });
  } catch (error) {
    console.error('❌ Delete account error:', error);
    res.status(500).json({
      success: false,
      message: 'Không thể xóa tài khoản'
    });
  }
});

app.listen(5000, () => {
  console.log('Test server running on port 5000');
});
