# 🔐 Password Manager - Hệ Thống Quản Lý Mật Khẩu An Toàn

## 📋 Tổng Quan

Đây là một hệ thống quản lý mật khẩu được thiết kế với kiến trúc **Zero-Knowledge**, đảm bảo rằng ngay cả server cũng không thể đọc được mật khẩu của người dùng.

### ✨ Tính Năng Chính

- ✅ **Zero-Knowledge Architecture**: Server không bao giờ biết master password hoặc có thể decrypt mật khẩu
- 🔒 **AES-256-GCM Encryption**: Mã hóa mạnh mẽ cho tất cả dữ liệu nhạy cảm
- 🔑 **Multi-Layer Encryption**: Client-side + Server-side encryption
- 📱 **OTP Authentication**: Hỗ trợ Email/SMS OTP cho các thao tác nhạy cảm
- 🔐 **External 2FA Storage**: Lưu trữ TOTP secrets cho Gmail, GitHub, AWS, etc.
- 🛡️ **Advanced Security**: Rate limiting, input validation, audit logging
- 🔄 **Key Rotation**: Hỗ trợ rotation keys không làm mất dữ liệu
- 📊 **Audit Trail**: Log đầy đủ các hoạt động bảo mật
- 🚀 **Modern Stack**: React + TypeScript + Node.js + MongoDB

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT (React)                        │
│  • Master Password → PBKDF2 → Encryption Key            │
│  • Client-side Encryption/Decryption                    │
│  • Zero-Knowledge Implementation                        │
└─────────────────────────────────────────────────────────┘
                         ↕ HTTPS
┌─────────────────────────────────────────────────────────┐
│                   SERVER (Node.js)                       │
│  • MVC Architecture                                      │
│  • Additional Encryption Layer                          │
│  • OTP Management                                        │
│  • Audit Logging                                         │
└─────────────────────────────────────────────────────────┘
                         ↕
┌─────────────────────────────────────────────────────────┐
│                   DATABASE (MongoDB)                     │
│  • Encrypted vault items                                │
│  • User credentials (hashed)                            │
│  • Security logs                                         │
└─────────────────────────────────────────────────────────┘
```

## 📚 Tài Liệu Chi Tiết

Dự án bao gồm các tài liệu chi tiết sau:

1. **[ARCHITECTURE.md](./ARCHITECTURE.md)** - Kiến trúc tổng thể và phân tích bảo mật
   - Mô hình Zero-Knowledge
   - Encryption at Rest
   - Key Management
   - OTP System
   - Input Validation

2. **[DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md)** - Thiết kế database MongoDB
   - Schema cho tất cả collections
   - Indexes và optimization
   - Backup strategy

3. **[API_DOCUMENTATION.md](./API_DOCUMENTATION.md)** - API endpoints (sẽ tạo)
   - Authentication endpoints
   - Vault management
   - OTP operations

## 🚀 Cài Đặt và Chạy

### Yêu Cầu Hệ Thống

- Node.js >= 18.0.0
- MongoDB >= 6.0
- Redis >= 7.0 (cho rate limiting)
- npm >= 9.0.0

### 1. Backend Setup

```bash
cd backend

# Cài đặt dependencies
npm install

# Tạo file .env từ template
cp .env.example .env

# Cập nhật các biến môi trường trong .env
# Đặc biệt quan trọng:
# - MONGODB_URI
# - JWT_SECRET
# - SERVER_ENCRYPTION_KEY (generate bằng: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
# - EMAIL_USER và EMAIL_PASSWORD (cho OTP)

# Khởi tạo database (tạo indexes)
npm run db:init

# Chạy development server
npm run dev

# Build cho production
npm run build
npm start
```

### 2. Frontend Setup (Sẽ tạo)

```bash
cd frontend

# Cài đặt dependencies
npm install

# Tạo file .env
cp .env.example .env

# Cập nhật REACT_APP_API_URL trong .env

# Chạy development
npm start

# Build cho production
npm run build
```

### 3. Generate Server Encryption Key

```bash
# Generate random 256-bit key
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Paste output vào .env:
# SERVER_ENCRYPTION_KEY=<generated_key>
```

### 4. Setup Email cho OTP

Để gửi OTP qua email, cấu hình Gmail:

1. Bật 2-Step Verification trong Google Account
2. Tạo App Password: https://myaccount.google.com/apppasswords
3. Update `.env`:
```
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

## 🔐 Zero-Knowledge Flow

### Đăng Ký (Registration)

```
1. User nhập Master Password (MP)
2. CLIENT: Generate salt (random 32 bytes)
3. CLIENT: Derive Encryption Key:
   EK = PBKDF2(MP, salt, 600k iterations)
4. CLIENT: Derive Auth Key:
   AK = PBKDF2(EK, "auth", 100k iterations)
5. CLIENT: Hash Auth Key:
   AK_Hash = Argon2id(AK)
6. CLIENT: Generate Data Encryption Key (DEK)
7. CLIENT: Encrypt DEK với EK:
   Encrypted_DEK = AES-256-GCM(DEK, EK)
8. SEND TO SERVER:
   - email
   - AK_Hash (double hashed on server)
   - salt
   - Encrypted_DEK
9. SERVER: Không bao giờ thấy MP, EK, hoặc plaintext DEK
```

### Đăng Nhập (Login)

```
1. CLIENT: Fetch salt từ server
2. CLIENT: Derive EK = PBKDF2(MP, salt, 600k)
3. CLIENT: Derive AK = PBKDF2(EK, "auth", 100k)
4. CLIENT: Hash AK_Hash = Argon2id(AK)
5. SEND TO SERVER: email, AK_Hash
6. SERVER: Verify AK_Hash, return JWT + Encrypted_DEK
7. CLIENT: Decrypt DEK = AES-256-GCM-Decrypt(Encrypted_DEK, EK)
8. CLIENT: Store DEK in memory (NOT localStorage)
9. Use DEK to encrypt/decrypt vault items
```

### Lưu Mật Khẩu

```
1. CLIENT: Encrypt password với DEK
2. SEND TO SERVER: Ciphertext + IV
3. SERVER: Optional - add another encryption layer
4. SERVER: Store in MongoDB
5. Server không thể decrypt vì không có DEK
```

## 🛡️ Tính Năng Bảo Mật

### 1. Multi-Layer Encryption

```
Plaintext Password
    ↓ Client Encrypt (DEK - derived from Master Password)
Ciphertext 1
    ↓ Server Encrypt (Server Master Key from KMS)
Ciphertext 2
    ↓ Store in MongoDB
```

### 2. Input Validation

- ✅ Schema validation với Zod
- ✅ NoSQL injection prevention
- ✅ XSS protection
- ✅ Command injection prevention
- ✅ Rate limiting

### 3. OTP cho Thao Tác Nhạy Cảm

Yêu cầu OTP khi:
- Đăng nhập từ thiết bị mới
- Copy password
- Export vault
- Thay đổi master password
- Xóa tài khoản

### 4. Audit Logging

Tất cả hoạt động được log:
- Login attempts (success/failed)
- Password access
- OTP generation/verification
- Key rotation
- Setting changes

### 5. Rate Limiting

```typescript
// General API: 100 requests / 15 phút
// Authentication: 5 attempts / 15 phút
// OTP: 3 requests / 5 phút
```

## 📊 Database Collections

```
users                  - User accounts
vault_items            - Encrypted passwords
otp_sessions           - Temporary OTP data
audit_logs             - Security events
encryption_keys        - Key metadata
external_otp_secrets   - 2FA for external services
sessions               - Active sessions
device_trust           - Trusted devices
```

## 🔑 Environment Variables

### Critical Variables

```bash
# Security - MUST CHANGE in production
JWT_SECRET=<random-secret>
JWT_REFRESH_SECRET=<random-secret>
SERVER_ENCRYPTION_KEY=<base64-encoded-32-bytes>

# Database
MONGODB_URI=mongodb://localhost:27017/password_manager_db

# Redis
REDIS_URL=redis://localhost:6379

# Email (cho OTP)
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

### Optional (Production)

```bash
# AWS KMS (recommended for production)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=<your-key>
AWS_SECRET_ACCESS_KEY=<your-secret>
KMS_KEY_ID=alias/password-manager-master-key

# SMS OTP (Twilio)
TWILIO_ACCOUNT_SID=<your-sid>
TWILIO_AUTH_TOKEN=<your-token>
TWILIO_PHONE_NUMBER=+1234567890
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Watch mode
npm run test:watch
```

## 📈 API Endpoints

### Authentication
```
POST /api/v1/auth/register       - Đăng ký
POST /api/v1/auth/login          - Đăng nhập
POST /api/v1/auth/logout         - Đăng xuất
POST /api/v1/auth/refresh        - Refresh token
POST /api/v1/auth/verify-email   - Xác thực email
```

### Vault Management
```
GET    /api/v1/vault/items       - Lấy danh sách items
POST   /api/v1/vault/items       - Tạo item mới
GET    /api/v1/vault/items/:id   - Lấy chi tiết item
PUT    /api/v1/vault/items/:id   - Cập nhật item
DELETE /api/v1/vault/items/:id   - Xóa item
```

### OTP Operations
```
POST /api/v1/otp/request         - Yêu cầu OTP
POST /api/v1/otp/verify          - Xác thực OTP
POST /api/v1/otp/resend          - Gửi lại OTP
```

### External OTP (2FA Storage)
```
GET    /api/v1/vault/external-otp       - Danh sách
POST   /api/v1/vault/external-otp       - Thêm mới
GET    /api/v1/vault/external-otp/:id   - Chi tiết
PUT    /api/v1/vault/external-otp/:id   - Cập nhật
DELETE /api/v1/vault/external-otp/:id   - Xóa
POST   /api/v1/vault/external-otp/:id/generate - Generate TOTP code
```

## 🔒 Best Practices

### 1. Key Management

```typescript
// ❌ NEVER do this
const SECRET_KEY = "my-secret-key";

// ✅ DO this
const SECRET_KEY = process.env.SERVER_ENCRYPTION_KEY;
if (!SECRET_KEY) throw new Error('Key not configured');
```

### 2. Password Storage

```typescript
// ❌ NEVER store plaintext
await User.create({ password: req.body.password });

// ✅ ALWAYS hash
const hashedPassword = await argon2.hash(req.body.password);
await User.create({ password: hashedPassword });
```

### 3. Input Validation

```typescript
// ❌ Trust user input
const email = req.body.email;

// ✅ Validate first
const EmailSchema = z.string().email();
const email = EmailSchema.parse(req.body.email);
```

### 4. Error Handling

```typescript
// ❌ Expose sensitive info
catch (error) {
  res.json({ error: error.message });
}

// ✅ Generic error message
catch (error) {
  logger.error('Error:', error);
  res.json({ error: 'An error occurred' });
}
```

## 🚀 Deployment

### Production Checklist

- [ ] Change all default secrets
- [ ] Setup AWS KMS for key management
- [ ] Configure HTTPS/SSL certificates
- [ ] Enable MongoDB encryption at rest
- [ ] Setup backup strategy
- [ ] Configure monitoring (Sentry, DataDog)
- [ ] Enable audit log retention
- [ ] Setup rate limiting with Redis
- [ ] Configure CORS properly
- [ ] Setup CDN for frontend
- [ ] Enable 2FA for admin accounts

### Recommended Infrastructure

```
Frontend: Vercel / Netlify
Backend: AWS EC2 / DigitalOcean / Heroku
Database: MongoDB Atlas (with encryption at rest)
Redis: AWS ElastiCache / Redis Cloud
KMS: AWS KMS / Azure Key Vault
Monitoring: Sentry + DataDog
```

## 📝 License

MIT License

## 👥 Contributing

Contributions are welcome! Please read the contributing guidelines first.

## 📞 Support

For issues and questions, please open a GitHub issue.

---

## 🔥 Quick Start (Development)

```bash
# Clone repo
git clone <repo-url>
cd password-manager

# Backend setup
cd backend
npm install
cp .env.example .env
# Edit .env với các thông tin cần thiết
npm run dev

# Frontend setup (trong terminal khác)
cd frontend
npm install
cp .env.example .env
# Edit .env
npm start

# Truy cập http://localhost:3000
```

## 🎯 Roadmap

- [x] Zero-Knowledge Architecture
- [x] AES-256-GCM Encryption
- [x] OTP Authentication
- [x] External 2FA Storage
- [x] Audit Logging
- [ ] Browser Extension
- [ ] Mobile App (React Native)
- [ ] Secure Password Sharing
- [ ] Import from other password managers
- [ ] Password strength checker
- [ ] Breach monitoring
- [ ] Biometric authentication

---

**⚠️ Security Notice**: Đây là một dự án educational/demonstration. Trước khi sử dụng trong production, vui lòng:
- Security audit bởi chuyên gia
- Penetration testing
- Compliance check (GDPR, SOC2, etc.)
- Insurance và legal protection

**🔐 Remember**: Bảo mật là một quá trình liên tục, không phải là một trạng thái. Luôn cập nhật dependencies và theo dõi security advisories.
