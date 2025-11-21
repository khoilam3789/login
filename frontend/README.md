# Password Manager - Frontend

Frontend application cho hệ thống quản lý mật khẩu với kiến trúc Zero-Knowledge.

## 🚀 Công nghệ

- **React 18** - UI library
- **TypeScript 5** - Type safety
- **Vite 5** - Build tool & dev server
- **Tailwind CSS 3** - Styling
- **React Router 6** - Routing
- **React Hot Toast** - Notifications
- **Web Crypto API** - Client-side encryption

## 📁 Cấu trúc thư mục

```
src/
├── components/          # UI components
│   ├── Button.tsx
│   ├── Input.tsx
│   ├── Card.tsx
│   ├── Modal.tsx
│   └── ProtectedRoute.tsx
├── contexts/           # React Context providers
│   ├── AuthContext.tsx
│   └── VaultContext.tsx
├── pages/              # Page components
│   ├── LoginPage.tsx
│   ├── RegisterPage.tsx
│   ├── DashboardPage.tsx
│   ├── VaultPage.tsx
│   ├── ExternalOTPPage.tsx
│   └── SettingsPage.tsx
├── services/           # Business logic & API
│   ├── crypto.service.ts    # Client-side encryption
│   ├── api.service.ts       # HTTP client
│   ├── auth.service.ts      # Authentication
│   ├── vault.service.ts     # Vault operations
│   └── otp.service.ts       # OTP management
├── App.tsx            # Main app component
├── main.tsx           # Entry point
└── index.css          # Global styles
```

## 🔐 Kiến trúc Zero-Knowledge

### 1. Master Password Flow

```
Master Password (client)
    ↓ PBKDF2 (600k iterations)
    ├─→ Encryption Key (EK) - mã hóa DEK
    └─→ Auth Key (AK) → SHA-256 → Auth Key Hash (gửi đến server)
```

### 2. Data Encryption Key (DEK)

```
DEK (generated client-side)
    ↓ Encrypted với EK
    └─→ Encrypted DEK (lưu trên server)
```

### 3. Vault Data Flow

```
Vault Data (plaintext)
    ↓ Encrypted với DEK
    └─→ Encrypted Data (lưu trên server)
```

**Server không bao giờ thấy:**
- Master Password
- Encryption Key (EK)
- Data Encryption Key (DEK) dạng plaintext
- Vault data dạng plaintext

## 🛠️ Cài đặt

### 1. Cài dependencies

```bash
npm install
```

### 2. Cấu hình environment

Tạo file `.env`:

```env
VITE_API_URL=http://localhost:5000/api/v1
```

### 3. Chạy development server

```bash
npm run dev
```

Ứng dụng sẽ chạy tại: http://localhost:5173

## 📦 Build cho production

```bash
npm run build
```

File build sẽ được tạo trong thư mục `dist/`.

### Preview production build

```bash
npm run preview
```

## 🔒 Tính năng bảo mật

### 1. Client-side Encryption

Tất cả dữ liệu nhạy cảm được mã hóa trên client trước khi gửi đến server:

```typescript
// Tạo DEK
const dek = await ClientCryptoService.generateDEK();

// Mã hóa dữ liệu
const encrypted = await ClientCryptoService.encrypt(data, dek);

// Server chỉ nhận encrypted data
await apiClient.post('/vault', encrypted);
```

### 2. Key Derivation

PBKDF2 với 600,000 iterations để chống brute-force:

```typescript
const { encryptionKey, authKey } = await ClientCryptoService.deriveMasterKeys(
  masterPassword,
  salt
);
```

### 3. Password Strength Checking

```typescript
const strength = ClientCryptoService.calculatePasswordStrength(password);
// Returns: { score, label, feedback[] }
```

### 4. Secure Random Generation

```typescript
// Tạo password ngẫu nhiên an toàn
const password = ClientCryptoService.generatePassword(16);
```

## 🎯 Các trang chính

### 1. Login (`/login`)
- Đăng nhập với email + master password
- Derive encryption keys client-side
- Request OTP nếu bật 2FA

### 2. Register (`/register`)
- Tạo tài khoản mới
- Password strength indicator
- Generate và encrypt DEK

### 3. Dashboard (`/dashboard`)
- Tổng quan vault
- Stats (tổng mục, favorites, categories)
- Quick actions

### 4. Vault (`/vault`)
- Quản lý mật khẩu
- CRUD operations
- Search & filter
- Copy to clipboard
- Password generator

### 5. External OTP (`/external-otp`)
- Lưu trữ 2FA secrets
- Generate TOTP codes
- Countdown timer
- Base32 decoding

### 6. Settings (`/settings`)
- Quản lý tài khoản
- Export/Import vault
- Đổi master password
- Session management

## 🔑 Authentication Flow

### Registration

```typescript
// 1. Generate salt
const salt = ClientCryptoService.generateSalt();

// 2. Derive keys
const { encryptionKey, authKey } = await deriveMasterKeys(password, salt);

// 3. Hash auth key
const authKeyHash = await hashAuthKey(authKey);

// 4. Generate & encrypt DEK
const dek = await generateDEK();
const encryptedDEK = await encryptDEK(dek, encryptionKey);

// 5. Send to server
await register({ email, authKeyHash, salt, encryptedDEK });
```

### Login

```typescript
// 1. Get salt from server
const { salt } = await getSalt(email);

// 2. Derive keys
const { encryptionKey, authKey } = await deriveMasterKeys(password, salt);

// 3. Hash and verify
const authKeyHash = await hashAuthKey(authKey);
const { token, encryptedDEK } = await login(email, authKeyHash);

// 4. Decrypt DEK
const dek = await decryptDEK(encryptedDEK, encryptionKey);

// 5. Store in memory (Context)
setDek(dek);
```

## 🧪 Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage
```

## 📊 Performance

### Optimization strategies:

1. **Code splitting** - Lazy load pages
2. **Memoization** - React.memo for components
3. **Debouncing** - Search inputs
4. **Virtual scrolling** - Long vault lists
5. **Web Workers** - Heavy crypto operations

## 🐛 Debugging

### Enable debug logs

```typescript
// In crypto.service.ts
const DEBUG = true;

if (DEBUG) {
  console.log('Encryption key:', encryptionKey);
}
```

### Check vault state

```typescript
// In DevTools Console
window.__VAULT_CONTEXT__
```

## 🔄 State Management

### AuthContext

```typescript
const { user, dek, isAuthenticated, login, logout } = useAuth();
```

### VaultContext

```typescript
const { 
  items, 
  isLoading, 
  createVaultItem, 
  updateVaultItem, 
  deleteVaultItem 
} = useVault();
```

## 🎨 Styling

### Tailwind CSS Classes

```tsx
<Button 
  variant="primary"    // primary | secondary | danger | ghost
  size="md"           // sm | md | lg
  fullWidth={true}
  isLoading={false}
/>
```

### Custom CSS Utilities

```css
/* in index.css */
.btn { @apply px-4 py-2 rounded-lg ... }
.input { @apply w-full px-4 py-2 border ... }
.card { @apply bg-white rounded-xl shadow-sm ... }
```

## 📱 Responsive Design

- **Mobile**: < 640px
- **Tablet**: 640px - 1024px
- **Desktop**: > 1024px

```tsx
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
```

## 🌐 Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

**Required APIs:**
- Web Crypto API
- IndexedDB
- LocalStorage

## 🔗 API Integration

Base URL: `http://localhost:5000/api/v1`

### Endpoints

```
POST   /auth/register     - Đăng ký
POST   /auth/login        - Đăng nhập
POST   /auth/logout       - Đăng xuất
GET    /vault             - Lấy tất cả vault items
POST   /vault             - Tạo vault item
PUT    /vault/:id         - Cập nhật vault item
DELETE /vault/:id         - Xóa vault item
GET    /otp/external-secrets - Lấy external secrets
POST   /otp/external-secrets - Thêm external secret
```

## 📝 Environment Variables

```env
# API URL
VITE_API_URL=http://localhost:5000/api/v1

# Feature flags
VITE_ENABLE_2FA=true
VITE_ENABLE_BIOMETRIC=false

# Debug
VITE_DEBUG=false
```

## 🚀 Deployment

### Build

```bash
npm run build
```

### Deploy to Netlify

```bash
netlify deploy --prod
```

### Deploy to Vercel

```bash
vercel --prod
```

### Environment variables (Production)

```
VITE_API_URL=https://api.yourapp.com/api/v1
```

## 📚 Documentation Links

- [ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
- [FRONTEND_CRYPTO.md](../FRONTEND_CRYPTO.md) - Crypto implementation
- [SECURITY_BEST_PRACTICES.md](../SECURITY_BEST_PRACTICES.md) - Security guide
- [DATABASE_SCHEMA.md](../DATABASE_SCHEMA.md) - Database design

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

MIT License - see LICENSE file

## 👨‍💻 Author

Password Manager Team

---

**⚠️ Security Notice:**

Master password không thể khôi phục. Nếu quên master password, dữ liệu vault sẽ mất vĩnh viễn.

**🔐 Zero-Knowledge:**

Server không bao giờ có quyền truy cập vào dữ liệu plaintext của bạn.
