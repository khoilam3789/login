# 🚀 Production Deployment Guide

## 1. PREPARATION CHECKLIST

### Security Configuration

- [ ] **Change all default secrets**
  ```bash
  # Generate strong secrets
  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
  ```

- [ ] **Setup AWS KMS (or equivalent)**
  - Create KMS key for encryption
  - Configure IAM roles with least privilege
  - Enable automatic key rotation

- [ ] **SSL/TLS Certificates**
  - Use Let's Encrypt or commercial CA
  - Configure HTTPS redirect
  - Enable HSTS headers

- [ ] **Environment Variables**
  - Never commit `.env` files
  - Use secret management (AWS Secrets Manager, HashiCorp Vault)
  - Rotate secrets regularly

### Database Configuration

- [ ] **MongoDB Atlas (Recommended)**
  ```
  - Enable encryption at rest
  - Configure IP whitelist
  - Enable MongoDB authentication
  - Set up automated backups
  - Configure replica sets
  ```

- [ ] **Database Indexes**
  ```bash
  npm run db:init  # Creates all necessary indexes
  ```

- [ ] **Backup Strategy**
  - Daily full backups
  - Hourly incremental backups
  - Test restore procedures
  - Off-site backup storage

### Application Security

- [ ] **Enable Rate Limiting**
  - Configure Redis for distributed rate limiting
  - Set appropriate limits per endpoint

- [ ] **Input Validation**
  - All schemas with Zod validated
  - Sanitization middleware enabled
  - XSS protection configured

- [ ] **Audit Logging**
  - Configure log retention policy
  - Set up log aggregation (ELK, Splunk)
  - Enable alerting for critical events

## 2. INFRASTRUCTURE SETUP

### Option A: AWS Deployment

#### Backend (EC2 / Elastic Beanstalk)

```bash
# Install Node.js
curl -sL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs

# Clone repository
git clone <your-repo>
cd password-manager/backend

# Install dependencies
npm install --production

# Build TypeScript
npm run build

# Install PM2 for process management
sudo npm install -g pm2

# Start application
pm2 start dist/server.js --name password-manager

# Setup PM2 startup
pm2 startup
pm2 save
```

#### Environment Setup

```bash
# Create .env file
cat > .env << EOF
NODE_ENV=production
PORT=5000

# Database
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/password_manager_db?retryWrites=true&w=majority

# Redis
REDIS_URL=redis://your-elasticache-endpoint:6379

# JWT
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
JWT_REFRESH_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")

# AWS KMS
AWS_REGION=us-east-1
KMS_KEY_ID=alias/password-manager-master-key

# Email
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# Frontend URL
FRONTEND_URL=https://your-domain.com
EOF

# Secure .env file
chmod 600 .env
```

#### Nginx Configuration

```nginx
# /etc/nginx/sites-available/password-manager-api
server {
    listen 80;
    server_name api.yourdomain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL Certificates
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to Node.js
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;
}
```

#### Frontend (S3 + CloudFront)

```bash
# Build React app
cd frontend
npm run build

# Upload to S3
aws s3 sync build/ s3://your-bucket-name --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation --distribution-id YOUR_DISTRIBUTION_ID --paths "/*"
```

#### CloudFront Configuration

```json
{
  "ViewerProtocolPolicy": "redirect-to-https",
  "AllowedMethods": ["GET", "HEAD", "OPTIONS"],
  "CachedMethods": ["GET", "HEAD"],
  "Compress": true,
  "DefaultTTL": 86400,
  "MaxTTL": 31536000,
  "MinTTL": 0,
  "SmoothStreaming": false,
  "CustomErrorResponses": [
    {
      "ErrorCode": 404,
      "ResponseCode": 200,
      "ResponsePagePath": "/index.html"
    }
  ]
}
```

### Option B: Docker Deployment

#### Dockerfile (Backend)

```dockerfile
# Backend Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Production image
FROM node:18-alpine

WORKDIR /app

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

USER nodejs

EXPOSE 5000

CMD ["node", "dist/server.js"]
```

#### docker-compose.yml

```yaml
version: '3.8'

services:
  # MongoDB
  mongodb:
    image: mongo:6
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
    volumes:
      - mongodb_data:/data/db
      - ./mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    networks:
      - app-network

  # Redis
  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - app-network

  # Backend API
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: always
    ports:
      - "5000:5000"
    environment:
      NODE_ENV: production
      MONGODB_URI: mongodb://admin:${MONGO_PASSWORD}@mongodb:27017/password_manager_db?authSource=admin
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      JWT_SECRET: ${JWT_SECRET}
      JWT_REFRESH_SECRET: ${JWT_REFRESH_SECRET}
      SERVER_ENCRYPTION_KEY: ${SERVER_ENCRYPTION_KEY}
    depends_on:
      - mongodb
      - redis
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
    networks:
      - app-network

volumes:
  mongodb_data:
  redis_data:

networks:
  app-network:
    driver: bridge
```

#### Deploy with Docker

```bash
# Create .env file with secrets
cp .env.example .env
# Edit .env with production values

# Build and start services
docker-compose up -d --build

# Check logs
docker-compose logs -f backend

# Scale backend (if needed)
docker-compose up -d --scale backend=3
```

### Option C: Kubernetes Deployment

#### k8s/deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: password-manager-backend
  labels:
    app: password-manager
spec:
  replicas: 3
  selector:
    matchLabels:
      app: password-manager
  template:
    metadata:
      labels:
        app: password-manager
    spec:
      containers:
      - name: backend
        image: your-registry/password-manager-backend:latest
        ports:
        - containerPort: 5000
        env:
        - name: NODE_ENV
          value: "production"
        - name: MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: mongodb-uri
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: password-manager-service
spec:
  selector:
    app: password-manager
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
  type: LoadBalancer
```

## 3. MONITORING & LOGGING

### Sentry Integration

```typescript
// src/config/sentry.ts
import * as Sentry from '@sentry/node';
import * as Tracing from '@sentry/tracing';
import { Express } from 'express';

export const initSentry = (app: Express) => {
  if (process.env.SENTRY_DSN) {
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV,
      integrations: [
        new Sentry.Integrations.Http({ tracing: true }),
        new Tracing.Integrations.Express({ app })
      ],
      tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0
    });

    app.use(Sentry.Handlers.requestHandler());
    app.use(Sentry.Handlers.tracingHandler());
  }
};

export const sentryErrorHandler = Sentry.Handlers.errorHandler();
```

### CloudWatch Logs (AWS)

```typescript
// src/config/cloudwatch.ts
import winston from 'winston';
import WinstonCloudWatch from 'winston-cloudwatch';

const cloudwatchTransport = new WinstonCloudWatch({
  logGroupName: '/password-manager/backend',
  logStreamName: () => {
    const date = new Date().toISOString().split('T')[0];
    return `${process.env.NODE_ENV}-${date}`;
  },
  awsRegion: process.env.AWS_REGION,
  messageFormatter: ({ level, message, ...meta }) => {
    return JSON.stringify({ level, message, ...meta });
  }
});

logger.add(cloudwatchTransport);
```

### Metrics with Prometheus

```typescript
// src/middlewares/metrics.middleware.ts
import promClient from 'prom-client';
import { Express } from 'express';

const register = new promClient.Registry();

// Default metrics
promClient.collectDefaultMetrics({ register });

// Custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

export const metricsMiddleware = (app: Express) => {
  app.use((req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
      const duration = (Date.now() - start) / 1000;
      httpRequestDuration
        .labels(req.method, req.route?.path || req.path, res.statusCode.toString())
        .observe(duration);
    });
    
    next();
  });

  // Metrics endpoint
  app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });
};
```

## 4. BACKUP & DISASTER RECOVERY

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup"
MONGODB_URI="your-mongodb-uri"
S3_BUCKET="your-backup-bucket"

# MongoDB backup
mongodump --uri="${MONGODB_URI}" --out="${BACKUP_DIR}/mongodb_${DATE}"

# Compress
tar -czf "${BACKUP_DIR}/mongodb_${DATE}.tar.gz" "${BACKUP_DIR}/mongodb_${DATE}"
rm -rf "${BACKUP_DIR}/mongodb_${DATE}"

# Upload to S3
aws s3 cp "${BACKUP_DIR}/mongodb_${DATE}.tar.gz" "s3://${S3_BUCKET}/backups/"

# Keep only last 30 days
find "${BACKUP_DIR}" -name "mongodb_*.tar.gz" -mtime +30 -delete

# Verify backup
mongorestore --uri="${MONGODB_URI}" --dry-run "${BACKUP_DIR}/mongodb_${DATE}.tar.gz"

echo "Backup completed: mongodb_${DATE}.tar.gz"
```

### Cron Job Setup

```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * /path/to/backup.sh >> /var/log/backup.log 2>&1
```

## 5. SECURITY HARDENING

### Firewall Rules (UFW)

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow MongoDB (only from application server)
sudo ufw allow from <app-server-ip> to any port 27017

# Enable firewall
sudo ufw enable
```

### Fail2Ban Configuration

```ini
# /etc/fail2ban/jail.local
[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
findtime = 60
bantime = 3600

[password-manager-auth]
enabled = true
filter = password-manager-auth
logpath = /app/logs/combined.log
maxretry = 5
findtime = 900
bantime = 7200
```

## 6. CI/CD PIPELINE

### GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
        working-directory: ./backend
      
      - name: Run tests
        run: npm test
        working-directory: ./backend
      
      - name: Lint
        run: npm run lint
        working-directory: ./backend

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: docker build -t password-manager-backend ./backend
      
      - name: Push to registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker tag password-manager-backend your-registry/password-manager-backend:latest
          docker push your-registry/password-manager-backend:latest
      
      - name: Deploy to production
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.PROD_SERVER }}
          username: ${{ secrets.PROD_USER }}
          key: ${{ secrets.PROD_SSH_KEY }}
          script: |
            cd /app
            docker-compose pull backend
            docker-compose up -d backend
            docker system prune -f
```

## 7. POST-DEPLOYMENT VERIFICATION

### Health Checks

```bash
# API health
curl https://api.yourdomain.com/health

# Expected response:
# {
#   "status": "OK",
#   "timestamp": "2024-01-01T00:00:00.000Z",
#   "uptime": 12345,
#   "environment": "production"
# }

# Database connectivity
curl https://api.yourdomain.com/api/v1/health/db

# Redis connectivity
curl https://api.yourdomain.com/api/v1/health/redis
```

### Load Testing

```bash
# Install Artillery
npm install -g artillery

# Run load test
artillery quick --count 100 --num 10 https://api.yourdomain.com/health

# Load test registration endpoint
artillery quick --count 50 --num 5 -p test-data.json https://api.yourdomain.com/api/v1/auth/register
```

## 8. ROLLBACK PROCEDURE

```bash
# 1. Identify last working version
git log --oneline

# 2. Rollback code
git revert <commit-hash>
git push

# 3. Rollback Docker container
docker-compose stop backend
docker-compose run backend git checkout <previous-version>
docker-compose up -d backend

# 4. Rollback database (if needed)
mongorestore --uri="mongodb-uri" --drop /backup/mongodb_TIMESTAMP

# 5. Verify
curl https://api.yourdomain.com/health
```

## 9. MAINTENANCE MODE

```nginx
# Enable maintenance mode
# /etc/nginx/sites-available/password-manager-api

# Add before location block:
if (-f /var/www/maintenance.html) {
    return 503;
}

error_page 503 @maintenance;
location @maintenance {
    root /var/www;
    rewrite ^(.*)$ /maintenance.html break;
}
```

```bash
# Enable maintenance
sudo touch /var/www/maintenance.html

# Disable maintenance
sudo rm /var/www/maintenance.html
```

---

## 📞 Emergency Contacts

- **DevOps Team**: devops@company.com
- **Security Team**: security@company.com
- **On-Call**: +1-XXX-XXX-XXXX

## 📚 Additional Resources

- [MongoDB Atlas Documentation](https://docs.atlas.mongodb.com/)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [Let's Encrypt](https://letsencrypt.org/)
- [OWASP Security Guidelines](https://owasp.org/)
