
# 🔐 CryptoNote - Enterprise Password Manager

A military-grade secure password manager with zero-knowledge architecture, built with enterprise security features including multi-factor authentication, anomaly detection, and comprehensive audit logging.

## 🛡️ Security Features

### **Core Security**
- **AES-256-GCM Encryption** - Authenticated encryption with per-user keys
- **Zero-Knowledge Architecture** - Server never sees plaintext passwords
- **bcrypt 14+ Rounds** - Military-grade password hashing
- **PBKDF2 Key Derivation** - 100,000+ iterations for user keys
- **Perfect Forward Secrecy** - Session keys rotated regularly

### **Authentication & Access Control**
- **Multi-Factor Authentication** - TOTP and SMS support
- **Role-Based Access Control (RBAC)** - Granular permissions system
- **Device Fingerprinting** - Track and verify known devices
- **Session Management** - Secure Redis-backed sessions
- **JWT with Refresh Tokens** - Short-lived access tokens

### **Threat Detection & Response**
- **AI/ML Anomaly Detection** - Real-time behavioral analysis
- **Brute Force Protection** - Progressive delays and account lockout
- **Rate Limiting** - Multi-tier request throttling
- **Velocity Attack Detection** - Automated rapid-fire attack prevention
- **Geographic Analysis** - Unusual location access detection

### **Compliance & Audit**
- **Complete Audit Trail** - Every action logged with integrity protection
- **GDPR/HIPAA/SOX Ready** - Compliance-focused design
- **Tamper-Evident Logs** - Cryptographic log integrity
- **Real-time Monitoring** - Security event correlation
- **Forensic Analysis** - Detailed incident investigation tools

### **Input Security**
- **XSS Protection** - Content sanitization and CSP headers
- **NoSQL Injection Prevention** - Input sanitization and validation
- **CSRF Protection** - Token-based request validation
- **Parameter Pollution Protection** - HPP middleware
- **JSON Schema Validation** - Strict input validation

## 🏗️ Architecture

### **Technology Stack**
- **Backend**: Node.js + Express.js with enterprise security middleware
- **Database**: MongoDB with encryption at rest
- **Cache/Sessions**: Redis with TLS encryption
- **Frontend**: React 19 + Vite + TypeScript
- **ML/AI**: TensorFlow.js for anomaly detection
- **Monitoring**: Winston logging + structured audit trails

### **Security Architecture**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   React Client  │    │  Express Server  │    │   MongoDB       │
│                 │    │                  │    │                 │
│ • Web Crypto    │◄──►│ • Rate Limiting  │◄──►│ • Encrypted     │
│ • Device ID     │    │ • Input Validation│    │ • Audit Logs    │
│ • MFA UI        │    │ • RBAC           │    │ • User Data     │
└─────────────────┘    │ • Anomaly ML     │    └─────────────────┘
                       │ • Audit Logging  │    
                       └──────────────────┘    
                                │
                       ┌──────────────────┐
                       │      Redis       │
                       │                  │
                       │ • Sessions       │
                       │ • Rate Limits    │
                       │ • ML Data        │
                       └──────────────────┘
```

## 🚀 Quick Start

### **Prerequisites**
- Node.js 18+ 
- MongoDB 6.0+
- Redis 7.0+
- Git

### **Installation**

1. **Clone Repository**
```bash
git clone https://github.com/your-org/cryptonote.git
cd cryptonote
```

2. **Server Setup**
```bash
cd server
npm install

# Copy and configure environment
cp .env.example .env
# Edit .env with your configuration (see Environment Setup below)

# Generate encryption keys
node -e "console.log('MASTER_ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
```

3. **Client Setup**
```bash
cd ../client/vite-project
npm install
```

4. **Start Services**
```bash
# Terminal 1 - Start MongoDB (if local)
mongod

# Terminal 2 - Start Redis (if local)
redis-server

# Terminal 3 - Start Backend
cd server
npm run dev

# Terminal 4 - Start Frontend
cd client/vite-project
npm run dev
```

5. **Access Application**
- Frontend: http://localhost:5173
- Backend API: http://localhost:5000
- Health Check: http://localhost:5000/health

## ⚙️ Environment Setup

### **Required Environment Variables**

Create `server/.env` from `server/.env.example`:

```bash
# Core Settings
NODE_ENV=development
PORT=5000

# Database
MONGO_URI=mongodb://localhost:27017/cryptonote
REDIS_URL=redis://localhost:6379

# Security Keys (GENERATE NEW ONES!)
JWT_SECRET=your-super-secure-jwt-secret-minimum-32-chars
SESSION_SECRET=your-super-secure-session-secret-minimum-32-chars
MASTER_ENCRYPTION_KEY=64-character-hex-string-exactly-32-bytes

# CORS
CORS_ORIGINS=http://localhost:5173,http://localhost:5174

# Email (Optional - for notifications)
EMAIL_HOST=smtp.gmail.com
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# SMS MFA (Optional - for SMS 2FA)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890
```

### **Key Generation**
```bash
# Generate secure encryption key (32 bytes = 64 hex chars)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate JWT secrets
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## 🔒 Security Configuration

### **Password Policy**
- Minimum 12 characters
- Must include: uppercase, lowercase, numbers, symbols
- Entropy validation
- Common pattern detection
- Breach database checking (optional)

### **MFA Configuration**
```javascript
// TOTP (Recommended)
- Google Authenticator compatible
- 30-second time windows
- 6-digit codes
- Backup codes provided

// SMS (Fallback)
- Twilio integration
- Rate limited (1 per minute)
- 6-digit codes
- 5-minute expiry
```

### **Rate Limiting**
```javascript
// Authentication endpoints
- 5 attempts per 15 minutes
- Progressive delays on failure
- IP-based tracking

// API endpoints
- 100 requests per 15 minutes
- Per-user tracking
- Burst allowance
```

### **Anomaly Detection Thresholds**
```javascript
ANOMALY_THRESHOLD_LOGIN=0.7    // Login pattern analysis
ANOMALY_THRESHOLD_SESSION=0.6  // Session behavior analysis  
ANOMALY_THRESHOLD_VELOCITY=0.8 // Rapid-fire attack detection
```

## 📊 Monitoring & Logging

### **Log Files**
```
logs/
├── server.log          # Application logs
├── audit.log           # Security audit trail
├── security.log        # Security events only
├── compliance.log      # Compliance-specific logs
└── emergency.log       # Critical failure logs
```

### **Audit Events Tracked**
- Authentication attempts (success/failure)
- Password operations (create/read/update/delete)
- MFA events (setup/verification)
- Administrative actions
- Security violations
- System events

### **Real-time Monitoring**
```bash
# Monitor security events
tail -f logs/security.log | jq '.'

# Monitor audit trail
tail -f logs/audit.log | jq '.eventType, .userId, .timestamp'

# Monitor anomaly detection
redis-cli MONITOR | grep anomaly
```

## 🛠️ Development

### **Project Structure**
```
cryptonote/
├── server/                 # Backend API
│   ├── config/            # Security configuration
│   ├── middleware/        # Auth & security middleware
│   ├── models/           # Database models
│   ├── routes/           # API endpoints
│   ├── services/         # Business logic services
│   │   ├── authService.js       # Authentication & MFA
│   │   ├── encryptionService.js # Encryption & key management
│   │   ├── auditService.js      # Audit logging
│   │   ├── anomalyDetection.js  # ML-based threat detection
│   │   └── rbacService.js       # Role-based access control
│   └── utils/            # Utility functions
├── client/vite-project/   # Frontend React app
│   ├── src/
│   │   ├── components/   # Reusable components
│   │   ├── pages/        # Page components
│   │   ├── services/     # API services
│   │   └── utils/        # Client utilities
└── docs/                 # Documentation
```

### **API Endpoints**

#### **Authentication**
```
POST   /api/auth/register        # User registration
POST   /api/auth/login           # User login
POST   /api/auth/logout          # User logout
POST   /api/auth/refresh         # Token refresh
PUT    /api/auth/change-password # Change master password
GET    /api/auth/profile         # Get user profile
GET    /api/auth/security-status # Security dashboard data
```

#### **MFA Management**
```
POST   /api/auth/mfa/setup       # Setup MFA
POST   /api/auth/mfa/sms/send    # Send SMS token
POST   /api/auth/validate-password # Password strength check
```

#### **Password Management**
```
GET    /api/passwords            # List user passwords
POST   /api/passwords            # Create password entry
PUT    /api/passwords/:id        # Update password entry
DELETE /api/passwords/:id        # Delete password entry
```

#### **Categories**
```
GET    /api/categories           # List categories
POST   /api/categories           # Create category
PUT    /api/categories/:id       # Update category
DELETE /api/categories/:id       # Delete category
```

### **Testing**
```bash
# Run security tests
npm run test:security

# Run integration tests
npm run test:integration

# Run performance tests
npm run test:performance

# Security audit
npm audit
npm run security-audit
```

## 🚨 Security Considerations

### **Deployment Security**
- Use HTTPS/TLS 1.3 in production
- Configure proper CSP headers
- Enable HSTS with preload
- Use secure session cookies
- Implement proper CORS policies
- Regular security updates

### **Database Security**
- Enable MongoDB authentication
- Use encrypted connections
- Regular backups with encryption
- Implement proper indexes
- Monitor for injection attempts

### **Infrastructure Security**
- Use VPC/private networks
- Implement WAF rules
- Regular security scanning
- Intrusion detection systems
- Log aggregation and monitoring

### **Incident Response**
1. **Detection** - Automated alerts and monitoring
2. **Analysis** - Forensic log analysis tools
3. **Containment** - Automatic account lockout
4. **Recovery** - Secure backup restoration
5. **Lessons Learned** - Security improvement process

## 📋 Compliance

### **GDPR Compliance**
- Data minimization principles
- Right to erasure implementation
- Data portability features
- Consent management
- Privacy by design

### **Security Standards**
- OWASP Top 10 mitigation
- NIST Cybersecurity Framework
- ISO 27001 alignment
- SOC 2 Type II ready

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/security-enhancement`)
3. Run security tests (`npm run test:security`)
4. Commit changes (`git commit -am 'Add security feature'`)
5. Push to branch (`git push origin feature/security-enhancement`)
6. Create Pull Request

### **Security Guidelines**
- All code must pass security review
- No hardcoded secrets or credentials
- Input validation on all endpoints
- Comprehensive error handling
- Security-focused code comments

## 📞 Support

- **Security Issues**: security@cryptonote.com
- **Bug Reports**: GitHub Issues
- **Documentation**: `/docs` directory
- **Community**: Discord/Slack channels

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security guidelines
- NIST for cybersecurity framework
- Security research community
- Open source security tools

---

**⚠️ Security Notice**: This is enterprise-grade security software. Ensure proper configuration and regular security updates. Never deploy with default credentials or weak encryption keys.

