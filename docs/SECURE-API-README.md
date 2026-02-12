# 🔒 Secure Node.js REST API

Complete production-ready secure REST API built with Node.js, Express, MongoDB, and JWT authentication. All security features in a single file!

## ⭐ Features

### 🛡️ Security Features
- ✅ **JWT Authentication** - Access & Refresh tokens
- ✅ **Password Hashing** - bcrypt with 12 rounds
- ✅ **Rate Limiting** - Prevent brute force attacks
- ✅ **Account Lockout** - 5 failed attempts = 2 hours lock
- ✅ **Helmet Protection** - Secure HTTP headers
- ✅ **CORS Configuration** - Cross-origin security
- ✅ **NoSQL Injection Prevention** - MongoDB sanitization
- ✅ **XSS Protection** - Cross-site scripting prevention
- ✅ **HPP Protection** - HTTP parameter pollution
- ✅ **CSRF Protection** - Cross-site request forgery
- ✅ **Request Size Limiting** - 10kb limit
- ✅ **Input Validation** - express-validator
- ✅ **Role-Based Access Control** - User/Admin/Moderator roles

### 📋 Core Features
- ✅ User Registration & Login
- ✅ Token Refresh Mechanism
- ✅ User Profile Management
- ✅ Product CRUD Operations
- ✅ Pagination Support
- ✅ Comprehensive Error Handling
- ✅ Request Logging (Winston & Morgan)
- ✅ Response Compression
- ✅ Graceful Shutdown

## 🚀 Quick Start

### Prerequisites
- Node.js >= 16.0.0
- MongoDB >= 4.4
- npm >= 8.0.0

### Installation

```bash
# Clone repository
git clone https://github.com/ChetanBiranje/secure-nodejs-api.git
cd secure-nodejs-api

# Install dependencies
npm install

# Create .env file
cp .env.example .env

# Edit .env with your configuration
nano .env

# Start MongoDB (if not running)
mongod

# Run the API
npm start

# Or run in development mode with auto-reload
npm run dev
```

### Environment Variables

Create a `.env` file:

```env
PORT=3000
MONGODB_URI=mongodb://localhost:27017/secure-api
JWT_SECRET=your-super-secret-key-min-256-bits
JWT_EXPIRES_IN=24h
ALLOWED_ORIGINS=http://localhost:3000
```

## 📚 API Documentation

### Base URL
```
http://localhost:3000
```

### Authentication Endpoints

#### 1. Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "_id": "...",
      "username": "johndoe",
      "email": "john@example.com",
      "role": "user"
    },
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc..."
  }
}
```

#### 2. Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### 3. Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGc..."
}
```

#### 4. Logout
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
```

#### 5. Get Current User
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

### User Endpoints

#### 1. Get All Users (Admin Only)
```http
GET /api/users?page=1&limit=10
Authorization: Bearer <admin_token>
```

#### 2. Get User by ID
```http
GET /api/users/:id
Authorization: Bearer <access_token>
```

#### 3. Update User
```http
PUT /api/users/:id
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "username": "newusername",
  "email": "newemail@example.com"
}
```

#### 4. Delete User (Admin Only)
```http
DELETE /api/users/:id
Authorization: Bearer <admin_token>
```

### Product Endpoints

#### 1. Create Product
```http
POST /api/products
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Laptop",
  "description": "High-performance laptop",
  "price": 999.99,
  "category": "Electronics",
  "stock": 50
}
```

#### 2. Get All Products
```http
GET /api/products?page=1&limit=10&category=Electronics
```

#### 3. Get Product by ID
```http
GET /api/products/:id
```

#### 4. Update Product (Owner/Admin)
```http
PUT /api/products/:id
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "price": 899.99,
  "stock": 45
}
```

#### 5. Delete Product (Owner/Admin)
```http
DELETE /api/products/:id
Authorization: Bearer <access_token>
```

## 🔐 Security Implementation Details

### 1. Password Security
```javascript
// Passwords are hashed with bcrypt (12 rounds)
const hashedPassword = await bcrypt.hash(password, 12);

// Password requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)
```

### 2. JWT Authentication
```javascript
// Access Token (24 hours)
const accessToken = jwt.sign(
  { userId, role },
  JWT_SECRET,
  { expiresIn: '24h' }
);

// Refresh Token (7 days)
const refreshToken = jwt.sign(
  { userId, type: 'refresh' },
  JWT_SECRET,
  { expiresIn: '7d' }
);
```

### 3. Rate Limiting
```javascript
// General API: 100 requests per 15 minutes
// Auth endpoints: 5 requests per 15 minutes
// Account lockout: 5 failed login attempts = 2 hours lock
```

### 4. Request Validation
```javascript
// All inputs are validated using express-validator
// MongoDB queries are sanitized
// Request body size limited to 10kb
```

## 🧪 Testing

### Using cURL

**Register:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

**Get Profile:**
```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Postman

1. Import the API endpoints
2. Set environment variable `{{baseUrl}}` = `http://localhost:3000`
3. Set authorization token after login
4. Test all endpoints

## 📊 Database Schema

### User Model
```javascript
{
  username: String (unique, 3-30 chars),
  email: String (unique, lowercase),
  password: String (hashed, min 8 chars),
  role: String (user/admin/moderator),
  isActive: Boolean,
  refreshToken: String,
  loginAttempts: Number,
  lockUntil: Date,
  lastLogin: Date,
  createdAt: Date,
  updatedAt: Date
}
```

### Product Model
```javascript
{
  name: String,
  description: String,
  price: Number,
  category: String,
  stock: Number,
  owner: ObjectId (ref: User),
  isActive: Boolean,
  createdAt: Date,
  updatedAt: Date
}
```

## 🔧 Configuration

### MongoDB Connection
```javascript
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
```

### Security Headers (Helmet)
```javascript
helmet({
  contentSecurityPolicy: {...},
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});
```

### CORS Configuration
```javascript
cors({
  origin: ALLOWED_ORIGINS.split(','),
  credentials: true,
  optionsSuccessStatus: 200
});
```

## 📝 Logging

Logs are saved to:
- `error.log` - Error level logs
- `combined.log` - All logs
- Console - Development output

```javascript
// Log levels: error, warn, info, debug
logger.info('User registered');
logger.error('Database connection failed');
```

## 🚨 Error Handling

All errors are handled centrally:

```javascript
// Validation errors
{
  "success": false,
  "message": "Validation error",
  "errors": [...]
}

// Authentication errors
{
  "success": false,
  "message": "Invalid token"
}

// Not found errors
{
  "success": false,
  "message": "Resource not found"
}
```

## 🎯 Best Practices Implemented

1. ✅ **Environment Variables** - Sensitive data in .env
2. ✅ **Error Handling** - Centralized error middleware
3. ✅ **Input Validation** - All inputs validated
4. ✅ **Password Hashing** - bcrypt with salt rounds
5. ✅ **JWT Security** - Short-lived access tokens
6. ✅ **Rate Limiting** - Prevent abuse
7. ✅ **HTTPS Enforcement** - HSTS headers
8. ✅ **Logging** - Winston logger
9. ✅ **Compression** - Response compression
10. ✅ **Graceful Shutdown** - Clean process termination

## 🔒 Security Checklist

- [x] Helmet security headers
- [x] CORS protection
- [x] Rate limiting
- [x] Input validation
- [x] NoSQL injection prevention
- [x] XSS protection
- [x] Password hashing
- [x] JWT authentication
- [x] Account lockout
- [x] CSRF protection
- [x] HPP protection
- [x] Request size limiting
- [x] Secure cookies
- [x] Error logging
- [x] Environment variables

## 🐛 Troubleshooting

### MongoDB Connection Error
```bash
# Make sure MongoDB is running
mongod

# Or use MongoDB Atlas cloud
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/dbname
```

### Port Already in Use
```bash
# Change port in .env
PORT=3001

# Or kill process using port
lsof -ti:3000 | xargs kill
```

### JWT Token Expired
```bash
# Use refresh token endpoint to get new access token
POST /api/auth/refresh
{
  "refreshToken": "your-refresh-token"
}
```

## 📈 Performance Tips

1. **Use MongoDB Indexes**
```javascript
userSchema.index({ email: 1 });
productSchema.index({ category: 1, createdAt: -1 });
```

2. **Enable Compression**
```javascript
app.use(compression()); // Already enabled
```

3. **Implement Caching**
```javascript
// Add Redis for caching frequently accessed data
```

4. **Database Optimization**
```javascript
// Use lean() for read-only queries
const users = await User.find().lean();
```

## 🚀 Deployment

### Heroku
```bash
heroku create your-api-name
git push heroku main
heroku config:set JWT_SECRET=your-secret
```

### Docker
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["node", "secure-nodejs-api.js"]
```

### Environment Variables for Production
```env
NODE_ENV=production
MONGODB_URI=mongodb+srv://...
JWT_SECRET=<strong-random-secret>
ALLOWED_ORIGINS=https://yourdomain.com
```

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

**Chetan Biranje**
- GitHub: [@ChetanBiranje](https://github.com/ChetanBiranje)

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This is a reference implementation. Always conduct security audits before production deployment.

## 📚 Resources

- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**⭐ If you find this helpful, please give it a star!**
