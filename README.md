# 🔒 Secure Node.js REST API

[![Node.js](https://img.shields.io/badge/Node.js-16%2B-green.svg)](https://nodejs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-4.4%2B-green.svg)](https://www.mongodb.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-A%2B-brightgreen.svg)](#security-features)

Complete **production-ready** secure REST API built with Node.js, Express, and MongoDB. All enterprise-grade security features in a single file for easy deployment and understanding.

**⭐ Star this repo if you find it helpful!**

---

## 🌟 Features

### 🛡️ Security Features

- ✅ **JWT Authentication** - Secure access & refresh token mechanism
- ✅ **Password Hashing** - bcrypt with 12 salt rounds
- ✅ **Rate Limiting** - Prevent brute force attacks (100 req/15min)
- ✅ **Account Lockout** - Auto-lock after 5 failed login attempts (2 hours)
- ✅ **Helmet Protection** - 11 security headers (XSS, CSP, HSTS, etc.)
- ✅ **CORS Configuration** - Cross-Origin Resource Sharing protection
- ✅ **NoSQL Injection Prevention** - MongoDB query sanitization
- ✅ **XSS Protection** - Cross-Site Scripting prevention
- ✅ **HPP Protection** - HTTP Parameter Pollution prevention
- ✅ **CSRF Protection** - Cross-Site Request Forgery tokens
- ✅ **Request Size Limiting** - 10kb body limit
- ✅ **Input Validation** - Comprehensive validation with express-validator
- ✅ **Role-Based Access Control** - User/Admin/Moderator roles

### 🚀 Core Features

- ✅ User Management (Registration, Login, CRUD)
- ✅ JWT Token System (Access + Refresh)
- ✅ Product Management (Complete CRUD)
- ✅ Pagination Support
- ✅ Error Handling
- ✅ Request Logging (Winston + Morgan)
- ✅ Response Compression
- ✅ Graceful Shutdown

---

## ⚡ Quick Start

### Prerequisites

- **Node.js** >= 16.0.0
- **MongoDB** >= 4.4
- **npm** >= 8.0.0

### 3-Step Setup

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env

# 3. Start the API
node secure-nodejs-api.js
```

**🎉 Done!** API running at `http://localhost:3000`

---

## 📚 API Endpoints

### Authentication
- `POST /api/auth/register` - Register user
- `POST /api/auth/login` - Login
- `POST /api/auth/refresh` - Refresh token
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout

### Users
- `GET /api/users` - Get all users (Admin)
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (Admin)

### Products
- `POST /api/products` - Create product
- `GET /api/products` - Get all products
- `GET /api/products/:id` - Get product by ID
- `PUT /api/products/:id` - Update product
- `DELETE /api/products/:id` - Delete product

---

## 🧪 Testing

### Manual Testing

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### Automated Testing

```bash
npm install axios
node test-api.js
```

---

## 🚀 Deployment

### Docker

```bash
docker-compose up -d
```

### Heroku

```bash
heroku create your-api-name
git push heroku main
```

### Production Environment

```env
NODE_ENV=production
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/db
JWT_SECRET=<strong-random-secret>
```

---

## 🔐 Security Implementation

### Password Requirements
- Minimum 8 characters
- 1 uppercase, 1 lowercase
- 1 number, 1 special character

### JWT Tokens
- Access Token: 24 hours
- Refresh Token: 7 days

### Rate Limiting
- General: 100 req/15min
- Auth: 5 req/15min
- Lockout: 5 failed attempts = 2 hours

---

## 📁 Project Structure

```
secure-nodejs-api/
├── secure-nodejs-api.js      # Main API (all code!)
├── package.json               # Dependencies
├── .env.example              # Environment template
├── test-api.js               # Test script
├── Postman-Collection.json   # Postman collection
├── Dockerfile                # Docker config
├── docker-compose.yml        # Docker Compose
└── README.md                 # Documentation
```

---

## 👨‍💻 Author

**Chetan Biranje**
- GitHub: [@ChetanBiranje](https://github.com/ChetanBiranje)

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file

---

## 🙏 Acknowledgments

- Express.js
- MongoDB & Mongoose
- JWT, Helmet, bcrypt
- Winston Logger

---

**Made with ❤️ for the developer community**

**⭐ Star if helpful!**
