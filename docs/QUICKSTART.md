# 🚀 QUICK START GUIDE - Secure Node.js API

## ⚡ 5-Minute Setup

### Method 1: Direct Run (Fastest)

```bash
# 1. Install dependencies
npm install

# 2. Create .env file
cp .env.example .env

# 3. Start MongoDB (in separate terminal)
mongod

# 4. Run the API
node secure-nodejs-api.js
```

**Done! 🎉** API running at `http://localhost:3000`

---

### Method 2: Docker (Recommended)

```bash
# 1. Build and run with Docker Compose
docker-compose up -d

# 2. Check if running
docker-compose ps
```

**Done! 🎉** API + MongoDB running together

---

## 🧪 Test the API

### Option 1: Use test script

```bash
# Install axios first
npm install axios

# Run tests
node test-api.js
```

### Option 2: Manual testing with cURL

```bash
# 1. Register a user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# 2. Login (copy the accessToken from response)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# 3. Get your profile (replace YOUR_TOKEN)
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN"

# 4. Create a product
curl -X POST http://localhost:3000/api/products \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Laptop",
    "description": "Gaming laptop",
    "price": 999.99,
    "category": "Electronics",
    "stock": 10
  }'

# 5. Get all products
curl -X GET http://localhost:3000/api/products
```

### Option 3: Postman

1. Import `Postman-Collection.json`
2. Set environment variable `baseUrl` = `http://localhost:3000`
3. Run "Register User" request
4. Token automatically saved
5. Test other endpoints

---

## 📁 File Structure

```
secure-nodejs-api/
├── secure-nodejs-api.js      # 🔥 Main API file (everything in one!)
├── package.json               # Dependencies
├── .env.example              # Environment template
├── test-api.js               # Testing script
├── Postman-Collection.json   # Postman collection
├── Dockerfile                # Docker build
├── docker-compose.yml        # Docker orchestration
└── SECURE-API-README.md      # Full documentation
```

---

## 🔐 Security Features (Already Included!)

✅ JWT Authentication (Access + Refresh tokens)  
✅ Password Hashing (bcrypt, 12 rounds)  
✅ Rate Limiting (100 req/15min)  
✅ Account Lockout (5 failed attempts)  
✅ Helmet Security Headers  
✅ CORS Protection  
✅ NoSQL Injection Prevention  
✅ XSS Protection  
✅ Input Validation  
✅ Role-Based Access Control  

---

## 🎯 Common Commands

```bash
# Development with auto-reload
npm run dev

# Production
npm start

# Run tests
npm test

# Check logs
tail -f combined.log

# Stop Docker
docker-compose down

# View Docker logs
docker-compose logs -f api
```

---

## 🐛 Troubleshooting

**MongoDB not connecting?**
```bash
# Make sure MongoDB is running
mongod

# Or use Docker
docker run -d -p 27017:27017 mongo
```

**Port 3000 already in use?**
```bash
# Change PORT in .env
PORT=3001

# Or kill the process
lsof -ti:3000 | xargs kill
```

**Dependencies not installing?**
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

---

## 📊 API Endpoints Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Register user |
| POST | `/api/auth/login` | No | Login |
| POST | `/api/auth/refresh` | No | Refresh token |
| GET | `/api/auth/me` | Yes | Current user |
| POST | `/api/auth/logout` | Yes | Logout |
| GET | `/api/users` | Admin | All users |
| GET | `/api/users/:id` | Yes | User by ID |
| PUT | `/api/users/:id` | Yes | Update user |
| DELETE | `/api/users/:id` | Admin | Delete user |
| POST | `/api/products` | Yes | Create product |
| GET | `/api/products` | No | All products |
| GET | `/api/products/:id` | No | Product by ID |
| PUT | `/api/products/:id` | Owner/Admin | Update product |
| DELETE | `/api/products/:id` | Owner/Admin | Delete product |

---

## 🎓 Next Steps

1. ✅ API running
2. 📖 Read full documentation: `SECURE-API-README.md`
3. 🔧 Customize for your needs
4. 🚀 Deploy to production
5. 📊 Monitor and scale

---

## 💡 Pro Tips

- Change `JWT_SECRET` in production
- Use MongoDB Atlas for cloud database
- Enable HTTPS in production
- Set up monitoring (PM2, New Relic)
- Regular security audits
- Keep dependencies updated

---

**Need help?** Check `SECURE-API-README.md` for detailed docs!

**Ready to deploy?** See deployment section in README!

---

Made with ❤️ by Chetan Biranje
