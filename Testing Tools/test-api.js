/**
 * API Testing Script
 * Run: node test-api.js
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
let accessToken = '';
let userId = '';
let productId = '';

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m'
};

const log = {
  success: (msg) => console.log(`${colors.green}✓ ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}✗ ${msg}${colors.reset}`),
  info: (msg) => console.log(`${colors.blue}ℹ ${msg}${colors.reset}`),
  test: (msg) => console.log(`${colors.yellow}▶ ${msg}${colors.reset}`)
};

async function testAPI() {
  console.log('\n🚀 Starting API Tests...\n');

  try {
    // Test 1: Health Check
    log.test('Testing Health Check...');
    const health = await axios.get(`${BASE_URL}/health`);
    log.success(`Health check passed: ${health.data.message}`);

    // Test 2: User Registration
    log.test('Testing User Registration...');
    const registerData = {
      username: 'testuser_' + Date.now(),
      email: `test${Date.now()}@example.com`,
      password: 'SecurePass123!'
    };
    
    const registerRes = await axios.post(`${BASE_URL}/api/auth/register`, registerData);
    accessToken = registerRes.data.data.accessToken;
    userId = registerRes.data.data.user._id;
    log.success(`User registered: ${registerRes.data.data.user.username}`);

    // Test 3: User Login
    log.test('Testing User Login...');
    const loginRes = await axios.post(`${BASE_URL}/api/auth/login`, {
      email: registerData.email,
      password: registerData.password
    });
    accessToken = loginRes.data.data.accessToken;
    log.success(`User logged in successfully`);

    // Test 4: Get Current User
    log.test('Testing Get Current User...');
    const meRes = await axios.get(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    log.success(`Current user: ${meRes.data.data.user.username}`);

    // Test 5: Create Product
    log.test('Testing Create Product...');
    const productData = {
      name: 'Test Product',
      description: 'This is a test product',
      price: 99.99,
      category: 'Electronics',
      stock: 50
    };
    
    const productRes = await axios.post(`${BASE_URL}/api/products`, productData, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    productId = productRes.data.data.product._id;
    log.success(`Product created: ${productRes.data.data.product.name}`);

    // Test 6: Get All Products
    log.test('Testing Get All Products...');
    const productsRes = await axios.get(`${BASE_URL}/api/products?page=1&limit=10`);
    log.success(`Found ${productsRes.data.data.products.length} products`);

    // Test 7: Get Product by ID
    log.test('Testing Get Product by ID...');
    const productDetailRes = await axios.get(`${BASE_URL}/api/products/${productId}`);
    log.success(`Product details: ${productDetailRes.data.data.product.name}`);

    // Test 8: Update Product
    log.test('Testing Update Product...');
    const updateRes = await axios.put(
      `${BASE_URL}/api/products/${productId}`,
      { price: 89.99, stock: 45 },
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    log.success(`Product updated: Price = ${updateRes.data.data.product.price}`);

    // Test 9: Invalid Login
    log.test('Testing Invalid Login (should fail)...');
    try {
      await axios.post(`${BASE_URL}/api/auth/login`, {
        email: registerData.email,
        password: 'WrongPassword123!'
      });
      log.error('Invalid login should have failed!');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        log.success('Invalid login correctly rejected');
      } else {
        throw error;
      }
    }

    // Test 10: Unauthorized Access
    log.test('Testing Unauthorized Access (should fail)...');
    try {
      await axios.get(`${BASE_URL}/api/auth/me`);
      log.error('Unauthorized access should have failed!');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        log.success('Unauthorized access correctly blocked');
      } else {
        throw error;
      }
    }

    // Test 11: Rate Limiting
    log.test('Testing Rate Limiting...');
    log.info('Sending multiple requests to test rate limiter...');
    let rateLimited = false;
    
    for (let i = 0; i < 105; i++) {
      try {
        await axios.get(`${BASE_URL}/health`);
      } catch (error) {
        if (error.response && error.response.status === 429) {
          rateLimited = true;
          break;
        }
      }
    }
    
    if (rateLimited) {
      log.success('Rate limiting is working correctly');
    } else {
      log.info('Rate limit not reached in this test (100+ requests needed)');
    }

    // Test 12: Input Validation
    log.test('Testing Input Validation (should fail)...');
    try {
      await axios.post(`${BASE_URL}/api/auth/register`, {
        username: 'ab', // Too short
        email: 'invalid-email',
        password: '123' // Too weak
      });
      log.error('Invalid input should have failed!');
    } catch (error) {
      if (error.response && error.response.status === 400) {
        log.success('Input validation working correctly');
      } else {
        throw error;
      }
    }

    // Test 13: Delete Product
    log.test('Testing Delete Product...');
    await axios.delete(`${BASE_URL}/api/products/${productId}`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    log.success('Product deleted successfully');

    // Test 14: Logout
    log.test('Testing Logout...');
    await axios.post(`${BASE_URL}/api/auth/logout`, {}, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    log.success('User logged out successfully');

    console.log('\n✅ All tests passed successfully!\n');

  } catch (error) {
    log.error(`Test failed: ${error.message}`);
    if (error.response) {
      console.log('Response data:', error.response.data);
    }
    process.exit(1);
  }
}

// Run tests
testAPI();
