const http = require('http');

const data = JSON.stringify({
  email: 'test_auto@example.com',
  password: 'SecureTest@123'
});

const options = {
  hostname: 'localhost',
  port: 5000,
  path: '/api/v1/auth/register',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }
};

const req = http.request(options, (res) => {
  let responseBody = '';
  res.on('data', (chunk) => {
    responseBody += chunk;
  });
  res.on('end', () => {
    console.log(`Status Code: ${res.statusCode}`);
    console.log(`Response Body: ${responseBody}`);
  });
});

req.on('error', (error) => {
  console.error(`Error: ${error.message}`);
});

req.write(data);
req.end();
