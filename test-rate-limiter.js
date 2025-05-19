const fetch = require('node-fetch');
const crypto = require('crypto');

const TARGET_URL = 'https://hackclub.maksimmalbasa.in.rs/api/register';
const REQUESTS = 200;         // Number of total requests to send
const DELAY_MS = 0;        // Delay between requests in milliseconds

function randomString(length) {
  return crypto.randomBytes(length).toString('hex').slice(0, length);
}

async function sendFakeRegisterRequest(i) {
  const username = `testuser_${i}_${randomString(4)}`;
  const email = `user${i}_${randomString(4)}@example.com`;
  const password = 'strongPassword123';

  const payload = {
    username,
    password,
    email
  };

  try {
    const response = await fetch(TARGET_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    console.log(`[${i}] Status: ${response.status} | Response:`, data);
    return { status: response.status, data };
  } catch (err) {
    console.error(`[${i}] Error sending request:`, err.message);
    return { status: 'error', error: err.message };
  }
}

async function runRateLimitTest() {
  console.log(`Starting rate limit test: ${REQUESTS} registrations, ${DELAY_MS}ms delay`);
  const results = [];
  
  // Send requests one by one
  for (let i = 0; i < REQUESTS; i++) {
    const result = await sendFakeRegisterRequest(i);
    results.push(result);
    
    // Wait between requests
    if (i < REQUESTS - 1) {
      await new Promise(resolve => setTimeout(resolve, DELAY_MS));
    }
  }
  
  // Count results by status
  const statusCounts = results.reduce((counts, result) => {
    const status = result.status;
    counts[status] = (counts[status] || 0) + 1;
    return counts;
  }, {});
  
  console.log('\nTest Results Summary:');
  console.log('---------------------');
  Object.entries(statusCounts).forEach(([status, count]) => {
    console.log(`Status ${status}: ${count} responses`);
  });
  
  // Check if rate limiting is working
  if (statusCounts['429'] > 0) {
    console.log('\n✅ RATE LIMITING IS WORKING! Detected 429 Too Many Requests responses.');
  } else {
    console.log('\n❌ RATE LIMITING MIGHT NOT BE WORKING. No 429 responses detected.');
  }
  
  console.log('\nTest complete.');
}

runRateLimitTest(); 