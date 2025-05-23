const express = require("express");
const bodyParser = require("body-parser");
const schedule = require('node-schedule');
const { admin, db } = require('./config/firebase');
const fs = require('fs');
const ipsRoutes = require('./routes/ipsRoutes');
const idsRoutes = require('./routes/idsRoutes');
require('dotenv').config(); 

// Configuration 
const API_KEY = process.env.API_KEY;
const PORT = process.env.PORT || 3002;

// In-memory storage for manual IP management
const ipStore = {
  users: {},       // { uid: { ip, lastActive } }
  rateLimits: {},  // { ip: { count, lastRequest } }
  blockedIPs: {}   // { ip: blockUntil }
};

// Manual IP Analysis Service
const manualIPService = {
  checkRateLimit: (ip) => {
    const now = Date.now();
    ipStore.rateLimits[ip] = ipStore.rateLimits[ip] || { count: 0, lastRequest: 0 };
    
    // Reset if last request was >1 minute ago
    if (now - ipStore.rateLimits[ip].lastRequest > 60000) {
      ipStore.rateLimits[ip] = { count: 1, lastRequest: now };
      return true;
    }
    
    // Allow max 10 requests per minute
    if (ipStore.rateLimits[ip].count++ < 10) {
      ipStore.rateLimits[ip].lastRequest = now;
      return true;
    }
    
    return false;
  },

  analyzeTraffic: (ip, requestData) => {
    const suspiciousPatterns = [
      /etc\/passwd/,
      /<script>/,
      /SELECT.*FROM/,
      /admin/,
      /\.\.\//
    ];
    
    const requestString = JSON.stringify(requestData).toLowerCase();
    return !suspiciousPatterns.some(pattern => pattern.test(requestString));
  },

  cleanupExpiredBlocks: () => {
    const now = Date.now();
    let cleaned = 0;
    
    Object.keys(ipStore.blockedIPs).forEach(ip => {
      if (ipStore.blockedIPs[ip] < now) {
        delete ipStore.blockedIPs[ip];
        cleaned++;
      }
    });
    
    return cleaned;
  }
};

// Initialize Express
const app = express();
// Add this line to trust proxy headers (like X-Forwarded-For)
app.set('trust proxy', true);  // <-- Add this line here
app.use(bodyParser.json());

// Helper function for token exchange
async function exchangeCustomTokenForIdToken(customToken) {
  const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=${API_KEY}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      token: customToken,
      returnSecureToken: true
    })
  });
  const data = await response.json();
  return data.idToken;
}

// ======================
// Authentication Routes
// ======================
app.post('/authenticate', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await admin.auth().getUserByEmail(email);
    
    // Improved IP detection (works behind proxies)
    const ip = req.headers['x-forwarded-for']?.split(',')[0] 
               || req.connection?.remoteAddress 
               || req.ip;
    
    // Store IP in Firestore
    await db.collection('users_ips').doc(user.uid).set({
      ip,
      lastActive: admin.firestore.FieldValue.serverTimestamp(),
      userAgent: req.headers['user-agent'],
      email: user.email,
      uid: user.uid
    }, { merge: true });
    
    // Keep in memory
    ipStore.users[user.uid] = { 
      ip, 
      lastActive: new Date(),
      userAgent: req.headers['user-agent']
    };
    
    // Create and exchange tokens
    const customToken = await admin.auth().createCustomToken(user.uid);
    const idToken = await exchangeCustomTokenForIdToken(customToken);
    
    res.json({ 
      token: idToken,
      ip,
      uid: user.uid 
    });
    
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(401).json({ error: "Authentication failed" });
  }
});

// ======================
// Middleware
// ======================
const manualAuth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) return res.status(401).send('Token required');
  
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = { 
      ...decoded, 
      ipData: ipStore.users[decoded.uid] || await db.collection('users_ips').doc(decoded.uid).get().then(doc => doc.data())
    };
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(403).send('Invalid token');
  }
};

// Apply security to all /api routes
app.use('/api', manualAuth, (req, res, next) => {
  const ip = req.ip;
  
  // Check rate limit
  if (!manualIPService.checkRateLimit(ip)) {
    return res.status(429).send('Too many requests');
  }
  
  // Analyze traffic
  if (!manualIPService.analyzeTraffic(ip, {
    method: req.method,
    path: req.path,
    headers: req.headers,
    body: req.body
  })) {
    ipStore.blockedIPs[ip] = Date.now() + 3600000;
    return res.status(403).send('Suspicious activity detected');
  }
  
  next();
});

// ======================
// Core API Routes
// ======================
app.get('/api/ids', (req, res) => {
  res.json({ 
    message: "IDS Data",
    yourIp: req.user.ipData.ip 
  });
});

app.get('/api/ips', (req, res) => {
  res.json({
    message: "IPS Data",
    currentUser: req.user.uid,
    storedIPs: ipStore.users
  });
});

// ======================
// Feature Routes
// ======================

// IPS Routes
app.use('/api/ips', manualAuth, ipsRoutes);
// IDS Routes
app.use('/api/ids', manualAuth, idsRoutes);

// ======================
// Background Jobs
// ======================
schedule.scheduleJob('0 * * * *', () => {
  const cleaned = manualIPService.cleanupExpiredBlocks();
  console.log(`🧹 Cleaned ${cleaned} expired IP blocks`);
  
  // Clean old rate limits
  Object.keys(ipStore.rateLimits).forEach(ip => {
    if (Date.now() - ipStore.rateLimits[ip].lastRequest > 86400000) {
      delete ipStore.rateLimits[ip];
    }
  });
});

// ======================
// Server Startup
// ======================
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('\n=== Authentication ===');
  console.log(`POST /authenticate - Authenticate user (body: {email, password})`);
  
  console.log('\n=== Core API ===');
  console.log('GET /api/ids - Basic IDS info');
  console.log('GET /api/ips - Basic IPS info');
  
  console.log('\n=== IPS Endpoints ===');
  console.log('POST /api/ips/block - Block an IP (body: {ip, reason, duration})');
  console.log('POST /api/ips/block-user - Block by user ID (body: {uid, reason, duration})');
  console.log('DELETE /api/ips/unblock - Unblock an IP (body: {ip})');
  console.log('GET /api/ips/blocked - Get list of blocked IPs');
  console.log('GET /api/ips/suspicious - Get suspicious activity (query: ?limit=100&ip=1.2.3.4)');
  console.log('POST /api/ips/cleanup - Force cleanup of expired blocks');
  console.log('GET /api/ips/stats - Get IPS statistics');
  
  console.log('\n=== IDS Endpoints ===');
  console.log('GET /api/ids/process_alerts - Process IDS alerts');
  console.log('GET /api/ids/alerts - Get alerts (query: ?limit=100&severity=0)');
  console.log('POST /api/ids/rules - Add custom IDS rule (body: {rule: "content"})');
  console.log('GET /api/ids/rules - Get all IDS rules');
  console.log('GET /api/ids/stats - Get alert statistics');
});