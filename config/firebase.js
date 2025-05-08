const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

// Debugging: Log environment variables
console.log('Checking GOOGLE_APPLICATION_CREDENTIALS:', process.env.GOOGLE_APPLICATION_CREDENTIALS);

try {
  // Method 1: Direct JSON parsing (recommended for Render)
  const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('✅ Firebase Admin initialized from environment variable');

} catch (envError) {
  console.log('Environment variable method failed, trying secret file...');
  
  try {
    // Method 2: Fallback to secret file path
    const configPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || path.join(__dirname, '../firebase-service-account.json');
    const serviceAccount = require(configPath);
    
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('✅ Firebase Admin initialized from secret file');
  } catch (fileError) {
    console.error('❌ Both initialization methods failed');
    console.error('Environment error:', envError);
    console.error('File error:', fileError);
    process.exit(1);
  }
}

const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

module.exports = { admin, db };