const admin = require('firebase-admin');

// Path where Render will place the secret file
const serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || '../firebase-service-account.json';

try {
  const serviceAccount = require(serviceAccountPath);
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
  console.error('❌ Failed to initialize Firebase Admin:', error);
  process.exit(1);
}

// Get Firestore instance
const db = admin.firestore();

// Optional: Firestore settings
db.settings({ ignoreUndefinedProperties: true });

module.exports = {
  admin,
  db
};