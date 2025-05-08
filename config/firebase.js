const admin = require('firebase-admin');
const path = require('path');

try {
  // Initialize using the secret file path from Render
  admin.initializeApp({
    credential: admin.credential.cert(
      require(process.env.GOOGLE_APPLICATION_CREDENTIALS)
    )
  });
  console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
  console.error('❌ Failed to initialize Firebase Admin:', error);
  process.exit(1);
}

const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

module.exports = { admin, db };