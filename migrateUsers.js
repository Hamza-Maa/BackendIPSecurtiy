const { admin, db } = require('./config/firebase'); // Adjust path as needed

async function migrateExistingUsers() {
  console.log('Starting migration...');
  const usersSnapshot = await db.collection('users_ips').get();
  
  // Firestore batches can only handle 500 operations at once
  const batchSize = 500;
  let processed = 0;
  let batch = db.batch();

  usersSnapshot.forEach(async (doc, index) => {
    const data = doc.data();
    if (data.blocked === undefined) {
      batch.update(doc.ref, {
        blocked: false,
        blockReason: null,
        blockUntil: null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      processed++;
    }

    // Commit and start new batch every 500 operations
    if (index > 0 && index % batchSize === 0) {
      await batch.commit();
      batch = db.batch();
      console.log(`Processed ${index} documents...`);
    }
  });

  // Commit final batch
  if (processed > 0) {
    await batch.commit();
    console.log(`✅ Migration completed. Updated ${processed} users.`);
  } else {
    console.log('✅ No users needed migration.');
  }
}

// Run with error handling
migrateExistingUsers()
  .catch(error => {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  })
  .then(() => process.exit(0));