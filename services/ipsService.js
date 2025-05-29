const { admin, db } = require('../config/firebase');
const geoip = require('geoip-lite');

class IPSService {
    constructor() {
        this.blockDuration = 3600000; // 1 hour in milliseconds
    }

    async isIPBlocked(ip) {
        if (ip === '::1' || ip === '127.0.0.1') return false;

        const snapshot = await db.collection('ips_blocklist')
            .where('ip', '==', ip)
            .where('active', '==', true)
            .where('expiresAt', '>', new Date())
            .limit(1)
            .get();
        
        return !snapshot.empty;
    }

    async isUserBlocked(uid) {
        const userDoc = await db.collection('users_ips').doc(uid).get();
        if (!userDoc.exists) return false;
        
        const userData = userDoc.data();
        if (userData.blocked && userData.blockUntil) {
            const blockUntil = userData.blockUntil.toDate();
            if (blockUntil > new Date()) {
                return true;
            } else {
                await this.unblockUser(uid);
            }
        }
        return false;
    }

    async blockIP(ip, reason, duration = this.blockDuration) {
        if (ip === '::1' || ip === '127.0.0.1') {
            throw new Error("Cannot block localhost IP");
        }

        if (await this.isIPBlocked(ip)) {
            throw new Error("IP is already blocked");
        }

        const geo = geoip.lookup(ip);
        const expiresAt = new Date(Date.now() + duration);

        await db.collection('ips_blocklist').add({
            ip,
            reason,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt,
            geo: geo || null,
            active: true
        });

        return true;
    }

    async blockUser(uid, reason, duration = this.blockDuration) {
        if (await this.isUserBlocked(uid)) {
            throw new Error("User is already blocked");
        }

        const expiresAt = new Date(Date.now() + duration);

        await db.collection('users_ips').doc(uid).update({
            blocked: true,
            blockReason: reason,
            blockUntil: expiresAt,
            blockedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return true;
    }

    async unblockIP(ip) {
        const snapshot = await db.collection('ips_blocklist')
            .where('ip', '==', ip)
            .where('active', '==', true)
            .get();

        const batch = db.batch();
        snapshot.forEach(doc => {
            batch.update(doc.ref, { 
                active: false,
                unblocked: admin.firestore.FieldValue.serverTimestamp()
            });
        });
        
        await batch.commit();
        return true;
    }

    async unblockUser(uid) {
        await db.collection('users_ips').doc(uid).update({
            blocked: false,
            blockReason: null,
            blockUntil: null,
            unblocked: admin.firestore.FieldValue.serverTimestamp()
        });

        return true;
    }

    async getBlockedIPs() {
        const snapshot = await db.collection('ips_blocklist')
            .where('active', '==', true)
            .get();

        return snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            expiresAt: doc.data().expiresAt.toDate()
        }));
    }

    async getBlockedUsers() {
        const snapshot = await db.collection('users_ips')
            .where('blocked', '==', true)
            .get();

        return snapshot.docs.map(doc => ({
            id: doc.id,
            uid: doc.id,
            ...doc.data(),
            blockUntil: doc.data().blockUntil?.toDate(),
            blockedAt: doc.data().blockedAt?.toDate()
        }));
    }

    async cleanupExpiredBlocks() {
        const now = new Date();
        let cleanedCount = 0;

        // Clean IP blocks
        const ipQuery = db.collection('ips_blocklist')
            .where('active', '==', true)
            .where('expiresAt', '<=', now);

        const ipSnapshot = await ipQuery.get();
        const ipBatch = db.batch();
        ipSnapshot.forEach(doc => {
            ipBatch.update(doc.ref, { 
                active: false,
                unblocked: admin.firestore.FieldValue.serverTimestamp()
            });
            cleanedCount++;
        });
        await ipBatch.commit();

        // Clean user blocks
        const userQuery = db.collection('users_ips')
            .where('blocked', '==', true)
            .where('blockUntil', '<=', now);

        const userSnapshot = await userQuery.get();
        const userBatch = db.batch();
        userSnapshot.forEach(doc => {
            userBatch.update(doc.ref, { 
                blocked: false,
                blockReason: null,
                blockUntil: null,
                unblocked: admin.firestore.FieldValue.serverTimestamp()
            });
            cleanedCount++;
        });
        await userBatch.commit();

        return cleanedCount;
    }
}

module.exports = new IPSService();