// services/ipsService.js
const { admin, db } = require('../config/firebase');
const fs = require('fs').promises;
const path = require('path');
const geoip = require('geoip-lite');

class IPSService {
    constructor() {
        this.rateLimit = new Map();
        this.suspiciousIPs = new Map();
        this.blockDuration = 3600000; // 1 hour in milliseconds
                // Add these properties
        this.ipStore = {
            users: {},
            rateLimits: {},
            blockedIPs: {},
            blockedUsers: {}
        };
        
        this.blacklistPath = path.join(__dirname, 'blacklist.rules'); // or your actual path
    }

    async isIPBlocked(ip) {
        try {
            if (ip === '::1' || ip === '127.0.0.1') return false;

            const snapshot = await db.collection('ips_blocklist')
                .where('ip', '==', ip)
                .where('active', '==', true)
                .where('expiresAt', '>', new Date())
                .limit(1)
                .get();
            
            return !snapshot.empty;
        } catch (error) {
            console.error(`❌ Error checking if IP ${ip} is blocked:`, error);
            return false;
        }
    }

    async isUserBlocked(uid) {
        try {
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
        } catch (error) {
            console.error(`❌ Error checking if user ${uid} is blocked:`, error);
            return false;
        }
    }

    async blockIP(ip, reason, duration = this.blockDuration) {
        try {
            if (ip === '::1' || ip === '127.0.0.1') {
                console.warn(`⚠️ Skipping block for localhost IP: ${ip}`);
                return false;
            }

            if (await this.isIPBlocked(ip)) {
                console.log(`ℹ️ IP ${ip} is already blocked`);
                return false;
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

            console.log(`✅ Successfully blocked IP: ${ip}`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to block IP ${ip}:`, error);
            throw error;
        }
    }

    async blockUser(uid, reason, duration = this.blockDuration) {
        try {
            if (await this.isUserBlocked(uid)) {
                console.log(`ℹ️ User ${uid} is already blocked`);
                return false;
            }

            const expiresAt = new Date(Date.now() + duration);

            await db.collection('users_ips').doc(uid).update({
                blocked: true,
                blockReason: reason,
                blockUntil: expiresAt,
                blockedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            const userDoc = await db.collection('users_ips').doc(uid).get();
            if (userDoc.exists && userDoc.data().ip) {
                await this.blockIP(userDoc.data().ip, `User ${uid} blocked: ${reason}`, duration);
            }

            console.log(`✅ Successfully blocked user: ${uid}`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to block user ${uid}:`, error);
            throw error;
        }
    }

    async unblockIP(ip) {
        try {
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
        } catch (error) {
            console.error(`❌ Error unblocking IP ${ip}:`, error);
            throw error;
        }
    }

    async unblockUser(uid) {
        try {
            const userDoc = await db.collection('users_ips').doc(uid).get();
            if (!userDoc.exists) return false;

            await db.collection('users_ips').doc(uid).update({
                blocked: false,
                blockReason: null,
                blockUntil: null,
                unblocked: admin.firestore.FieldValue.serverTimestamp()
            });

            const userData = userDoc.data();
            if (userData.ip) {
                const ipBlocks = await db.collection('ips_blocklist')
                    .where('ip', '==', userData.ip)
                    .where('reason', '==', `User ${uid} blocked`)
                    .where('active', '==', true)
                    .get();

                if (!ipBlocks.empty) {
                    await this.unblockIP(userData.ip);
                }
            }

            console.log(`✅ Successfully unblocked user: ${uid}`);
            return true;
        } catch (error) {
            console.error(`❌ Error unblocking user ${uid}:`, error);
            throw error;
        }
    }

    async getBlockedIPs() {
        try {
            const snapshot = await db.collection('ips_blocklist')
                .where('active', '==', true)
                .get();

            return snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data(),
                expiresAt: doc.data().expiresAt.toDate()
            }));
        } catch (error) {
            console.error('❌ Error getting blocked IPs:', error);
            throw new Error('Failed to retrieve blocked IPs');
        }
    }

    async getBlockedUsers() {
        try {
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
        } catch (error) {
            console.error('❌ Error getting blocked users:', error);
            throw new Error('Failed to retrieve blocked users');
        }
    }

    async checkRateLimit(ip, threshold = 100, timeWindow = 60000) {
        const now = Date.now();
        const ipData = this.rateLimit.get(ip) || { count: 0, firstRequest: now };

        // Reset counter if outside time window
        if (now - ipData.firstRequest > timeWindow) {
            ipData.count = 0;
            ipData.firstRequest = now;
        }

        ipData.count++;
        this.rateLimit.set(ip, ipData);

        // Check if rate limit exceeded
        if (ipData.count > threshold) {
            await this.blockIP(ip, 'Rate limit exceeded');
            return false;
        }

        return true;
    }

    async analyzeTraffic(ip, requestData) {
        try {
            if (await this.isIPBlocked(ip)) {
                return false;
            }

            const suspicious = this.detectSuspiciousActivity(requestData);
            
            if (suspicious) {
                const currentCount = (this.suspiciousIPs.get(ip) || 0) + 1;
                this.suspiciousIPs.set(ip, currentCount);

                if (currentCount >= 5) {
                    await this.blockIP(ip, 'Multiple suspicious activities detected');
                    return false;
                }

                await db.collection('ips_suspicious_activity').add({
                    ip,
                    timestamp: admin.firestore.FieldValue.serverTimestamp(),
                    requestData,
                    reason: 'Suspicious pattern detected'
                });
            }

            return !suspicious;
        } catch (error) {
            console.error('❌ Error analyzing traffic:', error);
            throw new Error('Traffic analysis failed');
        }
    }

    detectSuspiciousActivity(requestData) {
        const suspiciousPatterns = [
            /'.*OR.*['";]/i,          // SQL Injection
            /UNION.*SELECT/i,          // SQL Injection
            /<script.*>/i,             // XSS
            /javascript:/i,            // XSS
            /\.\.\//,                  // Directory traversal
            /;\s*(?:cmd|exec)/i,       // Command injection
            /(?:include|require)/i,    // File inclusion
            /(?:nikto|sqlmap)/i        // Security scanners
        ];

        const requestString = JSON.stringify(requestData).toLowerCase();
        return suspiciousPatterns.some(pattern => pattern.test(requestString));
    }

    async getSuspiciousActivity(options = {}) {
        try {
            let query = db.collection('ips_suspicious_activity')
                .orderBy('timestamp', 'desc');

            if (options.limit) {
                query = query.limit(options.limit);
            }

            if (options.ip) {
                query = query.where('ip', '==', options.ip);
            }

            const snapshot = await query.get();
            return snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data(),
                timestamp: doc.data().timestamp.toDate()
            }));
        } catch (error) {
            console.error('❌ Error getting suspicious activity:', error);
            throw new Error('Failed to retrieve suspicious activity');
        }
    }

    async cleanupExpiredBlocks() {
    try {
        const now = new Date();
        let cleanedCount = 0;
        console.log('⏳ Starting cleanup of expired blocks...');

        // Clean expired IP blocks
        const ipQuery = db.collection('ips_blocklist')
            .where('active', '==', true)
            .where('expiresAt', '<=', now);

        const ipSnapshot = await ipQuery.get();
        console.log(`🔍 Found ${ipSnapshot.size} expired IP blocks to clean`);

        if (!ipSnapshot.empty) {
            const ipBatch = db.batch();
            ipSnapshot.forEach(doc => {
                ipBatch.update(doc.ref, { 
                    active: false,
                    unblocked: admin.firestore.FieldValue.serverTimestamp()
                });
                cleanedCount++;
            });

            try {
                await ipBatch.commit();
                console.log('✅ Successfully cleaned expired IP blocks');
            } catch (batchError) {
                console.error('❌ Failed to commit IP batch update:', batchError);
                throw batchError;
            }

            // Handle blacklist rules if needed
            if (this.blacklistPath) {
                try {
                    if (await fs.access(this.blacklistPath).then(() => true).catch(() => false)) {
                        let currentRules = await fs.readFile(this.blacklistPath, 'utf-8');
                        let updatedRules = currentRules;
                        
                        ipSnapshot.forEach(doc => {
                            const ip = doc.data().ip;
                            updatedRules = updatedRules.replace(new RegExp(`drop ip ${ip} .*?\\n`, 'g'), '');
                        });

                        if (updatedRules !== currentRules) {
                            await fs.writeFile(this.blacklistPath, updatedRules);
                            console.log('📝 Updated blacklist rules file');
                        }
                    }
                } catch (fileError) {
                    console.warn('⚠️ Could not update blacklist rules:', fileError);
                }
            }
        }

        // Clean expired user blocks
        const userQuery = db.collection('users_ips')
            .where('blocked', '==', true)
            .where('blockUntil', '<=', now);

        const userSnapshot = await userQuery.get();
        console.log(`🔍 Found ${userSnapshot.size} expired user blocks to clean`);

        if (!userSnapshot.empty) {
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

            try {
                await userBatch.commit();
                console.log('✅ Successfully cleaned expired user blocks');
            } catch (batchError) {
                console.error('❌ Failed to commit user batch update:', batchError);
                throw batchError;
            }
        }

        // Clean in-memory stores
        const initialIPCount = Object.keys(this.ipStore.blockedIPs).length;
        const initialUserCount = Object.keys(this.ipStore.blockedUsers).length;
        
        Object.keys(this.ipStore.blockedIPs).forEach(ip => {
            if (this.ipStore.blockedIPs[ip] <= now) {
                delete this.ipStore.blockedIPs[ip];
            }
        });

        Object.keys(this.ipStore.blockedUsers).forEach(uid => {
            if (this.ipStore.blockedUsers[uid] <= now) {
                delete this.ipStore.blockedUsers[uid];
                if (this.ipStore.users[uid]) {
                    this.ipStore.users[uid].blocked = false;
                }
            }
        });

        console.log(`🧹 Cleaned ${cleanedCount} expired blocks (${initialIPCount - Object.keys(this.ipStore.blockedIPs).length} IPs, ${initialUserCount - Object.keys(this.ipStore.blockedUsers).length} users)`);
        return cleanedCount;
    } catch (error) {
        console.error('❌ Error cleaning up expired blocks:', error);
        throw new Error(`Failed to clean up expired blocks: ${error.message}`);
    }
}
}

module.exports = new IPSService();