/**
 * IP Security Service
 * Handles IP and user blocking, rate limiting, and traffic analysis
 */
const { admin, db } = require('../config/firebase');
const fs = require('fs').promises;
const path = require('path');
const geoip = require('geoip-lite');
const ipConfig = require('../config/ipConfig');
const fileUtils = require('../utils/fileUtils');
const ipsStore = require('./ipsStore');

class IPSService {
    constructor() {
        // Initialize rate limiting and suspicious IPs tracking
        this.rateLimit = new Map();
        this.suspiciousIPs = new Map();
        
        // Set the block duration from config
        this.blockDuration = ipConfig.time.blockDuration;
        
        // Set paths
        this.blacklistPath = ipConfig.paths.blacklistPath;
        this.whitelistPath = ipConfig.paths.whitelistPath;
        
        // Initialize the IP store for in-memory tracking
        this.ipStore = ipsStore;
        
        // Ensure required directories and files exist
        this.initializeFiles();
    }

    /**
     * Initialize required files and directories
     */
    async initializeFiles() {
        try {
            const dataDir = path.dirname(this.blacklistPath);
            await fileUtils.ensureDirectoryExists(dataDir);
            await fileUtils.ensureFileExists(this.blacklistPath, '# IP Blacklist Rules\n');
            await fileUtils.ensureFileExists(this.whitelistPath, '# Whitelisted IPs\n');
        } catch (error) {
            console.error('❌ Error initializing files:', error);
        }
    }

    /**
     * Check if an IP is blocked
     * @param {string} ip - IP address to check
     * @returns {Promise<boolean>} - Whether the IP is blocked
     */
    async isIPBlocked(ip) {
        try {
            if (ip === '::1' || ip === '127.0.0.1') return false;

            // Check in-memory store first for performance
            if (this.ipStore.isIPBlocked(ip)) return true;

            const snapshot = await db.collection('ips_blocklist')
                .where('ip', '==', ip)
                .where('active', '==', true)
                .where('expiresAt', '>', new Date())
                .limit(1)
                .get();
            
            const isBlocked = !snapshot.empty;
            
            // Update in-memory store if blocked
            if (isBlocked && !snapshot.empty) {
                const doc = snapshot.docs[0];
                this.ipStore.setBlockedIP(ip, doc.data().expiresAt.toDate());
            }
            
            return isBlocked;
        } catch (error) {
            console.error(`❌ Error checking if IP ${ip} is blocked:`, error);
            return false;
        }
    }

    /**
     * Check if a user is blocked
     * @param {string} uid - User ID to check
     * @returns {Promise<boolean>} - Whether the user is blocked
     */
    async isUserBlocked(uid) {
        try {
            // Check in-memory store first for performance
            if (this.ipStore.isUserBlocked(uid)) return true;

            const userDoc = await db.collection('users_ips').doc(uid).get();
            if (!userDoc.exists) return false;
            
            const userData = userDoc.data();
            if (userData.blocked && userData.blockUntil) {
                const blockUntil = userData.blockUntil.toDate();
                if (blockUntil > new Date()) {
                    // Update in-memory store
                    this.ipStore.setBlockedUser(uid, blockUntil);
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

    /**
     * Block an IP address
     * @param {string} ip - IP address to block
     * @param {string} reason - Reason for blocking
     * @param {number} duration - Duration of block in milliseconds
     * @returns {Promise<boolean>} - Success status
     */
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

            // Add to database
            await db.collection('ips_blocklist').add({
                ip,
                reason,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                expiresAt,
                geo: geo || null,
                active: true
            });

            // Update in-memory store
            this.ipStore.setBlockedIP(ip, expiresAt);

            // Try to update blacklist file if it exists
            try {
                const rule = `drop ip ${ip} any -> any any (msg:"${reason}"; sid:${Date.now()}; rev:1;)\n`;
                const blacklistContent = await fileUtils.safeReadFile(this.blacklistPath);
                await fileUtils.safeWriteFile(this.blacklistPath, blacklistContent + rule);
            } catch (fileError) {
                console.warn(`⚠️ Could not update blacklist file: ${fileError.message}`);
            }

            console.log(`✅ Successfully blocked IP: ${ip}`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to block IP ${ip}:`, error);
            throw error;
        }
    }

    /**
     * Block a user
     * @param {string} uid - User ID to block
     * @param {string} reason - Reason for blocking
     * @param {number} duration - Duration of block in milliseconds
     * @returns {Promise<boolean>} - Success status
     */
    async blockUser(uid, reason, duration = this.blockDuration) {
        try {
            if (await this.isUserBlocked(uid)) {
                console.log(`ℹ️ User ${uid} is already blocked`);
                return false;
            }

            const expiresAt = new Date(Date.now() + duration);

            // Update in database
            await db.collection('users_ips').doc(uid).update({
                blocked: true,
                blockReason: reason,
                blockUntil: expiresAt,
                blockedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            // Update in-memory store
            this.ipStore.setBlockedUser(uid, expiresAt);

            // Also block the user's IP if available
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

    /**
     * Unblock an IP address
     * @param {string} ip - IP address to unblock
     * @returns {Promise<boolean>} - Success status
     */
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
            
            // Update in-memory store
            this.ipStore.unblockIP(ip);
            
            // Try to update blacklist file if it exists
            try {
                const blacklistContent = await fileUtils.safeReadFile(this.blacklistPath);
                const updatedContent = blacklistContent.replace(new RegExp(`drop ip ${ip} .*?\\n`, 'g'), '');
                await fileUtils.safeWriteFile(this.blacklistPath, updatedContent);
            } catch (fileError) {
                console.warn(`⚠️ Could not update blacklist file: ${fileError.message}`);
            }
            
            return true;
        } catch (error) {
            console.error(`❌ Error unblocking IP ${ip}:`, error);
            throw error;
        }
    }

    /**
     * Unblock a user
     * @param {string} uid - User ID to unblock
     * @returns {Promise<boolean>} - Success status
     */
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

            // Update in-memory store
            this.ipStore.unblockUser(uid);

            // Unblock the user's IP if it was blocked because of this user
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

    /**
     * Get all currently blocked IPs
     * @returns {Promise<Array>} - List of blocked IPs
     */
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

    /**
     * Get all currently blocked users
     * @returns {Promise<Array>} - List of blocked users
     */
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

    /**
     * Check if a request from an IP exceeds rate limit
     * @param {string} ip - IP address
     * @param {number} threshold - Request threshold
     * @param {number} timeWindow - Time window in milliseconds
     * @returns {Promise<boolean>} - Whether the request is allowed
     */
    async checkRateLimit(ip, threshold = ipConfig.time.rateLimit.threshold, timeWindow = ipConfig.time.rateLimit.window) {
        const now = Date.now();
        const ipData = this.ipStore.getRateLimitData(ip) || { count: 0, firstRequest: now };

        // Reset counter if outside time window
        if (now - ipData.firstRequest > timeWindow) {
            ipData.count = 0;
            ipData.firstRequest = now;
        }

        ipData.count++;
        this.ipStore.updateRateLimit(ip, ipData.count, ipData.firstRequest);

        // Check if rate limit exceeded
        if (ipData.count > threshold) {
            await this.blockIP(ip, 'Rate limit exceeded');
            return false;
        }

        return true;
    }

    /**
     * Analyze traffic for suspicious patterns
     * @param {string} ip - IP address
     * @param {Object} requestData - Request data to analyze
     * @returns {Promise<boolean>} - Whether the request is allowed
     */
    async analyzeTraffic(ip, requestData) {
        try {
            if (await this.isIPBlocked(ip)) {
                return false;
            }

            const suspicious = this.detectSuspiciousActivity(requestData);
            
            if (suspicious) {
                const currentCount = this.ipStore.recordSuspiciousActivity(ip);

                if (currentCount >= ipConfig.detection.suspiciousThreshold) {
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

    /**
     * Detect suspicious patterns in request data
     * @param {Object} requestData - Request data to analyze
     * @returns {boolean} - Whether suspicious patterns were detected
     */
    detectSuspiciousActivity(requestData) {
        const requestString = JSON.stringify(requestData).toLowerCase();
        return ipConfig.detection.patterns.some(pattern => pattern.test(requestString));
    }

    /**
     * Get suspicious activity logs
     * @param {Object} options - Query options
     * @returns {Promise<Array>} - Suspicious activity logs
     */
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

    /**
     * Clean up expired blocks
     * @returns {Promise<number>} - Number of blocks cleaned up
     */
    async cleanupExpiredBlocks() {
        try {
            const now = new Date();
            let cleanedCount = 0;

            // Clean expired IP blocks in database
            const ipSnapshot = await db.collection('ips_blocklist')
                .where('active', '==', true)
                .where('expiresAt', '<=', now)
                .get();

            if (!ipSnapshot.empty) {
                const ipBatch = db.batch();
                ipSnapshot.forEach(doc => {
                    ipBatch.update(doc.ref, { 
                        active: false,
                        unblocked: admin.firestore.FieldValue.serverTimestamp()
                    });
                    cleanedCount++;
                });
                
                await ipBatch.commit();
                
                // Update blacklist file if it exists
                try {
                    let currentRules = await fileUtils.safeReadFile(this.blacklistPath);
                    let updatedRules = currentRules;
                    
                    ipSnapshot.forEach(doc => {
                        const ip = doc.data().ip;
                        const regex = new RegExp(`drop ip ${ip} .*?\\n`, 'g');
                        updatedRules = updatedRules.replace(regex, '');
                    });

                    if (updatedRules !== currentRules) {
                        await fileUtils.safeWriteFile(this.blacklistPath, updatedRules);
                    }
                } catch (fileError) {
                    console.warn(`⚠️ Could not update blacklist file: ${fileError.message}`);
                    // Continue execution even if file update fails
                }
            }

            // Clean expired user blocks in database
            const userSnapshot = await db.collection('users_ips')
                .where('blocked', '==', true)
                .where('blockUntil', '<=', now)
                .get();

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

                await userBatch.commit();
            }

            // Clean in-memory stores
            const memoryCleaned = this.ipStore.cleanupExpiredMemoryStores();
            cleanedCount += memoryCleaned;

            console.log(`🧹 Cleaned ${cleanedCount} expired blocks`);
            return cleanedCount;
        } catch (error) {
            console.error('❌ Error cleaning up expired blocks:', error);
            throw new Error('Failed to clean up expired blocks');
        }
    }
}

module.exports = new IPSService();