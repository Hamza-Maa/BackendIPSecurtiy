const { admin, db } = require('../config/firebase');
const fs = require('fs').promises;
const path = require('path');
const geoip = require('geoip-lite');

class IPSService {
    constructor() {
        this.blacklistPath = path.join(__dirname, 'snort3/rules/blacklist.rules');
        this.rateLimit = new Map();
        this.suspiciousIPs = new Map();
        this.blockDuration = 3600000; // 1 hour in milliseconds
        
        this.initializeBlacklistFile().catch(err => {
            console.error('❌ Failed to initialize blacklist file:', err);
        });
    }

    async initializeBlacklistFile() {
        try {
            await fs.access(this.blacklistPath);
        } catch (error) {
            await fs.writeFile(this.blacklistPath, '# IPS Blacklist Rules\n', 'utf-8');
        }
    }

    async isIPBlocked(ip) {
        try {
            // Skip check for localhost (::1 or 127.0.0.1)
            if (ip === '::1' || ip === '127.0.0.1') {
                return false;
            }

            const snapshot = await db.collection('ips_blocklist')
                .where('ip', '==', ip)
                .where('active', '==', true)
                .where('expiresAt', '>', new Date())
                .limit(1)
                .get();
            
            return !snapshot.empty;
        } catch (error) {
            console.error(`❌ Error checking if IP ${ip} is blocked:`, error);
            // Return false to allow the operation to continue
            return false;
        }
    }

    async blockIP(ip, reason, duration = this.blockDuration) {
        try {
            // Add to in-memory store
            ipStore.blockedIPs[ip] = Date.now() + duration;
            // Skip blocking localhost
            if (ip === '::1' || ip === '127.0.0.1') {
                console.warn(`⚠️ Skipping block for localhost IP: ${ip}`);
                return false;
            }

            const isBlocked = await this.isIPBlocked(ip);
            if (isBlocked) {
                console.log(`ℹ️ IP ${ip} is already blocked`);
                return false;
            }

            const geo = geoip.lookup(ip);
            const blockRule = `drop ip ${ip} any -> any any (msg:"Blocked by IPS: ${reason}";)\n`;
            
            // Update Snort rules
            let currentRules = await fs.readFile(this.blacklistPath, 'utf-8');
            if (!currentRules.includes(blockRule)) {
                await fs.appendFile(this.blacklistPath, blockRule);
            }

            // Store in Firestore
            await db.collection('ips_blocklist').add({
                ip,
                reason,
                timestamp: new Date(),
                expiresAt: new Date(Date.now() + duration),
                geo: geo || null,
                active: true
            });

            // Clear tracking data
            this.rateLimit.delete(ip);
            this.suspiciousIPs.delete(ip);

            console.log(`✅ Successfully blocked IP: ${ip}`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to block IP ${ip}:`, error);
            throw new Error(`Blocking failed: ${error.message}`);
        }
    }

    /**
     * Unblock an IP address
     * @param {string} ip - IP address to unblock
     * @returns {Promise<boolean>} - True if unblocked successfully
     */
    async unblockIP(ip) {
        try {
            // Update Snort rules
            let blacklist = await fs.readFile(this.blacklistPath, 'utf-8');
            const updatedRules = blacklist.replace(new RegExp(`drop ip ${ip} .*?\\n`, 'g'), '');
            
            if (updatedRules !== blacklist) {
                await fs.writeFile(this.blacklistPath, updatedRules);
            }

            // Update Firestore
            const snapshot = await db.collection('ips_blocklist')
                .where('ip', '==', ip)
                .where('active', '==', true)
                .get();

            if (snapshot.empty) {
                return false;
            }

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
            throw new Error(`Failed to unblock IP: ${error.message}`);
        }
    }

    /**
     * Check rate limiting for an IP
     * @param {string} ip - IP address to check
     * @param {number} [threshold=100] - Max requests allowed
     * @param {number} [timeWindow=60000] - Time window in ms (default 1 minute)
     * @returns {Promise<boolean>} - True if within rate limit
     */
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

    /**
     * Analyze traffic for suspicious activity
     * @param {string} ip - Source IP address
     * @param {object} requestData - Request data to analyze
     * @returns {Promise<boolean>} - True if traffic is clean
     */
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

    /**
     * Detect suspicious patterns in request data
     * @param {object} requestData - Request data to check
     * @returns {boolean} - True if suspicious
     */
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

    /**
     * Get list of currently blocked IPs
     * @returns {Promise<Array>} - Array of blocked IPs
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
     * Get suspicious activity logs
     * @param {object} [options] - Filter options
     * @param {number} [options.limit=100] - Max records to return
     * @param {string} [options.ip] - Filter by IP address
     * @returns {Promise<Array>} - Array of suspicious activities
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
     * @returns {Promise<number>} - Number of blocks cleaned
     */
    async cleanupExpiredBlocks() {
        try {
            const now = new Date(); // Use JavaScript Date instead of Firestore Timestamp
            
            // Get all active blocks where expiresAt is in the past
            const snapshot = await db.collection('ips_blocklist')
                .where('active', '==', true)
                .get();
            
            let cleanedCount = 0;
            const batch = db.batch();

            snapshot.forEach(doc => {
                const data = doc.data();
                // Convert Firestore Timestamp to Date if needed
                const expiresAt = data.expiresAt.toDate ? data.expiresAt.toDate() : new Date(data.expiresAt);
                
                if (expiresAt <= now) {
                    batch.update(doc.ref, { 
                        active: false,
                        unblocked: admin.firestore.FieldValue.serverTimestamp()
                    });
                    cleanedCount++;
                }
            });

            if (cleanedCount > 0) {
                await batch.commit();
                
                // Also update Snort rules for the unblocked IPs
                const currentRules = await fs.readFile(this.blacklistPath, 'utf-8');
                const updatedRules = snapshot.docs
                    .filter(doc => {
                        const data = doc.data();
                        const expiresAt = data.expiresAt.toDate ? data.expiresAt.toDate() : new Date(data.expiresAt);
                        return expiresAt <= now;
                    })
                    .reduce((rules, doc) => {
                        const ip = doc.data().ip;
                        return rules.replace(new RegExp(`drop ip ${ip} .*?\\n`, 'g'), '');
                    }, currentRules);
                
                await fs.writeFile(this.blacklistPath, updatedRules);
            }

            return cleanedCount;
        } catch (error) {
            console.error('❌ Error cleaning up expired blocks:', error);
            throw new Error('Failed to clean up expired blocks');
        }
    }
}

module.exports = new IPSService();