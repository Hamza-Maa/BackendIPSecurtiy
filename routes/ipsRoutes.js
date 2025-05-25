const express = require("express");
const { db } = require("../config/firebase");
const ipsService = require("../services/ipsService");
const router = express.Router();

// Access ipStore from server.js for synchronization
const { ipStore } = require("../server");


// Block an IP address
router.post("/block", async (req, res) => {
    const { ip, reason, duration } = req.body;
    
    if (!ip || !reason) {
        console.error("Missing ip or reason in /block request");
        return res.status(400).json({ error: "IP and reason are required" });
    }

    try {
        const success = await ipsService.blockIP(ip, reason, duration);
        if (success) {
            // Update in-memory store
            ipStore.blockedIPs[ip] = Date.now() + (duration || ipsService.blockDuration);
            console.log(`Successfully blocked IP ${ip}`);
            res.status(200).json({
                message: `✅ IP ${ip} blocked`,
                reason,
                duration: duration || ipsService.blockDuration
            });
        } else {
            res.status(400).json({ error: `IP ${ip} is already blocked or invalid` });
        }
    } catch (error) {
        console.error("Failed to block IP:", ip, error);
        res.status(500).json({ error: "Error blocking IP", details: error.message });
    }
});

// Block by user ID
router.post("/block-user", async (req, res) => {
    const { uid, reason, duration } = req.body;
    
    if (!uid || !reason) {
        console.error("Missing uid or reason in /block-user request");
        return res.status(400).json({ error: "User ID and reason are required" });
    }

    try {
        const success = await ipsService.blockUser(uid, reason, duration);
        if (success) {
            // Update in-memory store
            ipStore.blockedUsers[uid] = Date.now() + (duration || ipsService.blockDuration);
            const userDoc = await db.collection('users_ips').doc(uid).get();
            if (userDoc.exists) {
                const userData = userDoc.data();
                ipStore.users[uid] = {
                    ...ipStore.users[uid],
                    ip: userData.ip,
                    lastActive: userData.lastActive?.toDate() || new Date(),
                    userAgent: userData.userAgent || 'unknown',
                    blocked: true,
                    blockReason: reason,
                    blockUntil: new Date(Date.now() + (duration || ipsService.blockDuration)).getTime()
                };
            }
            console.log(`Successfully blocked user ${uid}`);
            res.status(200).json({
                message: `✅ User ${uid} blocked`,
                reason,
                duration: duration || ipsService.blockDuration
            });
        } else {
            res.status(400).json({ error: `User ${uid} is already blocked or not found` });
        }
    } catch (error) {
        console.error("Failed to block user:", uid, error);
        res.status(500).json({ error: "Error blocking user", details: error.message });
    }
});

// Unblock an IP address
router.delete("/unblock", async (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        console.error("Missing ip in /unblock request");
        return res.status(400).json({ error: "IP is required" });
    }

    try {
        const success = await ipsService.unblockIP(ip);
        if (success) {
            delete ipStore.blockedIPs[ip];
            console.log(`Successfully unblocked IP ${ip}`);
            res.status(200).json({ message: `✅ IP ${ip} unblocked` });
        } else {
            res.status(400).json({ error: `IP ${ip} is not blocked` });
        }
    } catch (error) {
        console.error("Failed to unblock IP:", ip, error);
        res.status(500).json({ error: "Error unblocking IP", details: error.message });
    }
});

// Get list of blocked IPs
router.get("/blocked", async (req, res) => {
    try {
        const blockedIPs = await ipsService.getBlockedIPs();
        res.status(200).json(blockedIPs);
    } catch (error) {
        console.error("Failed to get blocked IPs:", error);
        res.status(500).json({ error: "Error getting blocked IPs", details: error.message });
    }
});

// Get suspicious activity logs
router.get("/suspicious", async (req, res) => {
    try {
        const options = {
            limit: parseInt(req.query.limit) || 100,
            ip: req.query.ip
        };

        const activity = await ipsService.getSuspiciousActivity(options);
        res.status(200).json(activity);
    } catch (error) {
        console.error("Failed to get suspicious activity:", error);
        res.status(500).json({ error: "Error getting suspicious activity", details: error.message });
    }
});

// Force cleanup of expired blocks
router.post("/cleanup", async (req, res) => {
    try {
        const cleanedCount = await ipsService.cleanupExpiredBlocks();
        console.log(`Cleaned ${cleanedCount} expired blocks`);
        res.status(200).json({
            message: "✅ Cleanup completed",
            cleanedCount
        });
    } catch (error) {
        console.error("Failed to cleanup expired blocks:", error);
        res.status(500).json({ error: "Error cleaning up expired blocks", details: error.message });
    }
});

// Get IPS statistics
router.get("/stats", async (req, res) => {
    try {
        const [blockedIPs, suspiciousActivity] = await Promise.all([
            ipsService.getBlockedIPs(),
            ipsService.getSuspiciousActivity({ limit: 1000 })
        ]);

        // Calculate statistics
        const stats = {
            activeBlocks: blockedIPs.length,
            suspiciousActivities: suspiciousActivity.length,
            byCountry: {},
            recentBlocks: blockedIPs.slice(0, 10),
            recentSuspiciousActivity: suspiciousActivity.slice(0, 10)
        };

        // Group blocked IPs by country
        blockedIPs.forEach(block => {
            if (block.geo && block.geo.country) {
                stats.byCountry[block.geo.country] = (stats.byCountry[block.geo.country] || 0) + 1;
            }
        });

        res.status(200).json(stats);
    } catch (error) {
        console.error("Failed to get IPS statistics:", error);
        res.status(500).json({ error: "Error getting IPS statistics", details: error.message });
    }
});

module.exports = router;