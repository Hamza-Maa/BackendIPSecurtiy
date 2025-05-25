const ipStore = require('../config/ipStore');
const express = require("express");
const { db } = require("../config/firebase");
const ipsService = require("../services/ipsService");
const router = express.Router();

// Block an IP address
router.post("/block", async (req, res) => {
    const { ip, reason, duration } = req.body;
    
    if (!ip || !reason) {
        return res.status(400).send("IP and reason are required");
    }

    try {
        // Block in both systems
        await ipsService.blockIP(ip, reason, duration);
        
        // Also add to in-memory store
        const blockDuration = duration || ipsService.blockDuration;
        ipStore.blockedIPs[ip] = Date.now() + blockDuration;
        
        res.status(200).json({
            message: `✅ IP ${ip} blocked`,
            reason,
            duration: blockDuration
        });
    } catch (error) {
        console.error("Failed to block IP:", error);
        res.status(500).send("❌ Error blocking IP");
    }
});

// Block by user ID (using their stored IP)
router.post("/block-user", async (req, res) => {
    const { uid, reason, duration } = req.body;
    
    if (!uid || !reason) {
        return res.status(400).send("User ID and reason are required");
    }

    try {
        // Get user's IP from users_ips collection
        const userDoc = await db.collection('users_ips').doc(uid).get();
        if (!userDoc.exists) {
            return res.status(404).send("User IP not found");
        }
        
        const userIP = userDoc.data().ip;
        await ipsService.blockIP(userIP, reason, duration);
        
        res.status(200).json({
            message: `✅ User ${uid} (IP: ${userIP}) blocked`,
            reason,
            duration: duration || 'default'
        });
    } catch (error) {
        console.error("Failed to block user:", error);
        res.status(500).send("❌ Error blocking user");
    }
});

// Unblock an IP address
router.delete("/unblock", async (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        return res.status(400).send("IP is required");
    }

    try {
        await ipsService.unblockIP(ip);
        res.status(200).send(`✅ IP ${ip} unblocked`);
    } catch (error) {
        console.error("Failed to unblock IP:", error);
        res.status(500).send("❌ Error unblocking IP");
    }
});

// Get list of blocked IPs
router.get("/blocked", async (req, res) => {
    try {
        const blockedIPs = await ipsService.getBlockedIPs();
        res.status(200).json(blockedIPs);
    } catch (error) {
        console.error("Failed to get blocked IPs:", error);
        res.status(500).send("❌ Error getting blocked IPs");
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
        res.status(500).send("❌ Error getting suspicious activity");
    }
});

// Force cleanup of expired blocks
router.post("/cleanup", async (req, res) => {
    try {
        const cleanedCount = await ipsService.cleanupExpiredBlocks();
        res.status(200).json({
            message: "✅ Cleanup completed",
            cleanedCount
        });
    } catch (error) {
        console.error("Failed to cleanup expired blocks:", error);
        res.status(500).send("❌ Error cleaning up expired blocks");
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
        res.status(500).send("❌ Error getting IPS statistics");
    }
});

module.exports = router;