const admin = require('firebase-admin');
const geoip = require('geoip-lite');
const express = require("express");
const { db } = require("../config/firebase");
const ipsService = require("../services/ipsService");
const router = express.Router();

// Block an IP address (persistent in Firestore only)
router.post("/block", async (req, res) => {
    const { ip, reason, duration } = req.body;
    
    if (!ip || !reason) {
        return res.status(400).send("IP and reason are required");
    }

    try {
        // First validate the IP
        if (ip === '::1' || ip === '127.0.0.1') {
            return res.status(400).send("Cannot block localhost IP");
        }

        // Calculate block duration (default to 1 hour)
        const blockDuration = duration ? parseInt(duration) : 3600000;
        const expiresAt = Date.now() + blockDuration;

        // Block in Firestore
        const geo = geoip.lookup(ip);
        await db.collection('ips_blocklist').add({
            ip,
            reason,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: new Date(expiresAt),
            geo: geo || null,
            active: true
        });
        
        res.status(200).json({
            message: `✅ IP ${ip} blocked successfully in Firestore`,
            reason,
            duration: blockDuration,
            expiresAt: new Date(expiresAt)
        });
    } catch (error) {
        console.error("Failed to block IP:", error);
        res.status(500).json({
            error: "Failed to block IP",
            details: error.message
        });
    }
});

// Block by user ID (persistent in Firestore only)
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
        const blockDuration = duration ? parseInt(duration) : 3600000;
        const expiresAt = new Date(Date.now() + blockDuration);

        // Block user in Firestore
        await db.collection('users_ips').doc(uid).update({
            blocked: true,
            blockReason: reason,
            blockUntil: expiresAt,
            blockedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Also block the IP in Firestore
        const geo = geoip.lookup(userIP);
        await db.collection('ips_blocklist').add({
            ip: userIP,
            reason: `User ${uid} blocked: ${reason}`,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: expiresAt,
            geo: geo || null,
            active: true
        });
        
        res.status(200).json({
            message: `✅ User ${uid} (IP: ${userIP}) blocked in Firestore`,
            reason,
            duration: blockDuration,
            expiresAt
        });
    } catch (error) {
        console.error("Failed to block user:", error);
        res.status(500).send("❌ Error blocking user");
    }
});

// Unblock an IP address (persistent in Firestore only)
router.delete("/unblock", async (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        return res.status(400).send("IP is required");
    }

    try {
        // Mark as inactive in Firestore
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
        res.status(200).send(`✅ IP ${ip} unblocked in Firestore`);
    } catch (error) {
        console.error("Failed to unblock IP:", error);
        res.status(500).send("❌ Error unblocking IP");
    }
});

// Get list of blocked IPs (from Firestore only)
router.get("/blocked", async (req, res) => {
    try {
        const snapshot = await db.collection('ips_blocklist')
            .where('active', '==', true)
            .get();

        const blockedIPs = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            expiresAt: doc.data().expiresAt.toDate()
        }));
        
        res.status(200).json(blockedIPs);
    } catch (error) {
        console.error("Failed to get blocked IPs:", error);
        res.status(500).send("❌ Error getting blocked IPs");
    }
});

// Get blocked users (from Firestore only)
router.get("/blocked-users", async (req, res) => {
    try {
        const snapshot = await db.collection('users_ips')
            .where('blocked', '==', true)
            .get();

        const blockedUsers = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            blockUntil: doc.data().blockUntil?.toDate()
        }));
        
        res.status(200).json(blockedUsers);
    } catch (error) {
        console.error("Failed to get blocked users:", error);
        res.status(500).send("❌ Error getting blocked users");
    }
});

// Force cleanup of expired blocks (Firestore only)
router.post("/cleanup", async (req, res) => {
    try {
        const now = new Date();
        let cleanedCount = 0;

        // Clean expired IP blocks
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

        // Clean expired user blocks
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

        res.status(200).json({
            message: "✅ Cleanup completed in Firestore",
            cleanedCount
        });
    } catch (error) {
        console.error("Failed to cleanup expired blocks:", error);
        res.status(500).send("❌ Error cleaning up expired blocks");
    }
});

module.exports = router;