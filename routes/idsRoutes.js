const express = require("express");
const { db } = require("../config/firebase");
const idsService = require("../services/idsService");
const router = express.Router();

// Process IDS alerts
router.get("/process_alerts", async (req, res) => {
    try {
        const alerts = await idsService.processAlerts();
        res.status(200).json({
            message: "✅ IDS alerts processed",
            alertCount: alerts.length,
            alerts
        });
    } catch (error) {
        console.error("Failed to process IDS alerts:", error);
        res.status(500).send("❌ Error processing IDS alerts");
    }
});

// Get alerts with optional filtering
router.get("/alerts", async (req, res) => {
    try {
        const options = {
            limit: parseInt(req.query.limit) || 100,
            severity: parseInt(req.query.severity) || 0
        };

        const alerts = await idsService.getAlerts(options);
        res.status(200).json(alerts);
    } catch (error) {
        console.error("Failed to get alerts:", error);
        res.status(500).send("❌ Error getting alerts");
    }
});

// Add custom IDS rule
router.post("/rules", async (req, res) => {
    const { rule } = req.body;
    
    if (!rule) {
        return res.status(400).send("Rule content is required");
    }

    try {
        await idsService.addCustomRule(rule);
        res.status(201).send("✅ Custom rule added successfully");
    } catch (error) {
        console.error("Failed to add custom rule:", error);
        res.status(500).send("❌ Error adding custom rule");
    }
});

// Get all IDS rules
router.get("/rules", async (req, res) => {
    try {
        const rules = await idsService.getRules();
        res.status(200).json(rules);
    } catch (error) {
        console.error("Failed to get rules:", error);
        res.status(500).send("❌ Error getting rules");
    }
});

// Get alert statistics
router.get("/stats", async (req, res) => {
    try {
        const alerts = await idsService.getAlerts();
        
        // Calculate statistics
        const stats = {
            total: alerts.length,
            bySeverity: {},
            byType: {},
            recentAlerts: alerts.slice(0, 10) // Last 10 alerts
        };

        // Group alerts by severity and type
        alerts.forEach(alert => {
            stats.bySeverity[alert.severity] = (stats.bySeverity[alert.severity] || 0) + 1;
            stats.byType[alert.alert_type] = (stats.byType[alert.alert_type] || 0) + 1;
        });

        res.status(200).json(stats);
    } catch (error) {
        console.error("Failed to get alert statistics:", error);
        res.status(500).send("❌ Error getting alert statistics");
    }
});

module.exports = router;

