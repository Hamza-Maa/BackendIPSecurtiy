const express = require('express');
const vpnService = require('../services/vpnService');
const router = express.Router();

// Initialize VPN service when routes are loaded
vpnService.initialize().catch(console.error);

// Get all connected VPN clients
router.get("/clients", async (req, res) => {
    try {
        const clients = await vpnService.getAllConnectedClients();
        res.json(clients);
    } catch (error) {
        console.error("Failed to get VPN clients:", error);
        res.status(500).send("❌ Error getting VPN clients");
    }
});

// Get specific client status
router.get("/clients/:username", async (req, res) => {
    try {
        const status = await vpnService.getClientStatus(req.params.username);
        if (status) {
            res.json(status);
        } else {
            res.status(404).send("Client not found or not connected");
        }
    } catch (error) {
        console.error("Failed to get client status:", error);
        res.status(500).send("❌ Error getting client status");
    }
});

// Create new VPN client configuration
router.post("/clients", async (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).send("Username is required");
    }

    try {
        const config = await vpnService.createClientConfig(username);
        res.status(201).json({
            message: "✅ VPN client configuration created",
            config
        });
    } catch (error) {
        console.error("Failed to create VPN client:", error);
        res.status(500).send("❌ Error creating VPN client");
    }
});

// Revoke VPN client access
router.delete("/clients/:username", async (req, res) => {
    try {
        await vpnService.revokeClient(req.params.username);
        res.send("✅ VPN client access revoked");
    } catch (error) {
        console.error("Failed to revoke client access:", error);
        res.status(500).send("❌ Error revoking client access");
    }
});

module.exports = router;
