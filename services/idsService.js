const { db } = require('../config/firebase');
const fs = require('fs').promises;
const path = require('path');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');

class IDSService {
    constructor() {
        this.alertsPath = path.join(__dirname, './logs/alerts.json');
        this.rulesPath = path.join(__dirname, 'snort3/rules/local.rules');
        this.customRulesPath = path.join(__dirname, 'snort3/rules/custom.rules');
        this.emailTransporter = null;
        this.alerts = [];
        
        // Initialize email notifications if configured
        if (process.env.SMTP_HOST) {
            this.emailTransporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: process.env.SMTP_PORT || 587,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });
        }

        // Schedule periodic alert processing
        this.scheduleAlertProcessing();
    }

    scheduleAlertProcessing() {
        // Process alerts every minute
        schedule.scheduleJob('*/1 * * * *', async () => {
            try {
                await this.processAlerts();
            } catch (error) {
                console.error('❌ Scheduled alert processing failed:', error);
            }
        });
    }

    async createConnectionAlert(client) {
        const alert = {
            timestamp: new Date().toISOString(),
            src_ip: client.realAddress,
            dest_ip: client.virtualAddress,
            msg: `New VPN connection from ${client.commonName}`,
            severity: this.calculateConnectionSeverity(client),
            details: {
                user: client.commonName,
                connection_type: 'OpenVPN',
                bytesReceived: client.bytesReceived,
                bytesSent: client.bytesSent
            }
        };

        // Add to alerts array
        this.alerts.push(alert);

        // Write to alerts file
        await this.saveAlerts();

        // Process immediately
        await this.processAlert(alert);

        return alert;
    }

    calculateConnectionSeverity(client) {
        // Base severity for new connections
        let severity = 3;

        // Increase severity based on certain conditions
        if (client.bytesReceived > 1000000 || client.bytesSent > 1000000) {
            severity += 2; // High data transfer
        }

        // Add more conditions as needed
        return severity;
    }

    async saveAlerts() {
        try {
            await fs.writeFile(this.alertsPath, JSON.stringify(this.alerts, null, 2));
        } catch (error) {
            console.error('❌ Error saving alerts:', error);
        }
    }

    async processAlert(alert) {
        try {
            // Store in Firebase
            await db.collection('ids_alerts').add(alert);

            // Send notification for high severity alerts
            if (alert.severity >= 8) {
                await this.sendAlertNotification(alert);
            }
        } catch (error) {
            console.error('❌ Error processing alert:', error);
        }
    }

    async processAlerts() {
        try {
            const alerts = this.alerts;
            const newAlerts = [];

            for (const alert of alerts) {
                // Enhance alert with severity level
                const severity = this.calculateSeverity(alert);
                const enhancedAlert = {
                    ...alert,
                    severity,
                    processed: new Date(),
                };

                // Store in Firebase
                await db.collection('ids_alerts').add(enhancedAlert);

                // Send notification for high severity alerts
                if (severity >= 8) {
                    await this.sendAlertNotification(enhancedAlert);
                }

                newAlerts.push(enhancedAlert);
            }

            // Clear processed alerts
            await fs.writeFile(this.alertsPath, '[]');

            return newAlerts;
        } catch (error) {
            console.error('❌ Error processing alerts:', error);
            throw error;
        }
    }

    calculateSeverity(alert) {
        // Calculate severity based on alert properties
        let severity = 5; // Default medium severity

        // Increase severity for known dangerous patterns
        if (alert.msg.toLowerCase().includes('exploit')) severity += 2;
        if (alert.msg.toLowerCase().includes('attack')) severity += 2;
        if (alert.msg.toLowerCase().includes('malware')) severity += 2;
        
        // Adjust based on protocol
        if (alert.protocol === 'tcp') severity += 1;
        
        // Cap severity at 10
        return Math.min(severity, 10);
    }

    async sendAlertNotification(alert) {
        if (!this.emailTransporter) return;

        try {
            await this.emailTransporter.sendMail({
                from: process.env.SMTP_FROM,
                to: process.env.ALERT_EMAIL,
                subject: `⚠️ High Severity IDS Alert: ${alert.msg}`,
                html: `
                    <h2>High Severity IDS Alert Detected</h2>
                    <p><strong>Message:</strong> ${alert.msg}</p>
                    <p><strong>Source IP:</strong> ${alert.src_ip}</p>
                    <p><strong>Destination IP:</strong> ${alert.dest_ip}</p>
                    <p><strong>Severity:</strong> ${alert.severity}</p>
                    <p><strong>Timestamp:</strong> ${alert.timestamp}</p>
                `
            });
        } catch (error) {
            console.error('❌ Failed to send alert notification:', error);
        }
    }

    async addCustomRule(rule) {
        try {
            // Validate rule syntax
            if (!this.validateRuleSyntax(rule)) {
                throw new Error('Invalid rule syntax');
            }

            // Add rule to custom rules file
            await fs.appendFile(this.customRulesPath, `${rule}\n`);

            // Store rule in Firebase
            await db.collection('ids_rules').add({
                rule,
                created: new Date(),
                enabled: true
            });

            // Reload Snort rules
            await this.reloadRules();

            return true;
        } catch (error) {
            console.error('❌ Error adding custom rule:', error);
            throw error;
        }
    }

    validateRuleSyntax(rule) {
        // Basic rule syntax validation
        const rulePattern = /^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s+.+/;
        return rulePattern.test(rule);
    }

    async reloadRules() {
        try {
            // Signal Snort to reload rules
            // This is a placeholder - implement actual reload mechanism
            console.log('Reloading Snort rules...');
            return true;
        } catch (error) {
            console.error('❌ Error reloading rules:', error);
            throw error;
        }
    }

    async getAlerts(options = {}) {
        try {
            let query = db.collection('ids_alerts')
                .orderBy('timestamp', 'desc');

            if (options.limit) {
                query = query.limit(options.limit);
            }

            if (options.severity) {
                query = query.where('severity', '>=', options.severity);
            }

            const snapshot = await query.get();
            return snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));
        } catch (error) {
            console.error('❌ Error getting alerts:', error);
            throw error;
        }
    }

    async getRules() {
        try {
            const snapshot = await db.collection('ids_rules').get();
            return snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));
        } catch (error) {
            console.error('❌ Error getting rules:', error);
            throw error;
        }
    }
}

module.exports = new IDSService();
