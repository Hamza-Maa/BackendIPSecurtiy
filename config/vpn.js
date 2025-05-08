const path = require('path');
require('dotenv').config(); // Add this to load .env files

module.exports = {
    // OpenVPN Management Interface Configuration
    management: {
        host: process.env.OPENVPN_MANAGEMENT_HOST || 'localhost',
        port: parseInt(process.env.OPENVPN_MANAGEMENT_PORT) || 7505,
        password: process.env.OPENVPN_MANAGEMENT_PASSWORD || 'vpn-management-password',
        timeout: 5000, // Add connection timeout (ms)
        reconnectInterval: 10000 // Add auto-reconnect interval (ms)
    },

    // OpenVPN Server Configuration
    server: {
        config: path.join(__dirname, '../openvpn/server.conf'),
        clientConfigDir: path.join(__dirname, '../openvpn/client-configs'),
        certificatesDir: path.join(__dirname, '../openvpn/easy-rsa'), // Changed to standard easy-rsa location
        crlFile: path.join(__dirname, '../openvpn/crl.pem'), // Certificate Revocation List
        dhParamFile: path.join(__dirname, '../openvpn/dh.pem'), // DH parameters file
        tlsAuthFile: path.join(__dirname, '../openvpn/ta.key') // TLS auth key
    },

    // VPN Connection Settings
    settings: {
        protocol: process.env.OPENVPN_PROTOCOL || 'udp',
        port: parseInt(process.env.OPENVPN_PORT) || 1194,
        subnet: process.env.OPENVPN_SUBNET || '10.8.0.0',
        subnetMask: process.env.OPENVPN_SUBNET_MASK || '255.255.255.0',
        maxClients: parseInt(process.env.OPENVPN_MAX_CLIENTS) || 100,
        keepAlive: parseInt(process.env.OPENVPN_KEEPALIVE) || 10,
        keepAliveTimeout: parseInt(process.env.OPENVPN_KEEPALIVE_TIMEOUT) || 60,
        pushRoutes: [ // Add default routes to push to clients
            'route 192.168.1.0 255.255.255.0',
            'dhcp-option DNS 8.8.8.8',
            'dhcp-option DNS 8.8.4.4'
        ]
    },

    // Security Settings
    security: {
        cipher: process.env.OPENVPN_CIPHER || 'AES-256-GCM',
        auth: process.env.OPENVPN_AUTH || 'SHA256',
        keySize: parseInt(process.env.OPENVPN_KEY_SIZE) || 256,
        certValidDays: parseInt(process.env.OPENVPN_CERT_VALID_DAYS) || 365,
        tlsVersionMin: process.env.OPENVPN_TLS_VERSION_MIN || '1.2',
        renegotiateTime: process.env.OPENVPN_RENEGOTIATE_TIME || '3600' // In seconds
    },

    // Client Defaults
    clientDefaults: {
        redirectGateway: process.env.OPENVPN_REDIRECT_GATEWAY === 'true' || true,
        compression: process.env.OPENVPN_COMPRESSION || 'compress lz4-v2',
        persistKey: true,
        persistTun: true,
        nobind: true,
        muteReplayWarnings: true
    }
};