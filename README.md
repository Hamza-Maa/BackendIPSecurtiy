# VPN-IDS-IPS Backend System

A comprehensive backend system that integrates VPN management, Intrusion Detection System (IDS), and Intrusion Prevention System (IPS) with Firebase Authentication.

## Project Structure

```
ids-ips-vpn-backend/
├── config/
│   ├── firebase.js         # Firebase configuration
│   └── vpn.js             # VPN configuration
├── routes/
│   ├── idsRoutes.js       # IDS API routes
│   ├── ipsRoutes.js       # IPS API routes
│   └── vpnRoutes.js       # VPN API routes
├── services/
│   ├── idsService.js      # IDS business logic
│   ├── ipsService.js      # IPS business logic
│   └── vpnService.js      # VPN business logic
├── logs/
│   └── alerts.json        # IDS alerts storage
├── snort3/
│   └── rules/            # Snort IDS rules
├── server.js             # Main application file
└── generate-id-token.js  # Test token generator
```

## Component Details

### 1. Server Setup (server.js)
Main application file that initializes Express and middleware.
```javascript
// Key components:
- Express server setup
- Firebase authentication middleware
- Route registration
- Error handling
```

### 2. Firebase Authentication (config/firebase.js)
Firebase configuration and initialization.
```javascript
// Handles:
- Firebase Admin SDK initialization
- Service account configuration
- Token verification
```

### 3. VPN Management (services/vpnService.js)
VPN client management and monitoring.
```javascript
// Features:
- Client connection tracking
- Statistics monitoring
- Connection management
```

### 4. IDS System (services/idsService.js)
Intrusion detection implementation.
```javascript
// Includes:
- Traffic monitoring
- Alert generation
- Pattern matching
```

### 5. IPS System (services/ipsService.js)
Intrusion prevention implementation.
```javascript
// Provides:
- IP blocking
- Rate limiting
- Traffic filtering
```

## Step-by-Step Testing Guide

### Step 1: Start the Server
```bash
cd ids-ips-vpn-backend
npm start
```
Expected output:
```
✅ Mock VPN Management interface initialized
Server running at http://localhost:3002
✅ VPN IDS and IPS services initialized
```

### Step 2: Generate Test Token
```bash
cd ids-ips-vpn-backend
node generate-id-token.js
```
Expected output:
```
User: test-user-1
Custom token generated
Use this ID token in your API requests:
[TOKEN WILL BE DISPLAYED HERE]
```

### Step 3: Test VPN Endpoints
```powershell
# Get VPN Clients
$headers = @{
    'Authorization' = 'Bearer YOUR_ID_TOKEN'
}
Invoke-WebRequest -Uri 'http://localhost:3002/api/vpn/clients' -Headers $headers -Method Get -UseBasicParsing
```
Expected response:
```json
[{
    "commonName": "test-user1",
    "realAddress": "192.168.1.100",
    "virtualAddress": "10.8.0.2",
    "connectedSince": "2025-03-29T13:25:04.515Z",
    "bytesReceived": 1024,
    "bytesSent": 2048
}]
```

### Step 4: Test IDS Alerts
```powershell
# Get IDS Alerts
$headers = @{
    'Authorization' = 'Bearer YOUR_ID_TOKEN'
}
Invoke-WebRequest -Uri 'http://localhost:3002/api/ids/alerts' -Headers $headers -Method Get -UseBasicParsing
```
Expected response:
```json
[]  // Empty array if no alerts
```

### Step 5: Test IPS Blocking
```powershell
# Block an IP
$headers = @{
    'Authorization' = 'Bearer YOUR_ID_TOKEN'
    'Content-Type' = 'application/json'
}
$body = @{
    ip = '192.168.1.100'
    reason = 'Suspicious activity'
    
} | ConvertTo-Json
Invoke-WebRequest -Uri 'http://localhost:3002/api/ips/block' -Headers $headers -Method Post -Body $body -UseBasicParsing
```
Expected response:
```json
{
    "message": "✅ IP 192.168.1.100 blocked",
    "reason": "Suspicious activity detected",
    "duration": "default"
}
```

## File-Specific Features

### VPN Routes (routes/vpnRoutes.js)
```javascript
GET /api/vpn/clients
- Lists all connected VPN clients
- Requires authentication
- Uses vpnService.js for client management
```

### IDS Routes (routes/idsRoutes.js)
```javascript
GET /api/ids/alerts
- Returns security alerts
- Uses idsService.js for alert management
- Reads from logs/alerts.json
```

### IPS Routes (routes/ipsRoutes.js)
```javascript
POST /api/ips/block
- Blocks IP addresses
- Uses ipsService.js for IP management
- Updates snort3/rules/blacklist.rules
```

## Mobile App Integration Example

### Android/Kotlin (Using the API)
```kotlin
// File: YourAndroidApp/app/src/main/java/com/example/vpn/ApiService.kt

// 1. Get Firebase token
FirebaseAuth.getInstance().currentUser?.getIdToken(false)?.addOnSuccessListener { result ->
    val idToken = result.token
    
    // 2. Make API call
    val client = OkHttpClient()
    val request = Request.Builder()
        .url("http://your-server:3002/api/vpn/clients")
        .addHeader("Authorization", "Bearer $idToken")
        .build()
        
    client.newCall(request).execute()
}
```

## Troubleshooting

### Common Issues and Solutions

1. Server Won't Start
```bash
# Kill existing Node processes
taskkill /F /IM node.exe
# Restart server
npm start
```

2. Authentication Errors
```bash
# Generate new test token
node generate-id-token.js
# Use the new token in your requests
```

3. API Connection Issues
```bash
# Verify server is running
curl http://localhost:3002
# Check Firebase token hasn't expired
node generate-id-token.js
```

## Monitoring

### Log Locations
- API Logs: Console output
- IDS Alerts: `logs/alerts.json`
- IPS Blocks: `snort3/rules/blacklist.rules`

### Real-time Monitoring
1. Watch API logs:
```bash
npm start
```

2. Monitor IDS alerts:
```bash
tail -f logs/alerts.json
```

3. Check blocked IPs:
```bash
cat snort3/rules/blacklist.rules
