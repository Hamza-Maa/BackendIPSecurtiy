# Flutter Flow Integration Guide

This guide explains how to connect your Flutter Flow app to the VPN-IDS-IPS backend.

## Steps to Integrate

### 1. Add HTTP Package
In your `pubspec.yaml`:
```yaml
dependencies:
  http: ^0.13.0
```

### 2. Create API Service
Create a new file `lib/services/api_service.dart`:

```dart
import 'package:http/http.dart' as http;
import 'package:firebase_auth/firebase_auth.dart';
import 'dart:convert';

class ApiService {
  static const String baseUrl = 'http://your-server:3002/api';
  
  // Get Firebase token
  Future<String> _getToken() async {
    final user = FirebaseAuth.instance.currentUser;
    if (user != null) {
      return await user.getIdToken();
    }
    throw Exception('User not authenticated');
  }

  // Headers with authentication
  Future<Map<String, String>> _getHeaders() async {
    final token = await _getToken();
    return {
      'Authorization': 'Bearer $token',
      'Content-Type': 'application/json',
    };
  }

  // Get VPN Clients
  Future<List<dynamic>> getVpnClients() async {
    try {
      final headers = await _getHeaders();
      final response = await http.get(
        Uri.parse('$baseUrl/vpn/clients'),
        headers: headers,
      );

      if (response.statusCode == 200) {
        return json.decode(response.body);
      } else {
        throw Exception('Failed to load VPN clients');
      }
    } catch (e) {
      throw Exception('Error: $e');
    }
  }

  // Get IDS Alerts
  Future<List<dynamic>> getIdsAlerts() async {
    try {
      final headers = await _getHeaders();
      final response = await http.get(
        Uri.parse('$baseUrl/ids/alerts'),
        headers: headers,
      );

      if (response.statusCode == 200) {
        return json.decode(response.body);
      } else {
        throw Exception('Failed to load alerts');
      }
    } catch (e) {
      throw Exception('Error: $e');
    }
  }

  // Block IP (IPS)
  Future<Map<String, dynamic>> blockIp(String ip, String reason) async {
    try {
      final headers = await _getHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/ips/block'),
        headers: headers,
        body: json.encode({
          'ip': ip,
          'reason': reason,
        }),
      );

      if (response.statusCode == 200) {
        return json.decode(response.body);
      } else {
        throw Exception('Failed to block IP');
      }
    } catch (e) {
      throw Exception('Error: $e');
    }
  }
}
```

### 3. Use in Flutter Flow

#### Add to Your Existing Pages

1. **VPN Clients Page**:
```dart
// In your VPN clients page
final apiService = ApiService();

// Inside your build method or action
Future<void> loadVpnClients() async {
  try {
    final clients = await apiService.getVpnClients();
    // Update your UI with the clients data
    setState(() {
      // Update your state variable
      vpnClients = clients;
    });
  } catch (e) {
    // Handle error
    print('Error loading VPN clients: $e');
  }
}
```

2. **IDS Alerts Page**:
```dart
// In your alerts page
final apiService = ApiService();

Future<void> loadAlerts() async {
  try {
    final alerts = await apiService.getIdsAlerts();
    setState(() {
      // Update your state variable
      idsAlerts = alerts;
    });
  } catch (e) {
    print('Error loading alerts: $e');
  }
}
```

3. **IPS Block IP Page**:
```dart
// In your IPS page
final apiService = ApiService();

Future<void> blockSuspiciousIp(String ip) async {
  try {
    await apiService.blockIp(ip, 'Suspicious activity');
    // Show success message
  } catch (e) {
    // Show error message
    print('Error blocking IP: $e');
  }
}
```

### 4. Example Widget Implementation

```dart
class VpnClientsWidget extends StatefulWidget {
  @override
  _VpnClientsWidgetState createState() => _VpnClientsWidgetState();
}

class _VpnClientsWidgetState extends State<VpnClientsWidget> {
  final ApiService apiService = ApiService();
  List<dynamic> vpnClients = [];
  bool isLoading = false;

  @override
  void initState() {
    super.initState();
    loadVpnClients();
  }

  Future<void> loadVpnClients() async {
    setState(() {
      isLoading = true;
    });

    try {
      final clients = await apiService.getVpnClients();
      setState(() {
        vpnClients = clients;
        isLoading = false;
      });
    } catch (e) {
      setState(() {
        isLoading = false;
      });
      // Show error message
    }
  }

  @override
  Widget build(BuildContext context) {
    return isLoading
        ? CircularProgressIndicator()
        : ListView.builder(
            itemCount: vpnClients.length,
            itemBuilder: (context, index) {
              final client = vpnClients[index];
              return ListTile(
                title: Text(client['commonName']),
                subtitle: Text(client['virtualAddress']),
                trailing: Text('Connected: ${client['connectedSince']}'),
              );
            },
          );
  }
}
```

### 5. Testing the Integration

1. Start the backend server:
```bash
cd ids-ips-vpn-backend
npm start
```

2. Update the `baseUrl` in `api_service.dart` to match your server address

3. Run your Flutter app and test the integration:
   - Login with Firebase
   - Navigate to your VPN clients page
   - Check if the data is loading correctly
   - Test blocking an IP
   - View IDS alerts

### 6. Error Handling

Add proper error handling in your Flutter app:

```dart
try {
  // API call
} on FirebaseAuthException catch (e) {
  // Handle Firebase auth errors
  print('Firebase Auth Error: ${e.message}');
} on Exception catch (e) {
  // Handle other errors
  print('Error: $e');
}
```

### 7. Security Considerations

1. Always use HTTPS in production
2. Handle token expiration
3. Implement proper error handling
4. Add loading states
5. Add retry mechanisms for failed requests

## Troubleshooting

1. **Authentication Issues**:
   - Check if Firebase is properly initialized
   - Verify user is logged in
   - Check token expiration

2. **Connection Issues**:
   - Verify backend server is running
   - Check URL is correct
   - Verify network connectivity

3. **Data Issues**:
   - Check API response format
   - Verify data parsing
   - Log response bodies for debugging
