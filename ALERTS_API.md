# SOC Lab Real-Time Alerts - API Documentation

## 🚀 Overview

The SOC Lab now includes **real-time alert streaming** via WebSocket and comprehensive REST APIs for querying historical alerts.

---

## 📡 WebSocket Endpoint

### Connect to Real-Time Alerts Stream

**Endpoint:** `ws://localhost:8088/ws/alerts`  
**Protocol:** WebSocket  
**Auth:** None (add to Nginx gateway for production)

### JavaScript/TypeScript Client Example

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8088/ws/alerts');

ws.onopen = () => {
  console.log('Connected to SOC alerts stream');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'connected':
      console.log('✅', data.message);
      break;
      
    case 'alert':
      console.log('🚨 NEW ALERT:', data.data);
      // Handle alert in your UI
      displayAlert(data.data);
      break;
      
    case 'pong':
      console.log('Pong received');
      break;
  }
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected from alerts stream');
  // Implement reconnection logic here
};

// Optional: Send ping to keep connection alive
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send('ping');
  }
}, 30000); // Every 30 seconds
```

### React Hook Example

```typescript
import { useEffect, useState, useRef } from 'react';

interface Alert {
  id: string;
  created_at: string;
  risk_level: string;
  title: string;
  message: string;
  payload: any;
  sent: number;
}

export function useAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    // Connect to WebSocket
    ws.current = new WebSocket('ws://localhost:8088/ws/alerts');

    ws.current.onopen = () => {
      console.log('Connected to alerts stream');
      setConnected(true);
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.type === 'alert') {
        setAlerts(prev => [data.data, ...prev].slice(0, 100)); // Keep last 100
      }
    };

    ws.current.onclose = () => {
      console.log('Disconnected');
      setConnected(false);
    };

    // Cleanup on unmount
    return () => {
      ws.current?.close();
    };
  }, []);

  return { alerts, connected };
}

// Usage in component
function AlertsWidget() {
  const { alerts, connected } = useAlerts();

  return (
    <div>
      <div>Status: {connected ? '🟢 Connected' : '🔴 Disconnected'}</div>
      {alerts.map(alert => (
        <div key={alert.id} className={`alert alert-${alert.risk_level}`}>
          <h4>{alert.title}</h4>
          <p>{alert.message}</p>
        </div>
      ))}
    </div>
  );
}
```

---

## 🔌 REST API Endpoints

### Base URL
- **Local:** `http://localhost:8088`
- **Via Gateway (mTLS):** `https://localhost:8443`

---

### 1️⃣ List Alerts

**GET** `/api/alerts`

Query all alerts with filtering and pagination.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Number of alerts (1-500) |
| `offset` | int | 0 | Pagination offset |
| `risk_level` | string | - | Filter by level: `critical`, `high`, `medium`, `low` |
| `channel` | string | - | Filter by channel: `slack`, `webhook`, `none` |
| `sent_only` | bool | false | Only show sent alerts |
| `from_date` | string | - | ISO-8601 datetime (e.g., `2026-01-29T00:00:00Z`) |
| `to_date` | string | - | ISO-8601 datetime |

#### Example Requests

```bash
# Get all alerts (default 50)
curl http://localhost:8088/api/alerts

# Get critical alerts only
curl "http://localhost:8088/api/alerts?risk_level=critical&limit=100"

# Get alerts from last 24 hours
curl "http://localhost:8088/api/alerts?from_date=2026-01-29T00:00:00Z"

# Pagination
curl "http://localhost:8088/api/alerts?limit=20&offset=40"
```

#### Response Format

```json
{
  "total": 150,
  "limit": 50,
  "offset": 0,
  "count": 50,
  "alerts": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "created_at": "2026-01-30T08:45:23",
      "fingerprint": "abc123def456",
      "channel": "webhook",
      "risk_level": "critical",
      "title": "SOC Lab alert [critical]",
      "message": "SOC Lab alert window=...\n...",
      "payload": {
        "window_start": "2026-01-30T08:40:00Z",
        "window_end": "2026-01-30T08:45:00Z",
        "anomalies": [...],
        "rule_matches": [...]
      },
      "sent": 1
    }
  ]
}
```

---

### 2️⃣ Get Single Alert

**GET** `/api/alerts/{alert_id}`

Retrieve a specific alert by ID.

#### Example

```bash
curl http://localhost:8088/api/alerts/550e8400-e29b-41d4-a716-446655440000
```

#### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-01-30T08:45:23",
  "fingerprint": "abc123def456",
  "channel": "webhook",
  "risk_level": "critical",
  "title": "SOC Lab alert [critical]",
  "message": "Detailed alert message...",
  "payload": {
    "window_start": "2026-01-30T08:40:00Z",
    "anomalies": [...]
  },
  "sent": 1
}
```

---

### 3️⃣ Get Alert Statistics

**GET** `/api/alerts/stats`

Get aggregated alert statistics and trends.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `from_date` | string | now - 24h | Start date (ISO-8601) |
| `to_date` | string | now | End date (ISO-8601) |

#### Example

```bash
curl "http://localhost:8088/api/alerts/stats"
```

#### Response

```json
{
  "period": {
    "from": "2026-01-29T09:00:00Z",
    "to": "2026-01-30T09:00:00Z"
  },
  "totals": {
    "total": 150,
    "sent": 120,
    "not_sent": 30
  },
  "by_risk_level": [
    {"risk_level": "critical", "count": 25},
    {"risk_level": "high", "count": 45},
    {"risk_level": "medium", "count": 60},
    {"risk_level": "low", "count": 20}
  ],
  "by_channel": [
    {"channel": "webhook", "count": 100},
    {"channel": "slack", "count": 20},
    {"channel": "none", "count": 30}
  ],
  "timeline": [
    {"hour": "2026-01-30T08:00:00", "count": 15},
    {"hour": "2026-01-30T09:00:00", "count": 22},
    ...
  ]
}
```

---

## 🔧 Python Client Example

```python
import requests
import websocket
import json
import threading

# REST API - List alerts
def get_alerts(limit=50, risk_level=None):
    params = {"limit": limit}
    if risk_level:
        params["risk_level"] = risk_level
    
    response = requests.get("http://localhost:8088/api/alerts", params=params)
    return response.json()

# REST API - Get statistics
def get_stats():
    response = requests.get("http://localhost:8088/api/alerts/stats")
    return response.json()

# WebSocket - Real-time alerts
def on_message(ws, message):
    data = json.loads(message)
    if data.get("type") == "alert":
        print(f"🚨 NEW ALERT: {data['data']['title']}")
        print(f"   Risk: {data['data']['risk_level']}")
        print(f"   Message: {data['data']['message'][:200]}...")

def on_error(ws, error):
    print(f"WebSocket error: {error}")

def on_close(ws, close_status_code, close_msg):
    print("WebSocket closed")

def on_open(ws):
    print("✅ Connected to alerts stream")

def start_websocket():
    ws = websocket.WebSocketApp(
        "ws://localhost:8088/ws/alerts",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever()

# Example usage
if __name__ == "__main__":
    # Get alerts via REST API
    alerts = get_alerts(limit=10, risk_level="critical")
    print(f"Found {alerts['total']} critical alerts")
    
    # Get stats
    stats = get_stats()
    print(f"Total alerts in last 24h: {stats['totals']['total']}")
    
    # Start WebSocket in background
    ws_thread = threading.Thread(target=start_websocket, daemon=True)
    ws_thread.start()
    
    # Keep main thread alive
    import time
    while True:
        time.sleep(1)
```

---

## 📊 Alert Payload Structure

Each alert contains a `payload` field with detailed information:

```json
{
  "window_start": "2026-01-30T08:40:00Z",
  "window_end": "2026-01-30T08:45:00Z",
  "anomalies": [
    {
      "window": "2026-01-30T08:40:00",
      "project": "wealthy-dev-rg",
      "cluster": "wealthy",
      "namespace": "apps",
      "service": "kong",
      "risk_level": "critical",
      "score": 0.987,
      "confidence": 0.95,
      "reason": "New/Never-Seen Error Detection: service=kong...",
      "llm_summary": "Critical anomaly detected in kong service..."
    }
  ],
  "rule_matches": [
    {
      "window": "2026-01-30T08:40:00",
      "project": "wealthy-dev-rg",
      "cluster": "wealthy",
      "namespace": "security",
      "service": "auth",
      "identity": "suspicious.user@attacker.com",
      "rule_id": "iam.suspicious_identity",
      "severity": "high",
      "description": "Suspicious identity detected in logs"
    }
  ]
}
```

---

## 🔒 Production Security

For production deployments:

1. **Use mTLS Gateway**: Route all API/WebSocket calls through the Nginx gateway at `https://localhost:8443`
2. **Add Authentication**: Implement JWT or API key auth for WebSocket connections
3. **Rate Limiting**: Configure rate limits on alert endpoints
4. **SSL/TLS**: Use proper SSL certificates (not self-signed)

---

## 🧪 Testing the Integration

### Test WebSocket with `websocat`

```bash
# Install websocat
brew install websocat  # macOS
# or: cargo install websocat

# Connect to alerts stream
websocat ws://localhost:8088/ws/alerts

# Send ping
ping

# You should receive:
# {"type":"connected","message":"Connected to SOC Lab alerts stream","timestamp":"..."}
# {"type":"pong"}
```

### Test REST API with `curl`

```bash
# Get all alerts
curl http://localhost:8088/api/alerts | jq

# Get statistics
curl http://localhost:8088/api/alerts/stats | jq

# Get critical alerts
curl "http://localhost:8088/api/alerts?risk_level=critical" | jq
```

---

## 📈 Dashboard Integration

Add real-time alerts to your Grafana dashboard:

1. Create a new panel
2. Use the **News** panel type
3. Configure data source to poll `/api/alerts` REST endpoint
4. Set refresh interval to 10s for near-real-time updates

For true real-time, integrate WebSocket into your React UI and display alerts as they arrive!

---

## 🎯 Summary

You now have:

✅ **WebSocket endpoint** for real-time alert streaming: `ws://localhost:8088/ws/alerts`  
✅ **REST API** to list alerts: `GET /api/alerts`  
✅ **REST API** to get single alert: `GET /api/alerts/{id}`  
✅ **REST API** for statistics: `GET /api/alerts/stats`  
✅ **Client examples** in JavaScript, React, and Python  
✅ **Production-ready** alert system with deduplication and throttling

All alerts are stored in ClickHouse and can be queried, visualized, and streamed in real-time! 🚀
